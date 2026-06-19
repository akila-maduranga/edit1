#!/usr/bin/env python3
"""
Core patching engine — TikTok bypass with fingerprint-based re-encode prevention.

Pipeline:
   1. FFmpeg remux (Faststart, normalize)
   2. ZeroLoss Track Bypass (edts/elst rebuild)
    3. mvhd Fingerprint (next_track_id = 9999, fixed creation date)
    4. Udta Strip (remove ffmpeg encoder signature)
    5. Tkhd Fingerprint (alternate_group, preserve orientation)
   6. Frame Count Inflation (5x, sequential, two-entry stts, no filler NALs)
   7. Comment Udta Injection (Apple iTunes-style only)
   8. Restore original audio duration
"""

import struct
import subprocess
import random
from pathlib import Path

_SCRIPT_DIR = Path(__file__).parent


def _iter_boxes(data, start=0, end=None):
    if end is None:
        end = len(data)
    i = start
    while i + 8 <= end:
        size = struct.unpack(">I", data[i:i+4])[0]
        btype = data[i+4:i+8]
        if size == 0:
            size = end - i
        if size < 8:
            break
        yield i, size, btype
        i += size


def _find_box(data, box_type, start=0, end=None):
    for off, sz, bt in _iter_boxes(data, start, end):
        if bt == box_type:
            return off, sz
    return -1, 0


def _adjust_stco(data, delta, search_start=0, search_end=None):
    if search_end is None:
        search_end = len(data)
    pos = search_start
    while pos < search_end:
        idx = data.find(b'stco', pos, search_end)
        if idx == -1:
            idx = data.find(b'co64', pos, search_end)
            if idx == -1:
                break
            entry_size = 8
            pos = idx + 1
        else:
            entry_size = 4
            pos = idx + 1
        entry_count = int.from_bytes(data[idx+8:idx+12], 'big')
        off = idx + 12
        for _ in range(entry_count):
            old = int.from_bytes(data[off:off+entry_size], 'big')
            new_val = old + delta
            data[off:off+entry_size] = new_val.to_bytes(entry_size, 'big')
            off += entry_size


def _dump_atoms(data, label="", log_func=None):
    if not log_func:
        return
    i = 0
    while i + 8 <= len(data):
        size = int.from_bytes(data[i:i+4], 'big')
        kind = data[i+4:i+8]
        if size == 0:
            size = len(data) - i
        if log_func:
            log_func(f"  [{label}]  offset {i:>8}  size {size:>8}  {kind.decode('latin1', errors='replace')}")
        i += size
        if i >= len(data):
            break


# ── ZeroLoss Track Bypass (edts/elst rebuild) ──────────────────────────

def build_edts_atom(duration, media_time=0):
    elst_size = 36 if duration > 0xffffffff else 28
    edts_size = 8 + elst_size
    buf = bytearray(edts_size)
    struct.pack_into('>I4s', buf, 0, edts_size, b'edts')
    struct.pack_into('>I4s', buf, 8, elst_size, b'elst')
    if duration > 0xffffffff:
        struct.pack_into('>I', buf, 16, 0x01000000)
        struct.pack_into('>I', buf, 20, 1)
        struct.pack_into('>Q', buf, 24, duration)
        struct.pack_into('>q', buf, 32, media_time)
        struct.pack_into('>I', buf, 40, 0x00010000)
    else:
        struct.pack_into('>I', buf, 16, 0)
        struct.pack_into('>I', buf, 20, 1)
        struct.pack_into('>I', buf, 24, duration)
        struct.pack_into('>i', buf, 28, media_time)
        struct.pack_into('>I', buf, 32, 0x00010000)
    return bytes(buf)


def rebuild_elst_bypass(data):
    """No-op — skipped for now to test if elst is causing rejection."""
    return data


# ── Subtle mvhd fingerprint ─────────────────────────────────────────

def patch_mvhd_fingerprint(data):
    """Change mvhd.next_track_id to a large value + set a fixed creation time.
    Alters the file's hash/signature without introducing suspicious matrix values.
    """
    moov_off, moov_sz = _find_box(data, b"moov")
    if moov_off == -1:
        return data
    mvhd_off, _ = _find_box(data, b"mvhd", moov_off+8, moov_off+moov_sz)
    if mvhd_off == -1:
        return data
    p = bytearray(data)
    version = p[mvhd_off+8]
    if version == 0:
        ct_off = mvhd_off + 12
        nti_off = mvhd_off + 84
    else:
        ct_off = mvhd_off + 20
        nti_off = mvhd_off + 96
    rand_ts = random.randint(1_600_000_000, 1_750_000_000)
    if ct_off + 8 <= len(p):
        struct.pack_into('>II', p, ct_off, rand_ts, rand_ts)
    rand_nti = random.randint(100, 9998)
    if nti_off + 4 <= len(p):
        struct.pack_into('>I', p, nti_off, rand_nti)
    return bytes(p)


# ── Udta Strip ─────────────────────────────────────────────────────────

def strip_udta(data):
    moov_off, moov_sz = _find_box(data, b"moov")
    if moov_off == -1:
        return data
    udta_off, udta_sz = _find_box(data, b"udta", moov_off+8, moov_off+moov_sz)
    if udta_off == -1:
        return data
    data = bytearray(data)
    del data[udta_off:udta_off+udta_sz]
    new_moov_sz = moov_sz - udta_sz
    struct.pack_into('>I', data, moov_off, new_moov_sz)
    _adjust_stco(data, -udta_sz, moov_off+8, moov_off+8+new_moov_sz)
    return bytes(data)


# ── Tkhd fingerprint ──────────────────────────────────────────────────

def fingerprint_tkhd(data):
    """Set alternate_group for fingerprinting while preserving original tkhd
    matrix (rotation/orientation from the original encoder).
    """
    moov_off, moov_sz = _find_box(data, b"moov")
    if moov_off == -1:
        return data
    p = bytearray(data)
    group_id = 1
    for trak_off, trak_sz, _ in _iter_boxes(p, moov_off+8, moov_off+moov_sz):
        tkhd_off, _ = _find_box(p, b"tkhd", trak_off+8, trak_off+trak_sz)
        if tkhd_off == -1:
            continue
        version = p[tkhd_off+8]
        if version == 0:
            group_off = tkhd_off + 8 + 32
        elif version == 1:
            group_off = tkhd_off + 8 + 44
        else:
            continue
        if group_off + 2 <= len(p):
            struct.pack_into('>H', p, group_off, group_id)
            group_id += 1
    return bytes(p)


# ── Frame Inflation (two-entry stts + cycle real data + avcC/SPS) ──────

def _patch_avcC_sps(data):
    """Patch avcC AND SPS profile to High10, level to 6.2.
    TikTok may parse the SPS for actual codec info.
    """
    moov_off, moov_sz = _find_box(data, b"moov")
    if moov_off == -1:
        return data
    for trak_off, trak_sz, _ in _iter_boxes(data, moov_off+8, moov_off+moov_sz):
        mdia_off, mdia_sz = _find_box(data, b"mdia", trak_off+8, trak_off+trak_sz)
        if mdia_off == -1:
            continue
        hdlr_off, _ = _find_box(data, b"hdlr", mdia_off+8, mdia_off+mdia_sz)
        if hdlr_off == -1 or data[hdlr_off+16:hdlr_off+20] != b'vide':
            continue
        minf_off, minf_sz = _find_box(data, b"minf", mdia_off+8, mdia_off+mdia_sz)
        if minf_off == -1:
            continue
        stbl_off, stbl_sz = _find_box(data, b"stbl", minf_off+8, minf_off+minf_sz)
        if stbl_off == -1:
            continue
        stsd_off, _ = _find_box(data, b"stsd", stbl_off+8, stbl_off+stbl_sz)
        if stsd_off == -1:
            continue
        stsd_end = stsd_off + int.from_bytes(data[stsd_off:stsd_off+4], 'big')
        entry_count = int.from_bytes(data[stsd_off+8:stsd_off+12], 'big')
        pos = stsd_off + 12
        for _ in range(entry_count):
            if pos + 8 > stsd_end:
                break
            e_sz = int.from_bytes(data[pos:pos+4], 'big')
            e_type = data[pos+4:pos+8]
            if e_type == b'avc1':
                avcC_off, _ = _find_box(data, b'avcC', pos+8, pos+e_sz)
                if avcC_off == -1:
                    continue
                p = bytearray(data)
                avcC_sz = int.from_bytes(data[avcC_off:avcC_off+4], 'big')
                avcC_end = avcC_off + avcC_sz
                # avcC level + profile (always within header bounds for valid avcC)
                p[avcC_off+9] = 110   # profile: High → High10
                p[avcC_off+10] = 0    # profile_compat
                p[avcC_off+11] = 62   # level: 5.1 → 6.2
                # SPS NAL is at avcC_off + 16 (after config header)
                sps_start = avcC_off + 16
                if sps_start + 3 < avcC_end:
                    p[sps_start+1] = 110  # SPS profile_idc
                    p[sps_start+3] = 62   # SPS level_idc
                return bytes(p)
            pos += e_sz
    return data


def patch_color_metadata(data):
    """Strip HDR color metadata: change colr box to BT.709 (primaries=1,
    transfer=1, matrix=1). If no colr box exists, add one.
    """
    moov_off, moov_sz = _find_box(data, b"moov")
    if moov_off == -1:
        return data
    for trak_off, trak_sz, _ in _iter_boxes(data, moov_off+8, moov_off+moov_sz):
        mdia_off, mdia_sz = _find_box(data, b"mdia", trak_off+8, trak_off+trak_sz)
        if mdia_off == -1:
            continue
        hdlr_off, _ = _find_box(data, b"hdlr", mdia_off+8, mdia_off+mdia_sz)
        if hdlr_off == -1 or data[hdlr_off+16:hdlr_off+20] != b'vide':
            continue
        minf_off, minf_sz = _find_box(data, b"minf", mdia_off+8, mdia_off+mdia_sz)
        if minf_off == -1:
            continue
        stbl_off, stbl_sz = _find_box(data, b"stbl", minf_off+8, minf_off+minf_sz)
        if stbl_off == -1:
            continue
        stsd_off, _ = _find_box(data, b"stsd", stbl_off+8, stbl_off+stbl_sz)
        if stsd_off == -1:
            continue
        stsd_end = stsd_off + int.from_bytes(data[stsd_off:stsd_off+4], 'big')
        entry_count = int.from_bytes(data[stsd_off+8:stsd_off+12], 'big')
        pos = stsd_off + 12
        for _ in range(entry_count):
            if pos + 8 > stsd_end:
                break
            e_sz = int.from_bytes(data[pos:pos+4], 'big')
            e_type = data[pos+4:pos+8]
            if e_type == b'avc1':
                e_end = pos + e_sz
                colr_off, colr_sz = _find_box(data, b'colr', pos+8, e_end)
                p = bytearray(data)
                colr_data = struct.pack('>HHHB', 1, 1, 1, 0)
                if colr_off != -1:
                    p[colr_off+10:colr_off+17] = colr_data
                else:
                    colr_box = struct.pack('>I4s', 17, b'colr') + struct.pack('>H', 0) + colr_data
                    p[pos+8:pos+8] = colr_box
                    stsd_sz = int.from_bytes(p[stsd_off:stsd_off+4], 'big')
                    struct.pack_into('>I', p, stsd_off, stsd_sz + 17)
                    struct.pack_into('>I', p, pos, e_sz + 17)
                    for container_off in (stbl_off, minf_off, mdia_off, trak_off, moov_off):
                        c_sz = int.from_bytes(p[container_off:container_off+4], 'big')
                        struct.pack_into('>I', p, container_off, c_sz + 17)
                    _adjust_stco(p, 17, moov_off+8, moov_off+8+moov_sz+17)
                return bytes(p)
            pos += e_sz
    return data


def normalize_frame_rate(data, target_fps=60.0):
    """Change video stts deltas to produce a clean target_fps (default 60).
    Uses the video mdhd timescale.
    """
    moov_off, moov_sz = _find_box(data, b"moov")
    if moov_off == -1:
        return data
    p = bytearray(data)
    for trak_off, trak_sz, _ in _iter_boxes(p, moov_off+8, moov_off+moov_sz):
        tkhd_off, _ = _find_box(p, b"tkhd", trak_off+8, trak_off+trak_sz)
        if tkhd_off == -1:
            continue
        mdia_off, mdia_sz = _find_box(p, b"mdia", trak_off+8, trak_off+trak_sz)
        if mdia_off == -1:
            continue
        hdlr_off, _ = _find_box(p, b"hdlr", mdia_off+8, mdia_off+mdia_sz)
        if hdlr_off == -1 or p[hdlr_off+16:hdlr_off+20] != b'vide':
            continue
        mdhd_off, _ = _find_box(p, b"mdhd", mdia_off+8, mdia_off+mdia_sz)
        if mdhd_off == -1:
            continue
        ver = p[mdhd_off+8]
        ts_off = mdhd_off + (20 if ver == 0 else 28)
        timescale = int.from_bytes(p[ts_off:ts_off+4], 'big')
        clean_delta = max(int(timescale / target_fps), 1)
        minf_off, minf_sz = _find_box(p, b"minf", mdia_off+8, mdia_off+mdia_sz)
        if minf_off == -1:
            continue
        stbl_off, stbl_sz = _find_box(p, b"stbl", minf_off+8, minf_off+minf_sz)
        if stbl_off == -1:
            continue
        stts_off, stts_sz = _find_box(p, b"stts", stbl_off+8, stbl_off+stbl_sz)
        if stts_off == -1:
            continue
        entry_count = int.from_bytes(p[stts_off+12:stts_off+16], 'big')
        total_frames = 0
        for i in range(entry_count):
            off = stts_off + 16 + i * 8
            cnt = int.from_bytes(p[off:off+4], 'big')
            total_frames += cnt
        new_dur = total_frames * clean_delta
        new_stts_body = struct.pack('>II', 0, 1)
        new_stts_body += struct.pack('>II', total_frames, clean_delta)
        new_stts = struct.pack('>I4s', 8 + len(new_stts_body), b'stts') + new_stts_body
        delta = len(new_stts) - stts_sz
        if delta != 0:
            read_pos = stts_off + stts_sz
            write_pos = stts_off + len(new_stts)
            rest_len = len(p) - read_pos
            p[stts_off:stts_off+len(new_stts)] = new_stts
            p[write_pos:write_pos+rest_len] = p[read_pos:read_pos+rest_len]
            p = bytearray(p[:write_pos+rest_len])
        else:
            p[stts_off:stts_off+len(new_stts)] = new_stts
        _adjust_stco(p, delta, moov_off+8, moov_off+8+moov_sz+delta)
        for box_off in (stbl_off, minf_off, mdia_off, trak_off, moov_off):
            old_sz = int.from_bytes(p[box_off:box_off+4], 'big')
            struct.pack_into('>I', p, box_off, old_sz + delta)
        moov_sz = int.from_bytes(p[moov_off:moov_off+4], 'big')
        return bytes(p)
    return bytes(p)


def _sample_offsets(data, stco_off, stsc_off, stsz_off, sample_count):
    """Expand chunk offsets to per-sample offsets using stsc + stsz."""
    stco_count = int.from_bytes(data[stco_off+12:stco_off+16], 'big')
    offsets = []
    for i in range(stco_count):
        offsets.append(int.from_bytes(data[stco_off+16+i*4:stco_off+20+i*4], 'big'))

    uniform = int.from_bytes(data[stsz_off+12:stsz_off+16], 'big')
    sz_count = int.from_bytes(data[stsz_off+16:stsz_off+20], 'big')
    szs = []
    for i in range(min(sz_count, sample_count)):
        if uniform != 0:
            szs.append(uniform)
        else:
            szs.append(int.from_bytes(data[stsz_off+20+i*4:stsz_off+24+i*4], 'big'))

    stsc_count = int.from_bytes(data[stsc_off+12:stsc_off+16], 'big')
    chunks_spc = []
    for i in range(stsc_count):
        first = int.from_bytes(data[stsc_off+16+i*12:stsc_off+20+i*12], 'big')
        spc = int.from_bytes(data[stsc_off+20+i*12:stsc_off+24+i*12], 'big')
        next_first = int.from_bytes(data[stsc_off+28+i*12:stsc_off+32+i*12], 'big') if i + 1 < stsc_count else sample_count + 1
        for _ in range(first - 1, next_first - 1):
            chunks_spc.append(spc)

    result = []
    sample_idx = 0
    for chunk_idx, spc in enumerate(chunks_spc):
        if chunk_idx >= len(offsets):
            break
        chunk_off = offsets[chunk_idx]
        for s in range(spc):
            if sample_idx >= sample_count:
                return result
            sample_off = chunk_off + sum(szs[sample_idx - s:sample_idx])
            result.append(sample_off)
            sample_idx += 1
    return result

def inflate_sample_table_video(data, multiplier=5):
    """5x inflation — fake frames share last real frame's data (no filler NALs).
    Two-entry stts: real frames at original delta, fake frames at 1 tick.
    Sequential layout: real frames first, then fake frames.
    """
    moov_off, moov_sz = _find_box(data, b"moov")
    if moov_off == -1:
        return None

    video_stbl = None
    for trak_off, trak_sz, _ in _iter_boxes(data, moov_off+8, moov_off+moov_sz):
        mdia_off, mdia_sz = _find_box(data, b"mdia", trak_off+8, trak_off+trak_sz)
        if mdia_off == -1:
            continue
        hdlr_off, _ = _find_box(data, b"hdlr", mdia_off+8, mdia_off+mdia_sz)
        if hdlr_off == -1:
            continue
        if data[hdlr_off+16:hdlr_off+20] != b'vide':
            continue
        minf_off, minf_sz = _find_box(data, b"minf", mdia_off+8, mdia_off+mdia_sz)
        if minf_off == -1:
            continue
        stbl_off, stbl_sz = _find_box(data, b"stbl", minf_off+8, minf_off+minf_sz)
        if stbl_off == -1:
            continue
        video_stbl = (stbl_off, stbl_sz, trak_off, mdia_off, minf_off)
        break

    if video_stbl is None:
        return None

    stbl_off, stbl_sz, trak_off, mdia_off, minf_off = video_stbl
    stbl_end = stbl_off + stbl_sz

    mdhd_off, _ = _find_box(data, b"mdhd", mdia_off+8, trak_off + int.from_bytes(data[trak_off:trak_off+4], 'big'))
    if mdhd_off != -1:
        ver = data[mdhd_off+8]
        ts_off = mdhd_off + (20 if ver == 0 else 28)
        video_timescale = int.from_bytes(data[ts_off:ts_off+4], 'big')
    else:
        video_timescale = 90000

    stts_off, stts_sz = _find_box(data, b"stts", stbl_off+8, stbl_end)
    stsz_off, stsz_sz = _find_box(data, b"stsz", stbl_off+8, stbl_end)
    stco_off, stco_sz = _find_box(data, b"stco", stbl_off+8, stbl_end)
    stsc_off, stsc_sz = _find_box(data, b"stsc", stbl_off+8, stbl_end)

    if -1 in (stts_off, stsz_off, stco_off, stsc_off):
        return None

    try:
        stts_entry_count = int.from_bytes(data[stts_off+12:stts_off+16], 'big')
        real_count = 0
        last_delta = 0
        for i in range(stts_entry_count):
            off = stts_off + 16 + i * 8
            cnt = int.from_bytes(data[off:off+4], 'big')
            delta = int.from_bytes(data[off+4:off+8], 'big')
            real_count += cnt
            last_delta = delta

        if real_count == 0:
            return None

        total_count = min(real_count * multiplier, 0xFFFFFFFF)
        fake_count = total_count - real_count

        orig_total_dur_ticks = 0
        for i in range(stts_entry_count):
            off = stts_off + 16 + i * 8
            cnt = int.from_bytes(data[off:off+4], 'big')
            d = int.from_bytes(data[off+4:off+8], 'big')
            orig_total_dur_ticks += cnt * d
        proportional_delta = max(int(orig_total_dur_ticks / total_count), 1)
        new_stts_body = struct.pack('>II', 0, 1)
        new_stts_body += struct.pack('>II', total_count, proportional_delta)
        new_stts = struct.pack('>I4s', 8 + len(new_stts_body), b'stts') + new_stts_body

        uniform_size = int.from_bytes(data[stsz_off+12:stsz_off+16], 'big')
        orig_stsz_count = int.from_bytes(data[stsz_off+16:stsz_off+20], 'big')
        real_sizes = []
        for i in range(real_count):
            if uniform_size != 0:
                real_sizes.append(uniform_size)
            elif i < orig_stsz_count:
                real_sizes.append(int.from_bytes(data[stsz_off+20+i*4:stsz_off+24+i*4], 'big'))
            else:
                real_sizes.append(uniform_size if uniform_size else 0)

        real_offsets = _sample_offsets(data, stco_off, stsc_off, stsz_off, real_count)
        if not real_offsets:
            return None

        last_real_offset = real_offsets[-1]
        last_real_size = real_sizes[-1]

        new_stsz_body = bytearray(20 + total_count * 4)
        struct.pack_into('>III', new_stsz_body, 0, 0, 0, total_count)
        for i in range(real_count):
            struct.pack_into('>I', new_stsz_body, 12 + i * 4, real_sizes[i])
        for i in range(fake_count):
            struct.pack_into('>I', new_stsz_body, 12 + (real_count + i) * 4, last_real_size)
        new_stsz = struct.pack('>I4s', 8 + len(new_stsz_body), b'stsz') + bytes(new_stsz_body)

        new_stsc_body = struct.pack('>II', 0, 1)
        new_stsc_body += struct.pack('>III', 1, 1, 1)
        new_stsc = struct.pack('>I4s', 8 + len(new_stsc_body), b'stsc') + bytes(new_stsc_body)

        new_stco_body2 = bytearray(8 + total_count * 4)
        struct.pack_into('>II', new_stco_body2, 0, 0, total_count)
        for i in range(real_count):
            struct.pack_into('>I', new_stco_body2, 8 + i * 4, real_offsets[i])
        for i in range(fake_count):
            struct.pack_into('>I', new_stco_body2, 8 + (real_count + i) * 4, last_real_offset)
        new_stco2 = struct.pack('>I4s', 8 + len(new_stco_body2), b'stco') + bytes(new_stco_body2)

        replacements = [
            (stts_off, stts_sz, new_stts),
            (stsz_off, stsz_sz, new_stsz),
            (stsc_off, stsc_sz, new_stsc),
            (stco_off, stco_sz, new_stco2),
        ]
        replacements.sort(key=lambda x: x[0])

        moov_delta = sum(len(new) - old_sz for _, old_sz, new in replacements)

        result = bytearray(len(data) + moov_delta)
        read_pos = 0
        write_pos = 0
        for off, old_sz, new_bytes in replacements:
            result[write_pos:write_pos + off - read_pos] = data[read_pos:off]
            write_pos += off - read_pos
            result[write_pos:write_pos + len(new_bytes)] = new_bytes
            write_pos += len(new_bytes)
            read_pos = off + old_sz
        result[write_pos:] = data[read_pos:]

        for container_off in (stbl_off, minf_off, mdia_off, trak_off, moov_off):
            old_sz = int.from_bytes(result[container_off:container_off+4], 'big')
            new_sz = max(old_sz + moov_delta, 8)
            if new_sz > 0xFFFFFFFF:
                new_sz = 0xFFFFFFFF
            struct.pack_into('>I', result, container_off, new_sz)

        new_moov_end = moov_off + moov_sz + moov_delta
        _adjust_stco(result, moov_delta, moov_off+8, new_moov_end)

        total_stts_dur = total_count * proportional_delta
        total_sec = total_stts_dur / video_timescale
        mvhd_off, _ = _find_box(result, b"mvhd", moov_off+8, moov_off+moov_sz+moov_delta)
        if mvhd_off != -1:
            ver = result[mvhd_off+8]
            if ver == 0:
                mvhd_ts = int.from_bytes(result[mvhd_off+20:mvhd_off+24], 'big')
                old_dur = int.from_bytes(result[mvhd_off+24:mvhd_off+28], 'big')
                mvhd_dur = min(int(total_sec * mvhd_ts), 0xFFFFFFFF)
                mvhd_dur = max(mvhd_dur, old_dur)
                result[mvhd_off+24:mvhd_off+28] = struct.pack('>I', mvhd_dur)
            else:
                mvhd_ts = int.from_bytes(result[mvhd_off+28:mvhd_off+32], 'big')
                old_dur = int.from_bytes(result[mvhd_off+32:mvhd_off+40], 'big')
                mvhd_dur = int(total_sec * mvhd_ts)
                mvhd_dur = max(mvhd_dur, old_dur)
                result[mvhd_off+32:mvhd_off+40] = struct.pack('>Q', mvhd_dur)

        trak_dur = 0
        if 'mvhd_ts' in dir():
            trak_dur = min(int(total_sec * mvhd_ts), 0xFFFFFFFF)
        for trak_off, trak_sz, _ in _iter_boxes(result, moov_off+8, moov_off+moov_sz+moov_delta):
            mdia_off_v, mdia_sz_v = _find_box(result, b"mdia", trak_off+8, trak_off+trak_sz)
            is_video = False
            if mdia_off_v != -1:
                hdlr_off, _ = _find_box(result, b"hdlr", mdia_off_v+8, mdia_off_v+mdia_sz_v)
                if hdlr_off != -1 and result[hdlr_off+16:hdlr_off+20] == b'vide':
                    is_video = True
            if not is_video:
                continue

            tkhd_off, _ = _find_box(result, b"tkhd", trak_off+8, trak_off+trak_sz)
            if tkhd_off != -1:
                ver = result[tkhd_off+8]
                if ver == 0:
                    result[tkhd_off+28:tkhd_off+32] = struct.pack('>I', trak_dur)
                else:
                    result[tkhd_off+36:tkhd_off+44] = struct.pack('>Q', trak_dur)

            mdia_off, _ = _find_box(result, b"mdia", trak_off+8, trak_off+trak_sz)
            if mdia_off != -1:
                mdhd_off, _ = _find_box(result, b"mdhd", mdia_off+8, mdia_off+mdia_sz)
                if mdhd_off != -1:
                    ver = result[mdhd_off+8]
                    if ver == 0:
                        mdhd_ts = int.from_bytes(result[mdhd_off+20:mdhd_off+24], 'big')
                        mdhd_dur = min(int(total_sec * mdhd_ts), 0xFFFFFFFF)
                        result[mdhd_off+24:mdhd_off+28] = struct.pack('>I', mdhd_dur)
                    else:
                        mdhd_ts = int.from_bytes(result[mdhd_off+28:mdhd_off+32], 'big')
                        mdhd_dur = int(total_sec * mdhd_ts)
                        result[mdhd_off+32:mdhd_off+40] = struct.pack('>Q', mdhd_dur)

        return bytes(result)
    except (struct.error, ValueError, OverflowError, RuntimeError) as _exc:
        import traceback, sys
        _tb = traceback.format_exc()
        _msg = [f"[INFLATE ERROR] {type(_exc).__name__}: {_exc}"]
        _locs = locals()
        for _k in ('real_count','last_delta','total_count','new_delta','moov_delta',
                   'stbl_sz','minf_sz','mdia_sz','trak_sz','moov_off','moov_sz',
                   'mvhd_dur','new_sz'):
            if _k in _locs:
                _msg.append(f"  {_k}={_locs[_k]}")
        if 'real_sizes' in _locs and _locs['real_sizes']:
            _msg.append(f"  real_sizes len={len(_locs['real_sizes'])}, max={max(_locs['real_sizes'])}")
        if 'real_offsets' in _locs and _locs['real_offsets']:
            _msg.append(f"  real_offsets len={len(_locs['real_offsets'])}, max={max(_locs['real_offsets'])}")
        for _line in _tb.splitlines():
            _msg.append(f"  {_line}")
        sys.stderr.write("\n".join(_msg) + "\n")
        sys.stderr.flush()
        raise RuntimeError("\n".join(_msg)) from None


# ── Comment Udta Injection (meta/ilst, only \xa9cmt) ───────────────────

def build_comment_udta(comment):
    comment_bytes = comment.encode('utf-8')
    data_size = 16 + len(comment_bytes)
    cmt_size = 8 + data_size
    ilst_size = 8 + cmt_size
    hdlr_size = 33
    meta_size = 12 + hdlr_size + ilst_size
    udta_size = 8 + meta_size

    buf = bytearray(udta_size)
    p = 0

    struct.pack_into('>I4s', buf, p, udta_size, b'udta'); p += 8
    struct.pack_into('>I4sI', buf, p, meta_size, b'meta', 0); p += 12

    struct.pack_into('>I4sI', buf, p, hdlr_size, b'hdlr', 0); p += 12
    struct.pack_into('>I', buf, p, 0); p += 4
    struct.pack_into('>4s', buf, p, b'mdir'); p += 4
    struct.pack_into('>4s', buf, p, b'appl'); p += 4
    struct.pack_into('>II', buf, p, 0, 0); p += 8
    buf[p] = 0; p += 1

    struct.pack_into('>I4s', buf, p, ilst_size, b'ilst'); p += 8

    struct.pack_into('>I4s', buf, p, cmt_size, b'\xa9cmt'); p += 8
    struct.pack_into('>I4sII', buf, p, data_size, b'data', 1, 0); p += 16
    buf[p:p+len(comment_bytes)] = comment_bytes

    return bytes(buf)


def inject_comment_udta(data, comment):
    moov_off, moov_sz = _find_box(data, b"moov")
    if moov_off == -1:
        return data

    udta_bytes = build_comment_udta(comment)
    delta = len(udta_bytes)
    moov_end = moov_off + moov_sz

    result = bytearray(len(data) + delta)
    result[0:moov_end] = data[:moov_end]
    result[moov_end:moov_end+delta] = udta_bytes
    result[moov_end+delta:] = data[moov_end:]

    new_moov_sz = moov_sz + delta
    struct.pack_into('>I', result, moov_off, new_moov_sz)
    _adjust_stco(result, delta, moov_off+8, moov_off+8+new_moov_sz)

    return bytes(result)


# ── Audio duration helpers ─────────────────────────────────────────────

def read_audio_duration(data):
    moov_off, moov_sz = _find_box(data, b"moov")
    if moov_off == -1:
        return None
    for trak_off, trak_sz, tt in _iter_boxes(data, moov_off+8, moov_off+moov_sz):
        if tt != b"trak":
            continue
        mdia_off, mdia_sz = _find_box(data, b"mdia", trak_off+8, trak_off+trak_sz)
        if mdia_off == -1:
            continue
        hdlr_off, _ = _find_box(data, b"hdlr", mdia_off+8, mdia_off+mdia_sz)
        if hdlr_off == -1:
            continue
        if hdlr_off + 20 > len(data):
            continue
        if data[hdlr_off+16:hdlr_off+20] == b'soun':
            mdhd_off, _ = _find_box(data, b"mdhd", mdia_off+8, mdia_off+mdia_sz)
            if mdhd_off == -1:
                continue
            version = data[mdhd_off+8]
            if version == 0:
                dur_off = mdhd_off + 24
                if dur_off + 4 > len(data):
                    return None
                return int.from_bytes(data[dur_off:dur_off+4], 'big')
            else:
                dur_off = mdhd_off + 32
                if dur_off + 8 > len(data):
                    return None
                return int.from_bytes(data[dur_off:dur_off+8], 'big')
    return None


def patch_audio_duration(data, original_duration):
    moov_off, moov_sz = _find_box(data, b"moov")
    if moov_off == -1:
        return data
    for trak_off, trak_sz, tt in _iter_boxes(data, moov_off+8, moov_off+moov_sz):
        if tt != b"trak":
            continue
        mdia_off, mdia_sz = _find_box(data, b"mdia", trak_off+8, trak_off+trak_sz)
        if mdia_off == -1:
            continue
        hdlr_off, _ = _find_box(data, b"hdlr", mdia_off+8, mdia_off+mdia_sz)
        if hdlr_off == -1:
            continue
        if hdlr_off + 20 > len(data):
            continue
        if data[hdlr_off+16:hdlr_off+20] == b'soun':
            mdhd_off, _ = _find_box(data, b"mdhd", mdia_off+8, mdia_off+mdia_sz)
            if mdhd_off == -1:
                continue
            version = data[mdhd_off+8]
            if version == 0:
                dur_off = mdhd_off + 24
                dur_size = 4
            else:
                dur_off = mdhd_off + 32
                dur_size = 8
            p = bytearray(data)
            p[dur_off:dur_off+dur_size] = original_duration.to_bytes(dur_size, 'big')
            return bytes(p)
    return data


# ── Ftyp Brand Spoofing ─────────────────────────────────────────────────

def patch_ftyp(data):
    result = bytearray(data)
    ftyp_off, ftyp_sz = _find_box(result, b"ftyp")
    if ftyp_off == -1:
        return data
    result[ftyp_off+8:ftyp_off+12] = b'M4VH'
    return bytes(result)


# ── Stsd Codec Spoofing (avc1 -> avc3) ─────────────────────────────────

def patch_stsd_codec(data):
    result = bytearray(data)
    moov_off, moov_sz = _find_box(result, b"moov")
    if moov_off == -1:
        return data
    for trak_off, trak_sz, _ in _iter_boxes(result, moov_off+8, moov_off+moov_sz):
        mdia_off, mdia_sz = _find_box(result, b"mdia", trak_off+8, trak_off+trak_sz)
        if mdia_off == -1:
            continue
        hdlr_off, _ = _find_box(result, b"hdlr", mdia_off+8, mdia_off+mdia_sz)
        if hdlr_off == -1:
            continue
        if result[hdlr_off+16:hdlr_off+20] != b'vide':
            continue
        minf_off, minf_sz = _find_box(result, b"minf", mdia_off+8, mdia_off+mdia_sz)
        if minf_off == -1:
            continue
        stbl_off, stbl_sz = _find_box(result, b"stbl", minf_off+8, minf_off+minf_sz)
        if stbl_off == -1:
            continue
        stsd_off, stsd_sz = _find_box(result, b"stsd", stbl_off+8, stbl_off+stbl_sz)
        if stsd_off == -1:
            continue
        entry_off = stsd_off + 16
        if result[entry_off+4:entry_off+8] == b'avc1':
            result[entry_off+4:entry_off+8] = b'avc3'
    return bytes(result)


# ── Main 7-Pass Pipeline ──────────────────────────────────────────────

def patch_all(input_path, output_path, comment=None, log_func=None, use_inflation=True):
    if log_func:
        log_func("[JOB] starting pipeline")

    input_path = Path(input_path)
    output_path = Path(output_path)
    stem = input_path.stem
    suffix = input_path.suffix

    inject_comment = comment is not None and comment != "@akila"

    original_data = input_path.read_bytes()
    original_audio_dur = read_audio_duration(original_data)
    if log_func and original_audio_dur is not None:
        log_func(f"[AUDIO] original duration={original_audio_dur}")

    # ── Pass 1: FFmpeg remux (Faststart, normalize) ──────────────────────
    if log_func:
        log_func("")
        log_func("── 1/7  FFmpeg remux (Faststart) ───────────────────────────")
    clean = input_path.parent / f"{stem}_clean{suffix}"
    cmd = [
        "ffmpeg", "-y",
        "-i", str(input_path),
        "-c", "copy",
        "-movflags", "+faststart",
        "-metadata:s:a:0", "handler_name=SoundHandler",
        str(clean),
    ]
    if log_func:
        log_func(f"[REMUX] $ {' '.join(cmd)}")
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    for line in proc.stdout:
        line = line.rstrip()
        if line and log_func:
            log_func(f"[ffmpeg] {line}")
    proc.wait()
    if proc.returncode != 0:
        if log_func:
            log_func(f"[ERROR] ffmpeg exited {proc.returncode}")
        return False
    if log_func:
        log_func("[REMUX] done")

    data = clean.read_bytes()
    if log_func:
        log_func(f"[READ] {len(data):,} bytes")
        _dump_atoms(data, "REBASE", log_func)

    if use_inflation:
        # ── Pass 2a: Frame Count Inflation (minimal — only remux + inflate) ──
        if log_func:
            log_func("")
            log_func("── 2/2  Frame Count Inflation (5x, sequential, two-entry stts) ────────────────")
        inflated = inflate_sample_table_video(data, multiplier=5)
        if inflated is None:
            if log_func:
                log_func("[ERROR] Frame inflation failed")
            try: clean.unlink(missing_ok=True)
            except: pass
            return False
        data = inflated
        if log_func:
            log_func("[INFLATE] done")
    else:
        # ── Pass 2b: Codec + Brand Spoofing ───────────────────────────
        if log_func:
            log_func("")
            log_func("── 2/2  Codec Spoofing (avc1→avc3, M4VH brand) ───────────────")
        data = patch_stsd_codec(data)
        data = patch_ftyp(data)
        if log_func:
            log_func("[CODEC] done")

    # Final verify
    if log_func:
        log_func("")
        log_func("── Atom layout ───────────────────────────────────────────────")
        _dump_atoms(data, "FINAL", log_func)
        md = data.find(b'mdat')
        mv = data.find(b'moov')
        log_func(f"[VERIFY] mdat at {md}, moov at {mv}, moov at front: {'YES' if mv < md else 'NO'}")
        log_func(f"[VERIFY] file size: {len(data):,} bytes")

    output_path.write_bytes(data)
    if log_func:
        log_func(f"[WRITE] {output_path.name}  ({len(data):,} bytes)")

    try: clean.unlink(missing_ok=True)
    except: pass

    if log_func:
        log_func(f"[DONE]  {output_path.name}")
    return True
