#!/usr/bin/env python3
"""
Core patching engine — TikTok bypass with fingerprint-based re-encode prevention.

Pipeline:
   1. FFmpeg remux (Faststart, normalize)
   2. ZeroLoss Track Bypass (edts/elst rebuild)
   3. mvhd Fingerprint (next_track_id = 9999, fixed creation date)
   4. Udta Strip (remove ffmpeg encoder signature)
   5. Tkhd Fingerprint (identity matrix + alternate_group)
   6. Frame Count Inflation (5x, cycle real data, no filler, avcC/SPS)
   7. Comment Udta Injection (Apple iTunes-style only)
   8. Restore original audio duration
"""

import struct
import subprocess
import time
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
    moov_off, moov_sz = _find_box(data, b"moov")
    if moov_off == -1:
        return data

    data = bytearray(data)
    modifications = []

    for trak_off, trak_sz, _ in _iter_boxes(data, moov_off+8, moov_off+moov_sz):
        tkhd_off, _ = _find_box(data, b"tkhd", trak_off+8, trak_off+trak_sz)
        if tkhd_off == -1:
            continue
        version = data[tkhd_off+8]
        if version == 1:
            duration = int.from_bytes(data[tkhd_off+36:tkhd_off+44], 'big')
        else:
            duration = int.from_bytes(data[tkhd_off+28:tkhd_off+32], 'big')

        mdia_off, mdia_sz = _find_box(data, b"mdia", trak_off+8, trak_off+trak_sz)
        if mdia_off == -1:
            continue
        mdhd_off, _ = _find_box(data, b"mdhd", mdia_off+8, mdia_off+mdia_sz)
        media_time = 0
        if mdhd_off != -1:
            v = data[mdhd_off+8]
            ts_off = mdhd_off + (24 if v == 0 else 32)
            timescale = int.from_bytes(data[ts_off:ts_off+4], 'big')
            if timescale == 90000:
                media_time = 6000

        edts_bytes = build_edts_atom(duration, media_time)
        edts_off, edts_sz = _find_box(data, b"edts", trak_off+8, trak_off+trak_sz)
        if edts_off != -1:
            modifications.append((edts_off, edts_sz, edts_bytes, trak_off))
        else:
            modifications.append((mdia_off, 0, edts_bytes, trak_off))

    modifications.sort(key=lambda x: x[0])
    if not modifications:
        return bytes(data)

    total_delta = sum(len(m[2]) - m[1] for m in modifications)
    new_data = bytearray(len(data) + total_delta)
    read_pos = 0
    write_pos = 0
    for off, old_sz, new_bytes, trak_off in modifications:
        new_data[write_pos:write_pos + off - read_pos] = data[read_pos:off]
        write_pos += off - read_pos
        new_data[write_pos:write_pos + len(new_bytes)] = new_bytes
        write_pos += len(new_bytes)
        read_pos = off + old_sz
    new_data[write_pos:] = data[read_pos:]

    cum_delta = 0
    done_traks = set()
    for off, old_sz, new_bytes, trak_off in modifications:
        if trak_off in done_traks:
            cum_delta += len(new_bytes) - old_sz
            continue
        done_traks.add(trak_off)
        trak_sz = int.from_bytes(new_data[trak_off:trak_off+4], 'big')
        struct.pack_into('>I', new_data, trak_off, trak_sz + cum_delta)
        cum_delta += len(new_bytes) - old_sz

    moov_sz = int.from_bytes(new_data[moov_off:moov_off+4], 'big')
    struct.pack_into('>I', new_data, moov_off, moov_sz + total_delta)
    _adjust_stco(new_data, total_delta, moov_off+8, moov_off+8+moov_sz+total_delta)

    return bytes(new_data)


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
        dur_off = mvhd_off + 24
        nti_off = mvhd_off + 84
    else:
        ct_off = mvhd_off + 20
        dur_off = mvhd_off + 32
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
    """Keep tkhd matrix at identity, but set alternate_group so the
    track-level digest differs from an unmodified file.
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
            matrix_off = tkhd_off + 8 + 40
            group_off = tkhd_off + 8 + 32
        elif version == 1:
            matrix_off = tkhd_off + 8 + 52
            group_off = tkhd_off + 8 + 44
        else:
            continue
        if matrix_off + 36 <= len(p):
            struct.pack_into('>I', p, matrix_off, 0x00010000)
            struct.pack_into('>I', p, matrix_off+4, 0)
            struct.pack_into('>I', p, matrix_off+8, 0)
            struct.pack_into('>I', p, matrix_off+12, 0)
            struct.pack_into('>I', p, matrix_off+16, 0x00010000)
            struct.pack_into('>I', p, matrix_off+20, 0)
            struct.pack_into('>I', p, matrix_off+24, 0)
            struct.pack_into('>I', p, matrix_off+28, 0)
            struct.pack_into('>I', p, matrix_off+32, 0x40000000)
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
                # avcC level + profile
                p[avcC_off+9] = 110   # profile: High → High10
                p[avcC_off+10] = 0    # profile_compat
                p[avcC_off+11] = 62   # level: 5.1 → 6.2
                # SPS NAL is at avcC_off + 16 (after config header)
                sps_start = avcC_off + 16
                if sps_start + 3 < len(p):
                    p[sps_start+1] = 110  # SPS profile_idc
                    p[sps_start+3] = 62   # SPS level_idc
                return bytes(p)
            pos += e_sz
    return data


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
    """5x inflation: two-entry stts + filler NALs at end (non-interleaved).
    Real frames at original delta (60fps), then filler NALs at delta=750.
    Container durations (mvhd/tkhd/mdhd) clipped to real video duration
    to prevent TikTok's player from showing the freeze region.
    Unique stco entries — no compression.
    """
    data = _patch_avcC_sps(data)

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

    stts_off, stts_sz = _find_box(data, b"stts", stbl_off+8, stbl_end)
    stsz_off, stsz_sz = _find_box(data, b"stsz", stbl_off+8, stbl_end)
    stco_off, stco_sz = _find_box(data, b"stco", stbl_off+8, stbl_end)
    stsc_off, stsc_sz = _find_box(data, b"stsc", stbl_off+8, stbl_end)

    if -1 in (stts_off, stsz_off, stco_off, stsc_off):
        return None

    stts_entry_count = int.from_bytes(data[stts_off+12:stts_off+16], 'big')
    real_count = 0
    last_delta = 0
    total_ticks = 0
    for i in range(stts_entry_count):
        off = stts_off + 16 + i * 8
        cnt = int.from_bytes(data[off:off+4], 'big')
        delta = int.from_bytes(data[off+4:off+8], 'big')
        real_count += cnt
        last_delta = delta
        total_ticks += cnt * delta
    if real_count == 0:
        return None

    orig_stco_count = int.from_bytes(data[stco_off+12:stco_off+16], 'big')
    total_count = real_count * multiplier
    fake_count = total_count - real_count
    fake_delta = 750

    # Two-entry stts
    new_stts_body = struct.pack('>II', 0, 2)
    new_stts_body += struct.pack('>II', real_count, last_delta)
    new_stts_body += struct.pack('>II', fake_count, fake_delta)
    new_stts = struct.pack('>I4s', 8 + len(new_stts_body), b'stts') + new_stts_body

    # Find mdat for filler NAL data
    mdat_off, mdat_sz = _find_box(data, b"mdat")
    if mdat_off == -1:
        return None
    FILLER_NAL = b'\x00\x00\x00\x01\x0c\x80'
    FILLER_NAL_SIZE = len(FILLER_NAL)
    filler_data = bytes(FILLER_NAL * fake_count)

    # Read real frame sizes
    orig_stsz_count = int.from_bytes(data[stsz_off+16:stsz_off+20], 'big')
    uniform_size = int.from_bytes(data[stsz_off+12:stsz_off+16], 'big')
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

    # Non-interleaved stsz: all real, then all filler
    new_stsz_body = bytearray(20 + total_count * 4)
    struct.pack_into('>III', new_stsz_body, 0, 0, 0, total_count)
    for i in range(real_count):
        struct.pack_into('>I', new_stsz_body, 12 + i * 4, real_sizes[i])
    for i in range(fake_count):
        struct.pack_into('>I', new_stsz_body, 12 + (real_count + i) * 4, FILLER_NAL_SIZE)
    new_stsz = struct.pack('>I4s', 8 + len(new_stsz_body), b'stsz') + bytes(new_stsz_body)

    # stsc: all chunks have 1 sample
    new_stsc_body = struct.pack('>II', 0, 1)
    new_stsc_body += struct.pack('>III', 1, 1, 1)
    new_stsc = struct.pack('>I4s', 8 + len(new_stsc_body), b'stsc') + bytes(new_stsc_body)

    new_stco_count = total_count
    stts_delta = len(new_stts) - stts_sz
    stsz_delta = len(new_stsz) - stsz_sz
    stco_delta = (new_stco_count - orig_stco_count) * 4
    stsc_delta = len(new_stsc) - stsc_sz
    moov_delta = stts_delta + stsz_delta + stsc_delta + stco_delta

    # Non-interleaved stco: all real offsets, then all filler offsets
    new_stco_body2 = bytearray(8 + new_stco_count * 4)
    struct.pack_into('>II', new_stco_body2, 0, 0, new_stco_count)
    for i in range(real_count):
        struct.pack_into('>I', new_stco_body2, 8 + i * 4, real_offsets[i])
    for i in range(fake_count):
        pos = mdat_off + mdat_sz + i * FILLER_NAL_SIZE
        struct.pack_into('>I', new_stco_body2, 8 + (real_count + i) * 4, pos)
    new_stco2 = struct.pack('>I4s', 8 + len(new_stco_body2), b'stco') + bytes(new_stco_body2)

    replacements = [
        (stts_off, stts_sz, new_stts),
        (stsz_off, stsz_sz, new_stsz),
        (stsc_off, stsc_sz, new_stsc),
        (stco_off, stco_sz, new_stco2),
    ]
    replacements.sort(key=lambda x: x[0])

    new_size = len(data) + moov_delta
    result = bytearray(new_size)

    read_pos = 0
    write_pos = 0
    for off, old_sz, new_bytes in replacements:
        result[write_pos:write_pos + off - read_pos] = data[read_pos:off]
        write_pos += off - read_pos
        result[write_pos:write_pos + len(new_bytes)] = new_bytes
        write_pos += len(new_bytes)
        read_pos = off + old_sz
    result[write_pos:write_pos + len(data) - read_pos] = data[read_pos:]
    write_pos += len(data) - read_pos

    for container_off in (stbl_off, minf_off, mdia_off, trak_off, moov_off):
        old_sz = int.from_bytes(result[container_off:container_off+4], 'big')
        struct.pack_into('>I', result, container_off, old_sz + moov_delta)

    new_moov_end = moov_off + moov_sz + moov_delta
    _adjust_stco(result, moov_delta, moov_off+8, new_moov_end)

    # Extend mdat with filler NALs and update mdat header
    result.extend(filler_data)
    struct.pack_into('>I', result, mdat_off + moov_delta, mdat_sz + len(filler_data))

    # Clip container durations to real video duration (prevent freeze display)
    real_sec = total_ticks / 90000.0
    mvhd_dur = int(real_sec * 1000)  # fallback
    mvhd_off, _ = _find_box(result, b"mvhd", moov_off+8, moov_off+moov_sz+moov_delta)
    if mvhd_off != -1:
        ver = result[mvhd_off+12]
        if ver == 0:
            mvhd_ts = int.from_bytes(result[mvhd_off+24:mvhd_off+28], 'big')
            mvhd_dur = int(real_sec * mvhd_ts)
            result[mvhd_off+28:mvhd_off+32] = struct.pack('>I', mvhd_dur)
        else:
            mvhd_ts = int.from_bytes(result[mvhd_off+32:mvhd_off+36], 'big')
            mvhd_dur = int(real_sec * mvhd_ts)
            result[mvhd_off+36:mvhd_off+44] = struct.pack('>Q', mvhd_dur)

    # Clip tkhd and mdhd for each trak
    for trak_off, trak_sz, _ in _iter_boxes(result, moov_off+8, moov_off+moov_sz+moov_delta):
        tkhd_off, _ = _find_box(result, b"tkhd", trak_off+8, trak_off+trak_sz)
        if tkhd_off != -1:
            ver = result[tkhd_off+12]
            if ver == 0:
                result[tkhd_off+32:tkhd_off+36] = struct.pack('>I', mvhd_dur)
            else:
                result[tkhd_off+44:tkhd_off+52] = struct.pack('>Q', mvhd_dur)

        mdia_off, _ = _find_box(result, b"mdia", trak_off+8, trak_off+trak_sz)
        if mdia_off == -1:
            continue
        hdlr_off, _ = _find_box(result, b"hdlr", mdia_off+8, mdia_off+mdia_sz)
        if hdlr_off == -1:
            continue
        mdhd_off, _ = _find_box(result, b"mdhd", mdia_off+8, mdia_off+mdia_sz)
        if mdhd_off == -1:
            continue
        is_video = result[hdlr_off+16:hdlr_off+20] == b'vide'
        ver = result[mdhd_off+12]
        if is_video:
            if ver == 0:
                mdhd_ts = int.from_bytes(result[mdhd_off+24:mdhd_off+28], 'big')
                mdhd_dur = int(real_sec * mdhd_ts)
                result[mdhd_off+28:mdhd_off+32] = struct.pack('>I', mdhd_dur)
            else:
                mdhd_ts = int.from_bytes(result[mdhd_off+32:mdhd_off+36], 'big')
                mdhd_dur = int(real_sec * mdhd_ts)
                result[mdhd_off+36:mdhd_off+44] = struct.pack('>Q', mdhd_dur)

    return bytes(result)


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


# ── Main 7-Pass Pipeline ──────────────────────────────────────────────

def patch_all(input_path, output_path, comment=None, log_func=None):
    if log_func:
        log_func("[JOB] starting NoBlur 7-pass pipeline")

    input_path = Path(input_path)
    output_path = Path(output_path)
    stem = input_path.stem
    suffix = input_path.suffix

    if comment is None or comment == "@akila":
        ts = int(time.time())
        tag = f"{ts}_{random.randint(0, 0xFFFFFFFF):08x}"
        comment = f"Patched by method.akila - {tag}"

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

    # ── Pass 2: ZeroLoss Track Bypass (edts/elst rebuild) ────────────────
    if log_func:
        log_func("")
        log_func("── 2/7  ZeroLoss Track Bypass (edts/elst) ──────────────────")
    data = rebuild_elst_bypass(data)
    if log_func:
        log_func("[ELST] done")

    # ── Pass 3: Subtle mvhd fingerprint ──────────────────────────────
    if log_func:
        log_func("")
        log_func("── 3/7  mvhd Fingerprint (next_track_id + date) ───────────")
    data = patch_mvhd_fingerprint(data)
    if log_func:
        log_func("[MVHD] done")

    # ── Pass 4: Udta Strip ──────────────────────────────────────────────
    if log_func:
        log_func("")
        log_func("── 4/7  Udta Strip ──────────────────────────────────────────")
    before_sz = len(data)
    data = strip_udta(data)
    stripped = before_sz - len(data)
    if log_func:
        log_func(f"[UDTA] stripped {stripped} bytes" if stripped else "[UDTA] none found")

    # ── Pass 5: Tkhd fingerprint ────────────────────────────────────────
    if log_func:
        log_func("")
        log_func("── 5/7  Tkhd Fingerprint (identity matrix + alternate_group) ──")
    data = fingerprint_tkhd(data)
    if log_func:
        log_func("[TKHD] done")

    # ── Pass 6: Frame Count Inflation (avcC bump + single-entry stts) ─────────
    if log_func:
        log_func("")
        log_func("── 6/7  Frame Count Inflation (5x, non-interleaved, duration clip) ─────")
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

    # ── Pass 7: Comment Udta Injection ───────────────────────────────────
    if log_func:
        log_func("")
        log_func("── 7/7  Comment Udta Injection ─────────────────────────────")
    data = inject_comment_udta(data, comment)
    if log_func:
        log_func("[COMMENT] injected")

    # Restore original audio duration
    if original_audio_dur is not None:
        fixed = patch_audio_duration(data, original_audio_dur)
        if fixed is not None:
            data = fixed
            if log_func:
                log_func(f"[AUDIO] restored duration to {original_audio_dur}")

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
