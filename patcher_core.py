#!/usr/bin/env python3
"""
Core patching engine — TikTok bypass with fingerprint-based re-encode prevention.

Pipeline:
   1. FFmpeg remux (Faststart, normalize)
   2. ZeroLoss Track Bypass (edts/elst rebuild)
   3. mvhd Fingerprint (next_track_id = 9999, fixed creation date)
   4. Udta Strip (remove ffmpeg encoder signature)
    5. Tkhd Fingerprint (alternate_group, preserve original orientation)
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
    """Change mvhd timestamps and next_track_id using minimal, plausible values."""
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
    fixed_ts = 1_700_000_000  # Nov 2023 — plausible
    if ct_off + 8 <= len(p):
        struct.pack_into('>II', p, ct_off, fixed_ts, fixed_ts)
    if nti_off + 4 <= len(p):
        orig_nti = int.from_bytes(p[nti_off:nti_off+4], 'big')
        struct.pack_into('>I', p, nti_off, orig_nti + 1)
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
            group_off = tkhd_off + 8 + 34  # alternate_group for v0
        elif version == 1:
            group_off = tkhd_off + 8 + 46  # alternate_group for v1
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

def inflate_sample_table_video(data, multiplier=5, original_size=None):
    """NoBlur-style inflation: 8-byte dummy samples at a single offset.
    No valid NAL content needed. TikTok re-encodes anyway.
    """
    moov_off, moov_sz = _find_box(data, b"moov")
    if moov_off == -1:
        return None
    moov_end = moov_off + moov_sz

    video_stbl = None
    for trak_off, trak_sz, _ in _iter_boxes(data, moov_off+8, moov_end):
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

    # Read original stts
    stts_entry_count = int.from_bytes(data[stts_off+12:stts_off+16], 'big')
    real_count = 0
    total_duration = 0
    for i in range(stts_entry_count):
        off = stts_off + 16 + i * 8
        cnt = int.from_bytes(data[off:off+4], 'big')
        delta = int.from_bytes(data[off+4:off+8], 'big')
        real_count += cnt
        total_duration += cnt * delta
    if real_count == 0:
        return None

    sample_delta = round(total_duration / real_count)
    fake_count = real_count * (multiplier - 1)
    total_count = real_count + fake_count
    orig_chunk_count = int.from_bytes(data[stco_off+12:stco_off+16], 'big')

    # Detect codec for dummy size (NoBlur: 8B for avc1/avc3)
    stsd_off, _ = _find_box(data, b"stsd", stbl_off+8, stbl_end)
    codec = b'avc1'
    if stsd_off != -1 and stsd_off+20 <= len(data):
        codec = data[stsd_off+16:stsd_off+20]
    dummy_size = {b'avc1': 8, b'avc3': 8, b'hvc1': 16, b'hev1': 16, b'vp09': 4, b'av01': 4}.get(codec, 8)

    # Read real sizes from stsz
    uniform = int.from_bytes(data[stsz_off+12:stsz_off+16], 'big')
    real_sizes = []
    for i in range(real_count):
        if uniform != 0:
            real_sizes.append(uniform)
        else:
            real_sizes.append(int.from_bytes(data[stsz_off+20+i*4:stsz_off+24+i*4], 'big'))

    # Build new stts: preserve original entries + 1 filler entry
    new_stts_body = struct.pack('>II', 0, stts_entry_count + 1)
    for i in range(stts_entry_count):
        off = stts_off + 16 + i * 8
        cnt = int.from_bytes(data[off:off+4], 'big')
        delta = int.from_bytes(data[off+4:off+8], 'big')
        new_stts_body += struct.pack('>II', cnt, delta)
    new_stts_body += struct.pack('>II', fake_count, sample_delta)
    new_stts = struct.pack('>I4s', 8 + len(new_stts_body), b'stts') + bytes(new_stts_body)

    # Build new stsz: real + all dummy
    new_stsz_body = bytearray(20 + total_count * 4)
    struct.pack_into('>III', new_stsz_body, 0, 0, 0, total_count)
    for i in range(real_count):
        struct.pack_into('>I', new_stsz_body, 12 + i * 4, real_sizes[i])
    for i in range(fake_count):
        struct.pack_into('>I', new_stsz_body, 12 + (real_count + i) * 4, dummy_size)
    new_stsz = struct.pack('>I4s', 8 + len(new_stsz_body), b'stsz') + bytes(new_stsz_body)

    # Build stsc: original entries + new entry for fake chunks (1 spc)
    stsc_entry_count = int.from_bytes(data[stsc_off+12:stsc_off+16], 'big')
    new_stsc_body = bytearray(16 + (stsc_entry_count + 1) * 12)
    struct.pack_into('>II', new_stsc_body, 0, 0, stsc_entry_count + 1)
    for i in range(stsc_entry_count):
        off = stsc_off + 16 + i * 12
        struct.pack_into('>III', new_stsc_body, 8 + i * 12,
                         int.from_bytes(data[off:off+4], 'big'),
                         int.from_bytes(data[off+4:off+8], 'big'),
                         int.from_bytes(data[off+8:off+12], 'big'))
    struct.pack_into('>III', new_stsc_body, 8 + stsc_entry_count * 12,
                     orig_chunk_count + 1, 1, 1)
    new_stsc = struct.pack('>I4s', 8 + len(new_stsc_body), b'stsc') + bytes(new_stsc_body)

    # Calculate deltas
    stts_delta = len(new_stts) - stts_sz
    stsz_delta = len(new_stsz) - stsz_sz
    stsc_delta = len(new_stsc) - stsc_sz
    stco_delta = fake_count * 4
    moov_delta = stts_delta + stsz_delta + stsc_delta + stco_delta

    # Safe offset = file size + moov_delta (start of EOF padding)
    safe_offset = len(data) + moov_delta

    # Build new stco: original offsets (shifted) + all fake at safe_offset
    new_stco_body = bytearray(8 + (orig_chunk_count + fake_count) * 4)
    struct.pack_into('>II', new_stco_body, 0, 0, orig_chunk_count + fake_count)
    for i in range(orig_chunk_count):
        off = int.from_bytes(data[stco_off+16+i*4:stco_off+20+i*4], 'big')
        struct.pack_into('>I', new_stco_body, 8 + i * 4, off + moov_delta)
    for i in range(fake_count):
        struct.pack_into('>I', new_stco_body, 8 + (orig_chunk_count + i) * 4, safe_offset)
    new_stco = struct.pack('>I4s', 8 + len(new_stco_body), b'stco') + bytes(new_stco_body)

    # Replace boxes in stbl
    replacements = [
        (stts_off, stts_sz, new_stts),
        (stsz_off, stsz_sz, new_stsz),
        (stsc_off, stsc_sz, new_stsc),
        (stco_off, stco_sz, new_stco),
    ]
    replacements.sort(key=lambda x: x[0])

    padding_sz = fake_count * dummy_size
    new_sz = len(data) + moov_delta + padding_sz
    result = bytearray(new_sz)

    read_pos = 0
    write_pos = 0
    for off, old_sz, new_bytes in replacements:
        chunk = data[read_pos:off]
        result[write_pos:write_pos + len(chunk)] = chunk
        write_pos += len(chunk)
        result[write_pos:write_pos + len(new_bytes)] = new_bytes
        write_pos += len(new_bytes)
        read_pos = off + old_sz
    if read_pos < len(data):
        rest = data[read_pos:]
        result[write_pos:write_pos + len(rest)] = rest

    # Update container sizes
    for c_off in (stbl_off, minf_off, mdia_off, trak_off, moov_off):
        old = int.from_bytes(result[c_off:c_off+4], 'big')
        struct.pack_into('>I', result, c_off, old + moov_delta)

    # Extend mdat to include dummy padding (keep file valid)
    mdat_off, mdat_sz = _find_box(result, b"mdat")
    if mdat_off != -1:
        struct.pack_into('>I', result, mdat_off, mdat_sz + padding_sz)

    # Clip container durations to real video duration (hide freeze)
    real_sec = total_duration / 90000.0
    mvhd_off, _ = _find_box(result, b"mvhd", moov_off+8, moov_off+int.from_bytes(result[moov_off:moov_off+4], 'big'))
    if mvhd_off != -1:
        ver = result[mvhd_off+12]
        if ver == 0:
            ts = int.from_bytes(result[mvhd_off+24:mvhd_off+28], 'big')
            result[mvhd_off+28:mvhd_off+32] = struct.pack('>I', int(real_sec * ts))
        else:
            ts = int.from_bytes(result[mvhd_off+32:mvhd_off+36], 'big')
            result[mvhd_off+36:mvhd_off+44] = struct.pack('>Q', int(real_sec * ts))
    for t_off, t_sz, _ in _iter_boxes(result, moov_off+8, moov_off+int.from_bytes(result[moov_off:moov_off+4], 'big')):
        tkhd_off, _ = _find_box(result, b"tkhd", t_off+8, t_off+t_sz)
        if tkhd_off != -1:
            ver = result[tkhd_off+12]
            if ver == 0:
                result[tkhd_off+32:tkhd_off+36] = struct.pack('>I', int(real_sec * 1000))
            else:
                result[tkhd_off+44:tkhd_off+52] = struct.pack('>Q', int(real_sec * 1000))
        mdia_off, _ = _find_box(result, b"mdia", t_off+8, t_off+t_sz)
        if mdia_off != -1:
            hdlr_off, _ = _find_box(result, b"hdlr", mdia_off+8, mdia_off+int.from_bytes(result[mdia_off:mdia_off+4], 'big'))
            if hdlr_off != -1 and result[hdlr_off+16:hdlr_off+20] == b'vide':
                mdhd_off, _ = _find_box(result, b"mdhd", mdia_off+8, mdia_off+int.from_bytes(result[mdia_off:mdia_off+4], 'big'))
                if mdhd_off != -1:
                    ver = result[mdhd_off+12]
                    if ver == 0:
                        ts = int.from_bytes(result[mdhd_off+24:mdhd_off+28], 'big')
                        result[mdhd_off+28:mdhd_off+32] = struct.pack('>I', int(real_sec * ts))
                    else:
                        ts = int.from_bytes(result[mdhd_off+32:mdhd_off+36], 'big')
                        result[mdhd_off+36:mdhd_off+44] = struct.pack('>Q', int(real_sec * ts))

    # Update all NON-video trak stco/co64 with moov_delta
    new_moov_end = moov_off + int.from_bytes(result[moov_off:moov_off+4], 'big')
    for t_off, t_sz, _ in _iter_boxes(result, moov_off+8, new_moov_end):
        if t_off == trak_off:
            continue  # video track already has moov_delta in its new stco
        t_mdia_off, _ = _find_box(result, b"mdia", t_off+8, t_off+t_sz)
        if t_mdia_off == -1:
            continue
        t_minf_off, _ = _find_box(result, b"minf", t_mdia_off+8,
                                  t_mdia_off + int.from_bytes(result[t_mdia_off:t_mdia_off+4], 'big'))
        if t_minf_off == -1:
            continue
        t_stbl_off, _ = _find_box(result, b"stbl", t_minf_off+8,
                                  t_minf_off + int.from_bytes(result[t_minf_off:t_minf_off+4], 'big'))
        if t_stbl_off == -1:
            continue
        t_stbl_end = t_stbl_off + int.from_bytes(result[t_stbl_off:t_stbl_off+4], 'big')
        t_stco_off, _ = _find_box(result, b"stco", t_stbl_off+8, t_stbl_end)
        if t_stco_off != -1:
            cnt = int.from_bytes(result[t_stco_off+12:t_stco_off+16], 'big')
            for i in range(cnt):
                pos = t_stco_off + 16 + i * 4
                old = int.from_bytes(result[pos:pos+4], 'big')
                struct.pack_into('>I', result, pos, old + moov_delta)
        t_co64_off, _ = _find_box(result, b"co64", t_stbl_off+8, t_stbl_end)
        if t_co64_off != -1:
            cnt = int.from_bytes(result[t_co64_off+12:t_co64_off+16], 'big')
            for i in range(cnt):
                pos = t_co64_off + 16 + i * 8
                old = int.from_bytes(result[pos:pos+8], 'big')
                struct.pack_into('>Q', result, pos, old + moov_delta)

    # Auto-pad to match expected size for inflated bitrate
    if original_size is not None:
        target_size = original_size * multiplier
        need = max(0, target_size - len(result))
        if need > 0:
            free_sz = 8 + need
            free_box = struct.pack('>I4s', free_sz, b'free') + b'\x00' * need
            result.extend(free_box)

    return bytes(result)


# ── Comment Udta Injection (meta/ilst, only \xa9cmt) ───────────────────

def patch_elst_loop(data, loop_count=5):
    """Replace video track's elst with a multi-entry loop covering the
    real-frame portion. Filler frames in stts are ignored during display,
    so the freeze is hidden and video appears to repeat `loop_count` times.
    """
    moov_off, moov_sz = _find_box(data, b"moov")
    if moov_off == -1:
        return data
    moov_end = moov_off + moov_sz

    for trak_off, trak_sz, _ in _iter_boxes(data, moov_off+8, moov_end):
        mdia_off, mdia_sz = _find_box(data, b"mdia", trak_off+8, trak_off+trak_sz)
        if mdia_off == -1:
            continue
        hdlr_off, _ = _find_box(data, b"hdlr", mdia_off+8, mdia_off+mdia_sz)
        if hdlr_off == -1 or data[hdlr_off+16:hdlr_off+20] != b'vide':
            continue
        stbl_off, stbl_sz = _find_box(data, b"stbl", mdia_off+8, mdia_off+mdia_sz)
        if stbl_off == -1:
            continue
        stts_off, _ = _find_box(data, b"stts", stbl_off+8, stbl_off+stbl_sz)
        if stts_off == -1:
            continue
        entry_cnt = int.from_bytes(data[stts_off+12:stts_off+16], 'big')
        if entry_cnt == 0:
            continue
        first_cnt = int.from_bytes(data[stts_off+16:stts_off+20], 'big')
        first_delta = int.from_bytes(data[stts_off+20:stts_off+24], 'big')
        real_ticks = first_cnt * first_delta

        # Build 5-entry elst
        elst_body = struct.pack('>II', 0, loop_count)
        for _ in range(loop_count):
            elst_body += struct.pack('>IIii', real_ticks, 0, 0x00010000)
        elst_full = struct.pack('>I4s', 12 + len(elst_body), b'elst') + bytes(elst_body)
        edts_new = struct.pack('>I4s', 8 + len(elst_full), b'edts') + elst_full

        edts_off, edts_sz = _find_box(data, b"edts", trak_off+8, trak_off+trak_sz)
        edts_old = data[edts_off:edts_off+edts_sz] if edts_off != -1 else b''
        delta = len(edts_new) - (edts_sz if edts_off != -1 else 0)

        # Rebuild buffer
        if edts_off != -1:
            before = data[:edts_off]
            after = data[edts_off + edts_sz:]
        else:
            before = data[:mdia_off]
            after = data[mdia_off:]

        result = bytearray(len(data) + delta)
        result[:len(before)] = before
        result[len(before):len(before)+len(edts_new)] = edts_new
        result[len(before)+len(edts_new):] = after

        # Update container sizes
        for c_off in (trak_off, moov_off):
            old = int.from_bytes(result[c_off:c_off+4], 'big')
            struct.pack_into('>I', result, c_off, old + delta)
        new_moov_sz = moov_sz + delta
        _adjust_stco(result, delta, moov_off+8, moov_off+8+new_moov_sz)
        return bytes(result)
    return data


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


# ── Free Box Padding (bitrate inflation) ────────────────────────────────

def add_padding_free(data, padding_mb=50):
    """Append a 'free' box with zero padding to inflate file size.
    TikTok may see the inflated size as 'already high bitrate' and skip re-encode.
    """
    padding_bytes = padding_mb * 1024 * 1024
    box_size = 8 + padding_bytes
    buf = bytearray(box_size)
    struct.pack_into('>I4s', buf, 0, box_size, b'free')
    result = bytearray(len(data) + box_size)
    result[:len(data)] = data
    result[len(data):] = buf
    return bytes(result)


# ── Ftyp Brand Spoofing ─────────────────────────────────────────────────

def patch_ftyp(data):
    result = bytearray(data)
    ftyp_off, ftyp_sz = _find_box(result, b"ftyp")
    if ftyp_off == -1:
        return data
    # Overwrite major brand + first compatible brand
    result[ftyp_off+8:ftyp_off+12] = b'M4VH'
    compat_off = ftyp_off + 16
    compat_end = ftyp_off + ftyp_sz
    if compat_off + 8 <= compat_end:
        result[compat_off:compat_off+8] = b'M4VH' + b'M4VP'
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


# ── Stsd Bitrate Spoofing ──────────────────────────────────────────────

def patch_stsd_bitrate(data, bitrate=100_000_000):
    """Set a high bitrate in the video sample entry's btrt box (if present)."""
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
        entry_sz = int.from_bytes(result[entry_off:entry_off+4], 'big')
        entry_end = entry_off + entry_sz
        btrt_off, btrt_sz = _find_box(result, b"btrt", entry_off+8, entry_end)
        if btrt_off != -1:
            struct.pack_into('>III', result, btrt_off+8, bitrate//8, bitrate, bitrate)
            break
    return bytes(result)


# ── Main 7-Pass Pipeline ──────────────────────────────────────────────

def patch_all(input_path, output_path, comment=None, log_func=None, use_inflation=True, brand_spoof_only=False, minimal=False, skip_udta=False, multiplier=5):
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

    # ── Pass 2: ZeroLoss Track Bypass (edts/elst rebuild) ─────────
    if log_func:
        log_func("")
        log_func("── 2/7  ZeroLoss Track Bypass (edts/elst) ──────────────────")
    data = rebuild_elst_bypass(data)
    if log_func:
        log_func("[ELST] done")

    if not minimal:
        # ── Pass 3: Subtle mvhd fingerprint ──────────────────────────
        if log_func:
            log_func("")
            log_func("── 3/7  mvhd Fingerprint (next_track_id + date) ───────────")
        data = patch_mvhd_fingerprint(data)
        if log_func:
            log_func("[MVHD] done")

        # ── Pass 4: Udta Strip ──────────────────────────────────────
        if skip_udta:
            if log_func:
                log_func("")
                log_func("── 4/7  (skipped — skip_udta=True)")
        else:
            if log_func:
                log_func("")
                log_func("── 4/7  Udta Strip ──────────────────────────────────────────")
            before_sz = len(data)
            data = strip_udta(data)
            stripped = before_sz - len(data)
            if log_func:
                log_func(f"[UDTA] stripped {stripped} bytes" if stripped else "[UDTA] none found")

        # ── Pass 5: Tkhd fingerprint ────────────────────────────────
        if log_func:
            log_func("")
            log_func("── 5/7  Tkhd Fingerprint (alternate_group, preserve orientation) ──")
        data = fingerprint_tkhd(data)
        if log_func:
            log_func("[TKHD] done")
    else:
        if log_func:
            log_func("")
            log_func("── 3-5/7  (skipped — minimal mode)")

    # ── Pass 6: SPS/avcC spoofing (High10 + level 6.2) ──────────────
    if log_func:
        log_func("")
        log_func("── 6/7  SPS/avcC Spoof (High10, 6.2) ───────────────────────────")
    data = _patch_avcC_sps(data)
    if log_func:
        log_func("[AVCC] done")

    # ── Pass 7: Codec avc1→avc3 ────────────────────────────────────
    if log_func:
        log_func("")
        log_func("── 7/7  Codec avc1 → avc3 ─────────────────────────────────────")
    data = patch_stsd_codec(data)
    if log_func:
        log_func("[CODEC] avc3")

    if use_inflation:
        # ── Pass 8: Frame Count Inflation ────────────────────────────
        if log_func:
            log_func("")
            log_func("── 8/8  Frame Count Inflation (5x, non-interleaved, duration clip) ─────")
        inflated = inflate_sample_table_video(data, multiplier=multiplier, original_size=len(original_data))
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
        # ── Pass 8: Brand + Bitrate Spoofing ───────────────────────
        if log_func:
            log_func("")
            log_func("── 8/8  Brand + Bitrate Spoofing ────────────────────────────")
        data = patch_ftyp(data)
        if not brand_spoof_only:
            data = patch_stsd_bitrate(data, 50_000_000)
        if log_func:
            log_func("[SPOOF] M4VH brand" + (" + 50Mbps" if not brand_spoof_only else ""))
    
    # ── Pass 9: Comment Udta Injection ───────────────────────────────────
    if log_func:
        log_func("")
        log_func("── 9/9  Comment Udta Injection ─────────────────────────────")
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
