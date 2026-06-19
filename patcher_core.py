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
try:
    from tiktok_quality import patch as tiktok_patch
    TIKTOK_QUALITY_AVAILABLE = True
except ImportError:
    TIKTOK_QUALITY_AVAILABLE = False

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
    """Align mvhd to match real TikTok uploads: epoch 0 timestamps,
    next_track_id=3 (video + audio).
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
    # Set creation + modification time to epoch 0 (like real TikTok uploads)
    if ct_off + 8 <= len(p):
        struct.pack_into('>II', p, ct_off, 0, 0)
    # Set next_track_id to 3 (track 1 = video, track 2 = audio)
    if nti_off + 4 <= len(p):
        struct.pack_into('>I', p, nti_off, 3)
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
    """Skip avcC/SPS patching - TikTok accepts standard parameters.
    Reverted to Main Profile (100) and Level 4.0 (40).
    """
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

def _get_avcC_length_size(data):
    """Read lengthSizeMinusOne from the avcC decoder config record.
    Returns the length prefix size in bytes (typically 4).
    """
    avcC_off = data.find(b'avcC')
    if avcC_off == -1 or avcC_off + 9 > len(data):
        return 4  # safe default
    return (data[avcC_off + 8] & 0x03) + 1


def _nal_make_nonref(frame_bytes, length_size):
    """Set nal_ref_idc=0 on the first NAL unit.
    IDR (type 5) frames are left untouched since changing the NAL type
    alters the slice header syntax (idr_pic_id field), which would break
    decoding.  Only non-IDR slices get nal_ref_idc cleared.
    Returns the modified frame bytes.
    """
    if len(frame_bytes) <= length_size:
        return frame_bytes
    nalu_start = length_size
    orig_header = frame_bytes[nalu_start]
    nal_unit_type = orig_header & 0x1F
    # IDR (type 5) — keep as-is (nal_ref_idc != 0 is required).
    # Non-slice NALs (type 6-12, etc.) — keep as-is.
    if nal_unit_type not in (1,):  # non-IDR slice only
        return frame_bytes
    new_header = orig_header & 0x9F  # clear nal_ref_idc bits
    result = bytearray(frame_bytes)
    result[nalu_start] = new_header
    return bytes(result)


def inflate_sample_table_video(data, multiplier=3):
    """Frame inflation by duplicating real frame data.  Each non-IDR
    copy gets nal_ref_idc=0 so duplicate frame_num values are valid
    non-reference pictures.  IDR copies are left as valid IDRs (no
    conflict since each is a complete keyframe).  stss sync samples
    are remapped; ctts is removed (filler frames have no composition
    offset requirement).
    """
    moov_off, moov_sz = _find_box(data, b"moov")
    if moov_off == -1:
        return None

    # Find video track stbl
    video_stbl = None
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

    # Read video mdhd timescale
    mdia_sz_v = int.from_bytes(data[mdia_off:mdia_off+4], 'big')
    mdhd_off_v, _ = _find_box(data, b"mdhd", mdia_off+8, mdia_off+mdia_sz_v)
    video_timescale = 90000
    if mdhd_off_v != -1:
        mdhd_v_ver = data[mdhd_off_v+8]
        if mdhd_v_ver == 0:
            video_timescale = int.from_bytes(data[mdhd_off_v+20:mdhd_off_v+24], 'big')
        else:
            video_timescale = int.from_bytes(data[mdhd_off_v+28:mdhd_off_v+32], 'big')

    # Read real frame count and delta
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

    total_count = real_count * multiplier
    fake_count = total_count - real_count
    fake_delta = 10

    # Read real frame sizes and offsets
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

    length_size = _get_avcC_length_size(data)
    mdat_off, mdat_sz = _find_box(data, b"mdat")

    # Read real frame bytes and build modified copies
    copy_chunks = bytearray()
    for i in range(real_count):
        frame_bytes = data[real_offsets[i] : real_offsets[i] + real_sizes[i]]
        for _ in range(multiplier - 1):
            modified = _nal_make_nonref(frame_bytes, length_size)
            copy_chunks.extend(modified)
    copy_total = len(copy_chunks)

    # Relative offsets within copy_chunks for stco
    copy_offsets_rel = []
    off = 0
    for i in range(real_count):
        fsize = real_sizes[i]
        for _ in range(multiplier - 1):
            copy_offsets_rel.append(off)
            off += fsize

    # Build stts
    new_stts_body = struct.pack('>II', 0, 2)
    new_stts_body += struct.pack('>II', real_count, last_delta)
    new_stts_body += struct.pack('>II', fake_count, fake_delta)
    new_stts = struct.pack('>I4s', 8 + len(new_stts_body), b'stts') + new_stts_body

    # Build stsz
    body_len = 12 + total_count * 4
    new_stsz_body = bytearray(body_len)
    struct.pack_into('>III', new_stsz_body, 0, 0, 0, total_count)
    idx = 0
    for i in range(real_count):
        struct.pack_into('>I', new_stsz_body, 12 + idx * 4, real_sizes[i])
        idx += 1
        for _ in range(multiplier - 1):
            struct.pack_into('>I', new_stsz_body, 12 + idx * 4, real_sizes[i])
            idx += 1
    new_stsz = struct.pack('>I4s', 8 + len(new_stsz_body), b'stsz') + bytes(new_stsz_body)

    # stsc: 1 sample per chunk
    new_stsc_body = struct.pack('>II', 0, 1)
    new_stsc_body += struct.pack('>III', 1, 1, 1)
    new_stsc = struct.pack('>I4s', 8 + len(new_stsc_body), b'stsc') + bytes(new_stsc_body)

    # Build stco
    new_stco_body = bytearray(8 + total_count * 4)
    struct.pack_into('>II', new_stco_body, 0, 0, total_count)
    idx = 0
    copy_idx = 0
    for i in range(real_count):
        struct.pack_into('>I', new_stco_body, 8 + idx * 4, real_offsets[i])
        idx += 1
        for _ in range(multiplier - 1):
            abs_off = mdat_off + mdat_sz + copy_offsets_rel[copy_idx]
            struct.pack_into('>I', new_stco_body, 8 + idx * 4, abs_off)
            idx += 1
            copy_idx += 1
    new_stco = struct.pack('>I4s', 8 + len(new_stco_body), b'stco') + bytes(new_stco_body)

    # Replacements within moov
    replacements = [
        (stts_off, stts_sz, new_stts),
        (stsz_off, stsz_sz, new_stsz),
        (stsc_off, stsc_sz, new_stsc),
        (stco_off, stco_sz, new_stco),
    ]
    replacements.sort(key=lambda x: x[0])
    moov_delta = sum(len(new) - old_sz for _, old_sz, new in replacements)

    total_result_len = len(data) + moov_delta + copy_total
    result = bytearray(total_result_len)

    read_pos = 0
    write_pos = 0
    for off, old_sz, new_bytes in replacements:
        chunk = data[read_pos:off]
        result[write_pos:write_pos + len(chunk)] = chunk
        write_pos += len(chunk)
        result[write_pos:write_pos + len(new_bytes)] = new_bytes
        write_pos += len(new_bytes)
        read_pos = off + old_sz
    remaining = data[read_pos:]
    result[write_pos:write_pos + len(remaining)] = remaining

    # Append modified copy data after original mdat
    copy_start = mdat_off + moov_delta + mdat_sz
    result[copy_start:copy_start + copy_total] = copy_chunks

    # Update mdat header size
    new_mdat_sz = mdat_sz + copy_total
    struct.pack_into('>I', result, copy_start - mdat_sz, new_mdat_sz)

    # Update container sizes
    for container_off in (stbl_off, minf_off, mdia_off, trak_off, moov_off):
        old_sz = int.from_bytes(result[container_off:container_off+4], 'big')
        struct.pack_into('>I', result, container_off, old_sz + moov_delta)

    # Adjust all stco atoms by moov_delta
    new_moov_end = moov_off + moov_sz + moov_delta
    _adjust_stco(result, moov_delta, moov_off+8, new_moov_end)

    # Update durations
    total_stts_dur = (real_count * last_delta) + (fake_count * fake_delta)
    total_sec = total_stts_dur / float(video_timescale)
    mvhd_off, _ = _find_box(result, b"mvhd", moov_off+8, new_moov_end)
    if mvhd_off != -1:
        ver = result[mvhd_off+8]
        if ver == 0:
            mvhd_ts = int.from_bytes(result[mvhd_off+20:mvhd_off+24], 'big')
            mvhd_dur = int(total_sec * mvhd_ts)
            result[mvhd_off+24:mvhd_off+28] = struct.pack('>I', mvhd_dur)
        else:
            mvhd_ts = int.from_bytes(result[mvhd_off+28:mvhd_off+32], 'big')
            mvhd_dur = int(total_sec * mvhd_ts)
            result[mvhd_off+32:mvhd_off+40] = struct.pack('>Q', mvhd_dur)

    for trak_off, trak_sz, _ in _iter_boxes(result, moov_off+8, new_moov_end):
        tkhd_off, _ = _find_box(result, b"tkhd", trak_off+8, trak_off+trak_sz)
        if tkhd_off != -1:
            ver = result[tkhd_off+8]
            if ver == 0:
                result[tkhd_off+28:tkhd_off+32] = struct.pack('>I', mvhd_dur)
            else:
                result[tkhd_off+40:tkhd_off+48] = struct.pack('>Q', mvhd_dur)

        mdia_off, _ = _find_box(result, b"mdia", trak_off+8, trak_off+trak_sz)
        if mdia_off != -1:
            mdhd_off, _ = _find_box(result, b"mdhd", mdia_off+8, mdia_off+mdia_sz)
            if mdhd_off != -1:
                ver = result[mdhd_off+8]
                if ver == 0:
                    mdhd_ts = int.from_bytes(result[mdhd_off+20:mdhd_off+24], 'big')
                    mdhd_dur = int(total_sec * mdhd_ts)
                    result[mdhd_off+24:mdhd_off+28] = struct.pack('>I', mdhd_dur)
                else:
                    mdhd_ts = int.from_bytes(result[mdhd_off+28:mdhd_off+32], 'big')
                    mdhd_dur = int(total_sec * mdhd_ts)
                    result[mdhd_off+32:mdhd_off+40] = struct.pack('>Q', mdhd_dur)

    # Update stss sync sample numbers in-place (no size change)
    stbl_end = stbl_off + int.from_bytes(result[stbl_off+4:stbl_off+8], 'big')
    stss_off, _ = _find_box(result, b"stss", stbl_off+8, stbl_end)
    if stss_off != -1:
        entry_count = int.from_bytes(result[stss_off+12:stss_off+16], 'big')
        for i in range(entry_count):
            off = stss_off + 16 + i * 4
            old = int.from_bytes(result[off:off+4], 'big')
            new_val = (old - 1) * multiplier + 1
            struct.pack_into('>I', result, off, new_val)
    # Zero out ctts entry count (no composition offsets needed for filler)
    ctts_off, _ = _find_box(result, b"ctts", stbl_off+8, stbl_end)
    if ctts_off != -1:
        struct.pack_into('>I', result, ctts_off + 12, 0)

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


# ── Ftyp Brand Spoofing ─────────────────────────────────────────────────

def patch_ftyp(data):
    """Align ftyp to match real TikTok uploads: major=isom, minor=0.2.0,
    compatible brands = isom,iso2,avc1,mp41.
    """
    result = bytearray(data)
    ftyp_off, ftyp_sz = _find_box(result, b"ftyp")
    if ftyp_off == -1:
        return data
    # Major brand: isom (TikTok-native)
    result[ftyp_off+8:ftyp_off+12] = b'isom'
    # Minor version: 0.2.0
    result[ftyp_off+12:ftyp_off+16] = struct.pack('>I', 0x00000200)
    # Compatible brands: isom, iso2, avc1, mp41
    compat = b'isomiso2avc1mp41'
    compat_end = ftyp_off + 16 + len(compat)
    if compat_end <= ftyp_off + ftyp_sz:
        result[ftyp_off+16:compat_end] = compat
    return bytes(result)


def shuffle_moov_atoms(data):
    """Shuffle atom order within moov to change fingerprint without affecting playback."""
    moov_off, moov_sz = _find_box(data, b"moov")
    if moov_off == -1:
        return data

    # Collect all atoms within moov (excluding moov header itself)
    atoms = []
    for off, sz, btype in _iter_boxes(data, moov_off+8, moov_off+moov_sz):
        atoms.append((off, sz, btype, data[off:off+sz]))

    if len(atoms) < 2:
        return data

    # Shuffle non-critical atoms (keep mvhd, trak atoms in place)
    critical = {b'mvhd', b'trak'}
    non_critical = [a for a in atoms if a[2] not in critical]
    critical_atoms = [a for a in atoms if a[2] in critical]

    # Simple shuffle of non-critical atoms
    import random
    random.shuffle(non_critical)

    # Rebuild moov
    new_moov = bytearray()
    new_moov.extend(data[moov_off:moov_off+8])  # moov header
    for a in critical_atoms + non_critical:
        new_moov.extend(a[3])

    # Update moov size
    struct.pack_into('>I', new_moov, 0, len(new_moov))

    # Replace in data
    result = bytearray(data)
    result[moov_off:moov_off+moov_sz] = bytes(new_moov)

    # Adjust stco for moov size change
    delta = len(new_moov) - moov_sz
    if delta != 0:
        _adjust_stco(result, delta, moov_off+8, len(result))

    return bytes(result)


# ── Stsd Codec Spoofing (avc1 -> avc3) ─────────────────────────────────

def patch_avcC_profile(data):
    """Keep original avcC profile/level to match real TikTok uploads.
    TikTok-native videos typically use High@4.2 or original encoder values.
    """
    return data


def patch_stsd_codec(data):
    """Keep avc1 codec type to match real TikTok upload metadata.
    Fingerprint diversity comes from inflation and atom order instead.
    """
    return data


# ── IDR Frame Detection ─────────────────────────────────────────────────

# ── Video Resolution Detection ─────────────────────────────────────────

def get_video_resolution(data):
    """Extract video resolution from MP4 metadata."""
    moov_off, moov_sz = _find_box(data, b"moov")
    if moov_off == -1:
        return None
    
    for trak_off, trak_sz, _ in _iter_boxes(data, moov_off+8, moov_off+moov_sz):
        mdia_off, mdia_sz = _find_box(data, b"mdia", trak_off+8, trak_off+trak_sz)
        if mdia_off == -1:
            continue
        
        hdlr_off, hdlr_sz = _find_box(data, b"hdlr", mdia_off+8, mdia_off+mdia_sz)
        if hdlr_off == -1:
            continue
        
        # Check if this is a video track
        if data[hdlr_off+16:hdlr_off+20] != b'vide':
            continue
        
        # Find tkhd to get dimensions
        tkhd_off, tkhd_sz = _find_box(data, b"tkhd", trak_off+8, trak_off+trak_sz)
        if tkhd_off == -1:
            continue
        
        version = data[tkhd_off+12]
        if version == 0:
            # 32-bit values
            width = int.from_bytes(data[tkhd_off+40:tkhd_off+44], 'big') >> 16
            height = int.from_bytes(data[tkhd_off+44:tkhd_off+48], 'big') >> 16
        else:
            # 64-bit values
            width = int.from_bytes(data[tkhd_off+52:tkhd_off+56], 'big') >> 16
            height = int.from_bytes(data[tkhd_off+56:tkhd_off+60], 'big') >> 16
        
        return (width, height)
    
    return None


# ── Move moov to end ─────────────────────────────────────────────────────

def move_moov_to_end(data):
    """Move moov atom to end of file (non-faststart) and adjust stco offsets.
    TikTok's uploader is known to handle non-faststart files better for this exploit.
    """
    moov_off, moov_sz = _find_box(data, b"moov")
    if moov_off == -1:
        return data

    mdat_off, mdat_sz = _find_box(data, b"mdat")
    if mdat_off == -1:
        return data

    # Check if moov is already at end
    if moov_off > mdat_off:
        return data

    ftyp_off, ftyp_sz = _find_box(data, b"ftyp")
    if ftyp_off == -1:
        return data

    # Build new structure: ftyp + mdat + moov
    new_data = bytearray()
    new_data += data[ftyp_off:ftyp_off+ftyp_sz]
    new_data += data[mdat_off:mdat_off+mdat_sz]
    new_data += data[moov_off:moov_off+moov_sz]

    # After moving, mdat is now at offset ftyp_sz (old position was ftyp_sz + moov_sz)
    # So all stco offsets must be decreased by moov_sz
    shift = -moov_sz

    # Find and adjust all stco atoms inside the new moov
    new_data = bytearray(new_data)
    pos = 0
    while pos < len(new_data):
        idx = new_data.find(b'stco', pos)
        if idx == -1:
            break
        # stco: size(4) type(4) version_flags(4) entry_count(4) [offsets...]
        entry_count = int.from_bytes(new_data[idx+12:idx+16], 'big')
        off = idx + 16
        for _ in range(entry_count):
            if off + 4 > len(new_data):
                break
            old = int.from_bytes(new_data[off:off+4], 'big')
            new_off = old + shift
            # Ensure new offset is within valid range
            if new_off >= 0:
                new_data[off:off+4] = struct.pack('>I', new_off)
            off += 4
        pos = idx + 4  # continue searching

    return bytes(new_data)


# ── Main 7-Pass Pipeline ──────────────────────────────────────────────

def patch_all(input_path, output_path, comment=None, log_func=None, use_inflation=True):
    if log_func:
        log_func("[JOB] starting NoBlur 7-pass pipeline")

    input_path = Path(input_path)
    output_path = Path(output_path)
    stem = input_path.stem
    suffix = input_path.suffix

    # Detect video resolution for logging
    original_data = input_path.read_bytes()
    resolution = get_video_resolution(original_data)
    if resolution and log_func:
        width, height = resolution
        log_func(f"[RESOLUTION] {width}x{height}")

    if comment is None or comment == "@akila":
        ts = int(time.time())
        tag = f"{ts}_{random.randint(0, 0xFFFFFFFF):08x}"
        comment = f"Patched by method.akila - {tag}"

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
    # SKIPPED: Not essential for exploit and often causes issues
    # if log_func:
    #     log_func("")
    #     log_func("── 2/7  ZeroLoss Track Bypass (edts/elst) ──────────────────")
    # data = rebuild_elst_bypass(data)
    # if log_func:
    #     log_func("[ELST] done")

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
        log_func("── 5/7  Tkhd Fingerprint (alternate_group, preserve orientation) ──")
    data = fingerprint_tkhd(data)
    if log_func:
        log_func("[TKHD] done")

    # ── Pass 6: Metadata Fingerprinting (always applied) ─────────────
    if log_func:
        log_func("")
        log_func("── 6/7  Metadata Fingerprint ─────────────────────────────────")
    data = patch_stsd_codec(data)
    data = patch_avcC_profile(data)
    data = patch_ftyp(data)
    data = shuffle_moov_atoms(data)
    if log_func:
        log_func("[FINGERPRINT] done")

    # ── Pass 6b: Frame Count Inflation (optional, often unreliable) ─────
    if use_inflation:
        if log_func:
            log_func("")
            log_func("── 6b/7  Frame Count Inflation (3x) ────────────────────────")
        inflated = inflate_sample_table_video(data, multiplier=3)
        if inflated is not None:
            data = inflated
            if log_func:
                log_func("[INFLATE] done")
        elif log_func:
            log_func("[INFLATE] skipped — metadata-only fallback applied instead")
    
    # ── Pass 7: Comment Udta Injection ───────────────────────────────────
    if log_func:
        log_func("")
        log_func("── 7/7  Comment Udta Injection ─────────────────────────────")
    data = inject_comment_udta(data, comment)
    if log_func:
        log_func("[COMMENT] injected")

    # ── Pass 8: Move moov to end (non-faststart) ─────────────────────────
    # SKIPPED: Non-faststart files are unplayable until fully downloaded
    # if log_func:
    #     log_func("")
    #     log_func("── 8/8  Move moov to end (non-faststart) ───────────────────────")
    # data = move_moov_to_end(data)
    # if log_func:
    #     log_func("[MOOV] moved to end")

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
