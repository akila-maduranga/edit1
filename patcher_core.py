#!/usr/bin/env python3
"""
Core patching engine — TikTok bypass with fingerprint-based re-encode prevention.

Pipeline:
   1. FFmpeg remux (Faststart, normalize)
   2. ZeroLoss Track Bypass (edts/elst rebuild)
   3. mvhd Fingerprint (next_track_id = 9999, fixed creation date)
   4. Udta Strip (remove ffmpeg encoder signature)
   5. Tkhd Fingerprint (identity matrix + alternate_group)
   6. Frame Density Inflation (5x, 8-byte dummy samples, EOF padding)
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
    # Set creation/modification time to a fixed point (Jan 1 2020)
    fixed_ts = 1577836800
    if ct_off + 8 <= len(p):
        struct.pack_into('>II', p, ct_off, fixed_ts, fixed_ts)
    # Set next_track_id to a large value to signal "already processed"
    if nti_off + 4 <= len(p):
        struct.pack_into('>I', p, nti_off, 9999)
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
        # Set matrix to identity (standard)
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
        # Set alternate_group to a non-zero value (track-level fingerprint)
        if group_off + 2 <= len(p):
            struct.pack_into('>H', p, group_off, group_id)
            group_id += 1
    return bytes(p)


# ── Frame Density Inflation (3x, valid H.264 filler NALs at EOF) ───────

FILLER_NAL = b'\x00\x00\x00\x01\x0c\x00\x00\x80'  # 8-byte H.264 filler (ignored by decoder)

def inflate_sample_table_video(data, multiplier=3):
    moov_off, moov_sz = _find_box(data, b"moov")
    if moov_off == -1:
        return None

    # Find video stbl
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

    # Read original sample count from stts (support multiple entries)
    stts_entry_count = int.from_bytes(data[stts_off+12:stts_off+16], 'big')
    real_count = 0
    last_delta = 0
    stts_entries = []
    for i in range(stts_entry_count):
        off = stts_off + 16 + i * 8
        cnt = int.from_bytes(data[off:off+4], 'big')
        delta = int.from_bytes(data[off+4:off+8], 'big')
        real_count += cnt
        last_delta = delta
        stts_entries.append((cnt, delta))
    if real_count == 0:
        return None

    orig_stco_count = int.from_bytes(data[stco_off+12:stco_off+16], 'big')
    total_count = real_count * multiplier
    fake_count = total_count - real_count

    # Build stts: original entries + 1 extra for fake frames
    new_stts_body = struct.pack('>II', 0, stts_entry_count + 1)
    for cnt, delta in stts_entries:
        new_stts_body += struct.pack('>II', cnt, delta)
    new_stts_body += struct.pack('>II', fake_count, last_delta)
    new_stts = struct.pack('>I4s', 8 + len(new_stts_body), b'stts') + new_stts_body

    # Build stsz: all entries (real sizes + 8-byte filler)
    uniform_size = int.from_bytes(data[stsz_off+12:stsz_off+16], 'big')
    new_stsz_body = bytearray(20 + total_count * 4)
    struct.pack_into('>III', new_stsz_body, 0, 0, 0, total_count)
    real_sizes_off = stsz_off + 20
    for i in range(real_count):
        if uniform_size != 0:
            val = uniform_size
        else:
            val = int.from_bytes(data[real_sizes_off+i*4:real_sizes_off+i*4+4], 'big')
        struct.pack_into('>I', new_stsz_body, 12 + i*4, val)
    for i in range(fake_count):
        struct.pack_into('>I', new_stsz_body, 12 + real_count*4 + i*4, len(FILLER_NAL))
    new_stsz = struct.pack('>I4s', 8 + len(new_stsz_body), b'stsz') + bytes(new_stsz_body)

    # Compute deltas
    stts_delta = len(new_stts) - stts_sz
    stsz_delta = len(new_stsz) - stsz_sz
    stco_delta = fake_count * 4
    stsc_delta = 12
    moov_delta = stts_delta + stsz_delta + stsc_delta + stco_delta

    new_stco_count = orig_stco_count + fake_count

    # Build stsc: original entries + 1 extra for fake chunks
    stsc_entry_count = int.from_bytes(data[stsc_off+12:stsc_off+16], 'big')
    new_stsc_entry_count = stsc_entry_count + 1
    new_stsc_body = bytearray(8 + new_stsc_entry_count * 12)
    struct.pack_into('>II', new_stsc_body, 0, 0, new_stsc_entry_count)
    base = stsc_off + 16
    for i in range(stsc_entry_count):
        for j in range(3):
            val = int.from_bytes(data[base+i*12+j*4:base+i*12+j*4+4], 'big')
            struct.pack_into('>I', new_stsc_body, 8 + i*12 + j*4, val)
    extra_first_chunk = orig_stco_count + 1
    struct.pack_into('>III', new_stsc_body, 8 + stsc_entry_count*12, extra_first_chunk, 1, 1)
    new_stsc = struct.pack('>I4s', 8 + len(new_stsc_body), b'stsc') + bytes(new_stsc_body)

    # Rebuild stco — offsets as raw original values; _adjust_stco at end adds moov_delta
    stco_base = stco_off + 16
    safe_offset = len(data)  # points to EOF filler NALs; _adjust_stco will add moov_delta
    new_stco_body2 = bytearray(8 + new_stco_count * 4)
    struct.pack_into('>II', new_stco_body2, 0, 0, new_stco_count)
    for i in range(orig_stco_count):
        val = int.from_bytes(data[stco_base+i*4:stco_base+i*4+4], 'big')
        struct.pack_into('>I', new_stco_body2, 8 + i*4, val)
    for i in range(fake_count):
        struct.pack_into('>I', new_stco_body2, 8 + orig_stco_count*4 + i*4, safe_offset)
    new_stco2 = struct.pack('>I4s', 8 + len(new_stco_body2), b'stco') + bytes(new_stco_body2)

    # Replace atoms in order: stts, stsz, stsc, stco
    replacements = [
        (stts_off, stts_sz, new_stts),
        (stsz_off, stsz_sz, new_stsz),
        (stsc_off, stsc_sz, new_stsc),
        (stco_off, stco_sz, new_stco2),
    ]
    replacements.sort(key=lambda x: x[0])

    filler_total = fake_count * len(FILLER_NAL)
    new_size = len(data) + moov_delta + filler_total
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

    # Update container sizes
    for container_off in (stbl_off, minf_off, mdia_off, trak_off, moov_off):
        old_sz = int.from_bytes(result[container_off:container_off+4], 'big')
        struct.pack_into('>I', result, container_off, old_sz + moov_delta)

    # Adjust all stco entries for the moov delta
    new_moov_end = moov_off + moov_sz + moov_delta
    _adjust_stco(result, moov_delta, moov_off+8, new_moov_end)

    # Write valid H.264 filler NALs at EOF
    result[write_pos:write_pos + filler_total] = FILLER_NAL * fake_count

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
    struct.pack_into('>I', buf, p, 0); p += 4      # pre_defined
    struct.pack_into('>4s', buf, p, b'mdir'); p += 4  # handler_type
    struct.pack_into('>4s', buf, p, b'appl'); p += 4  # vendor
    struct.pack_into('>II', buf, p, 0, 0); p += 8    # reserved
    buf[p] = 0; p += 1                               # name (empty)

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

    # ── Pass 6: Frame Density Inflation (5x, 8-byte dummy, EOF padding) ──
    if log_func:
        log_func("")
        log_func("── 6/7  Frame Density Inflation (3x) ───────────────────────")
    inflated = inflate_sample_table_video(data)
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
