#!/usr/bin/env python3
"""
Core patching engine — prevents TikTok duration-doubling bug via MP4 structure manipulation.

Pipeline:
   1. Python reloov (moov to front)
   2. mvhd Fingerprint (next_track_id, fixed creation time)
   3. Udta Strip (remove encoder signature)
   4. Tkhd Fingerprint (alternate_group)
   5. Bypass Method (inflate / balanced-sync / codec-spoof)
   6. Comment Udta Injection (iTunes-style)
   7. Restore original audio duration
"""

import struct
import random
from pathlib import Path

_SCRIPT_DIR = Path(__file__).parent


def _iter_boxes(data, start=0, end=None):
    if end is None:
        end = len(data)
    i = start
    while i + 8 <= end:
        size_bytes = data[i:i+4]
        if len(size_bytes) < 4:
            break
        size = struct.unpack(">I", size_bytes)[0]
        btype = data[i+4:i+8]
        if size == 1:
            if i + 16 > end:
                break
            size = struct.unpack(">Q", data[i+8:i+16])[0]
            header_len = 16
        elif size == 0:
            size = end - i
            header_len = 8
        else:
            header_len = 8
        if size < header_len or size > end - i:
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
    stack = [(search_start, search_end)]
    while stack:
        start, end = stack.pop()
        for off, sz, btype in _iter_boxes(data, start, end):
            if btype in (b'stco', b'co64'):
                entry_size = 4 if btype == b'stco' else 8
                entry_count = int.from_bytes(data[off+12:off+16], 'big')
                pos = off + 16
                for _ in range(entry_count):
                    old = int.from_bytes(data[pos:pos+entry_size], 'big')
                    new_val = min(max(old + delta, 0), (1 << (8 * entry_size)) - 1)
                    data[pos:pos+entry_size] = new_val.to_bytes(entry_size, 'big')
                    pos += entry_size
            elif sz > 8:
                stack.append((off + 8, off + sz))


def validate_mp4(data):
    """Validate basic MP4 structure: ftyp at start, moov and mdat present, boxes well-formed."""
    if len(data) < 12:
        return False, "file too small"
    ftyp_off, ftyp_sz = _find_box(data, b"ftyp")
    if ftyp_off == -1:
        return False, "missing ftyp box"
    if ftyp_off != 0:
        return False, "ftyp not at start of file"
    moov_off, moov_sz = _find_box(data, b"moov")
    if moov_off == -1:
        return False, "missing moov box"
    if moov_sz < 8:
        return False, "moov box too small"
    mdat_off, mdat_sz = _find_box(data, b"mdat")
    if mdat_off == -1:
        return False, "missing mdat box"
    if mdat_sz < 8:
        return False, "mdat box too small"
    total_parsed = 0
    for off, sz, bt in _iter_boxes(data):
        if sz < 8:
            return False, f"box {bt} at offset {off} has invalid size {sz}"
        total_parsed += sz
        if off + sz > len(data):
            return False, f"box {bt} at offset {off} extends past file end"
    return True, "ok"


def _dump_atoms(data, label="", log_func=None):
    if not log_func:
        return
    i = 0
    while i + 8 <= len(data):
        size = int.from_bytes(data[i:i+4], 'big')
        kind = data[i+4:i+8]
        if size == 1:
            if i + 16 > len(data):
                break
            size = int.from_bytes(data[i+8:i+16], 'big')
            hdr = 16
        elif size == 0:
            size = len(data) - i
            hdr = 8
        else:
            hdr = 8
        if size < hdr:
            break
        log_func(f"  [{label}]  offset {i:>8}  size {size:>10}  hdr {hdr}  {kind.decode('latin1', errors='replace')}")
        i += size





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
    # Only adjust stco if moov is before mdat (mdat moves when moov changes)
    mdat_off, _ = _find_box(data, b"mdat")
    if moov_off < mdat_off:
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
    return bytes(p)


# ── Frame Inflation ────────────────────────────────────────────────────


def _sample_offsets(data, stco_off, stsc_off, stsz_off, sample_count, entry_size=4):
    """Expand chunk offsets to per-sample offsets using stsc + stsz.
    entry_size: 4 for stco (32-bit), 8 for co64 (64-bit).
    """
    stco_count = int.from_bytes(data[stco_off+12:stco_off+16], 'big')
    offsets = []
    for i in range(stco_count):
        off = stco_off + 16 + i * entry_size
        offsets.append(int.from_bytes(data[off:off+entry_size], 'big'))

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

def inflate_sample_table_video(data, multiplier=10, filler_type='nal'):
    """Inflation — add fake frames to prevent TikTok re-encode.
    filler_type='nal': append H.264 filler NALs (512 bytes, fake_delta=750).
    filler_type='lastcopy': append copies of last real frame data (valid picture, fake_delta=750).
    filler_type='zero': zero-size frames, fake_delta=1.
    Container durations clipped to real frames only.
    """
    moov_off, moov_sz = _find_box(data, b"moov")
    if moov_off == -1:
        return None

    mdat_off, mdat_sz = _find_box(data, b"mdat")
    if mdat_off == -1:
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
    if stco_off == -1:
        stco_off, stco_sz = _find_box(data, b"co64", stbl_off+8, stbl_end)
        co_entry_size = 8
    else:
        co_entry_size = 4
    stsc_off, stsc_sz = _find_box(data, b"stsc", stbl_off+8, stbl_end)

    if -1 in (stts_off, stsz_off, stco_off, stsc_off):
        return None

    try:
        stts_entry_count = int.from_bytes(data[stts_off+12:stts_off+16], 'big')
        real_count = 0
        orig_total_dur_ticks = 0
        orig_last_delta = 0
        for i in range(stts_entry_count):
            off = stts_off + 16 + i * 8
            cnt = int.from_bytes(data[off:off+4], 'big')
            d = int.from_bytes(data[off+4:off+8], 'big')
            real_count += cnt
            orig_total_dur_ticks += cnt * d
            orig_last_delta = d

        if real_count == 0:
            return None

        total_count = min(int(real_count * multiplier), 0xFFFFFFFF)
        fake_count = total_count - real_count

        real_offsets = _sample_offsets(data, stco_off, stsc_off, stsz_off, real_count, co_entry_size)
        if not real_offsets:
            return None

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

        if filler_type == 'lastcopy':
            last_sz = real_sizes[-1]
            last_off = real_offsets[-1]
            last_frame_data = data[last_off:last_off + last_sz]
            filler_data = last_frame_data * fake_count
            fake_sz = last_sz
            fake_delta = 750
            mdat_extension = len(filler_data)
            fill_off = mdat_off + mdat_sz
        elif filler_type == 'nal':
            FILLER_NAL_SZ = 512
            nal_body_len = FILLER_NAL_SZ - 4
            fake_frame = struct.pack('>I', nal_body_len) + b'\x0c' + b'\x00' * (nal_body_len - 1)
            filler_data = fake_frame * fake_count
            fake_sz = FILLER_NAL_SZ
            fake_delta = 750
            mdat_extension = len(filler_data)
            fill_off = mdat_off + mdat_sz
        else:
            filler_data = b''
            fake_sz = 0
            fake_delta = 1
            mdat_extension = 0
            fill_off = 0

        fake_dur_ticks = fake_count * fake_delta

        new_stts_body = struct.pack('>II', 0, 2)
        new_stts_body += struct.pack('>II', real_count, orig_last_delta)
        new_stts_body += struct.pack('>II', fake_count, fake_delta)
        new_stts = struct.pack('>I4s', 8 + len(new_stts_body), b'stts') + new_stts_body

        new_stsz_body = bytearray(20 + total_count * 4)
        struct.pack_into('>III', new_stsz_body, 0, 0, 0, total_count)
        for i in range(real_count):
            struct.pack_into('>I', new_stsz_body, 12 + i * 4, real_sizes[i])
        for i in range(fake_count):
            struct.pack_into('>I', new_stsz_body, 12 + (real_count + i) * 4, fake_sz)
        new_stsz = struct.pack('>I4s', 8 + len(new_stsz_body), b'stsz') + bytes(new_stsz_body)

        new_stsc_body = struct.pack('>II', 0, 1)
        new_stsc_body += struct.pack('>III', 1, 1, 1)
        new_stsc = struct.pack('>I4s', 8 + len(new_stsc_body), b'stsc') + bytes(new_stsc_body)

        new_stco_body2 = bytearray(8 + total_count * 4)
        struct.pack_into('>II', new_stco_body2, 0, 0, total_count)
        for i in range(real_count):
            struct.pack_into('>I', new_stco_body2, 8 + i * 4, real_offsets[i])
        for i in range(fake_count):
            off = fill_off + i * fake_sz
            struct.pack_into('>I', new_stco_body2, 8 + (real_count + i) * 4, off)
        new_stco2 = struct.pack('>I4s', 8 + len(new_stco_body2), b'stco') + bytes(new_stco_body2)

        replacements = [
            (stts_off, stts_sz, new_stts),
            (stsz_off, stsz_sz, new_stsz),
            (stsc_off, stsc_sz, new_stsc),
            (stco_off, stco_sz, new_stco2),
        ]
        replacements.sort(key=lambda x: x[0])

        moov_delta = sum(len(new) - old_sz for _, old_sz, new in replacements)

        result = bytearray(len(data) + moov_delta + mdat_extension)
        read_pos = 0
        write_pos = 0
        for off, old_sz, new_bytes in replacements:
            result[write_pos:write_pos + off - read_pos] = data[read_pos:off]
            write_pos += off - read_pos
            result[write_pos:write_pos + len(new_bytes)] = new_bytes
            write_pos += len(new_bytes)
            read_pos = off + old_sz
        rest_len = len(data) - read_pos
        result[write_pos:write_pos + rest_len] = data[read_pos:read_pos + rest_len]
        write_pos += rest_len

        if filler_data:
            result[write_pos:write_pos + len(filler_data)] = filler_data
            write_pos += len(filler_data)
            new_mdat_sz = mdat_sz + len(filler_data)
            mdat_offset_adjusted = mdat_off + moov_delta
            struct.pack_into('>I', result, mdat_offset_adjusted, new_mdat_sz)

        for container_off in (stbl_off, minf_off, mdia_off, trak_off, moov_off):
            old_sz = int.from_bytes(result[container_off:container_off+4], 'big')
            new_sz = max(old_sz + moov_delta, 8)
            if new_sz > 0xFFFFFFFF:
                new_sz = 0xFFFFFFFF
            struct.pack_into('>I', result, container_off, new_sz)

        new_moov_end = moov_off + moov_sz + moov_delta
        _adjust_stco(result, moov_delta, moov_off+8, new_moov_end)

        real_dur_sec = orig_total_dur_ticks / video_timescale

        mvhd_off, _ = _find_box(result, b"mvhd", moov_off+8, moov_off+moov_sz+moov_delta)
        if mvhd_off != -1:
            ver = result[mvhd_off+8]
            if ver == 0:
                mvhd_ts = int.from_bytes(result[mvhd_off+20:mvhd_off+24], 'big')
                mvhd_dur = min(int(real_dur_sec * mvhd_ts), 0xFFFFFFFF)
                result[mvhd_off+24:mvhd_off+28] = struct.pack('>I', mvhd_dur)
                mvhd_ts_used = mvhd_ts
            else:
                mvhd_ts = int.from_bytes(result[mvhd_off+28:mvhd_off+32], 'big')
                mvhd_dur = int(real_dur_sec * mvhd_ts)
                result[mvhd_off+32:mvhd_off+40] = struct.pack('>Q', mvhd_dur)
                mvhd_ts_used = mvhd_ts

        trak_dur = min(int(real_dur_sec * mvhd_ts_used), 0xFFFFFFFF)
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
                        mdhd_dur = min(int(real_dur_sec * mdhd_ts), 0xFFFFFFFF)
                        result[mdhd_off+24:mdhd_off+28] = struct.pack('>I', mdhd_dur)
                    else:
                        mdhd_ts = int.from_bytes(result[mdhd_off+28:mdhd_off+32], 'big')
                        mdhd_dur = int(real_dur_sec * mdhd_ts)
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
    mdat_off, _ = _find_box(result, b"mdat")
    if moov_off < mdat_off:
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
    # Major brand -> M4VH, overwrite last compat brand with isom
    result[ftyp_off+8:ftyp_off+12] = b'M4VH'
    result[ftyp_off+ftyp_sz-4:ftyp_off+ftyp_sz] = b'isom'
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


# ── Timescale spoofing (120fps-method) ──────────────────────────────

def find_mvhd_timescale(data):
    """Return (off, ver, ts_off, dur_off, ts, dur) or None."""
    moov_off, moov_sz = _find_box(data, b"moov")
    if moov_off == -1:
        return None
    mvhd_off, _ = _find_box(data, b"mvhd", moov_off+8, moov_off+moov_sz)
    if mvhd_off == -1:
        return None
    ver = data[mvhd_off+8]
    if ver == 0:
        return (mvhd_off, ver, mvhd_off+20, mvhd_off+24,
                int.from_bytes(data[mvhd_off+20:mvhd_off+24], 'big'),
                int.from_bytes(data[mvhd_off+24:mvhd_off+28], 'big'))
    return (mvhd_off, ver, mvhd_off+28, mvhd_off+32,
            int.from_bytes(data[mvhd_off+28:mvhd_off+32], 'big'),
            int.from_bytes(data[mvhd_off+32:mvhd_off+40], 'big'))


def find_video_mdhd_timescale(data):
    """Return (off, ver, ts_off, dur_off, ts, dur) for video mdhd or None."""
    moov_off, moov_sz = _find_box(data, b"moov")
    if moov_off == -1:
        return None
    for trak_off, trak_sz, _ in _iter_boxes(data, moov_off+8, moov_off+moov_sz):
        mdia_off, mdia_sz = _find_box(data, b"mdia", trak_off+8, trak_off+trak_sz)
        if mdia_off == -1:
            continue
        hdlr_off, _ = _find_box(data, b"hdlr", mdia_off+8, mdia_off+mdia_sz)
        if hdlr_off == -1 or data[hdlr_off+16:hdlr_off+20] != b'vide':
            continue
        mdhd_off, _ = _find_box(data, b"mdhd", mdia_off+8, mdia_off+mdia_sz)
        if mdhd_off == -1:
            return None
        ver = data[mdhd_off+8]
        if ver == 0:
            return (mdhd_off, ver, mdhd_off+20, mdhd_off+24,
                    int.from_bytes(data[mdhd_off+20:mdhd_off+24], 'big'),
                    int.from_bytes(data[mdhd_off+24:mdhd_off+28], 'big'))
        return (mdhd_off, ver, mdhd_off+28, mdhd_off+32,
                int.from_bytes(data[mdhd_off+28:mdhd_off+32], 'big'),
                int.from_bytes(data[mdhd_off+32:mdhd_off+40], 'big'))
    return None


def patch_timescale_multiplier(data, multiplier=2):
    """Divide mvhd, video mdhd timescale+duration, and tkhd durations by multiplier.
    Tricks TikTok into seeing lower frame rate, preventing re-encode.
    No data added — no freeze, no stuck.
    Note: stts delta values are NOT adjusted, creating a timescale/delta inconsistency.
    The elst with media_rate=multiplier compensates, but some parsers may misbehave.
    """
    moov_off, moov_sz = _find_box(data, b"moov")
    if moov_off == -1:
        return data

    p = bytearray(data)

    mvhd_info = find_mvhd_timescale(bytes(p))
    if mvhd_info is not None:
        _, ver, ts_off, dur_off, old_ts, old_dur = mvhd_info
        new_ts = max(old_ts // multiplier, 1)
        new_dur = old_dur // multiplier
        struct.pack_into('>I', p, ts_off, new_ts)
        if ver == 0:
            struct.pack_into('>I', p, dur_off, new_dur)
        else:
            struct.pack_into('>Q', p, dur_off, new_dur)

    mdhd_info = find_video_mdhd_timescale(bytes(p))
    if mdhd_info is not None:
        _, ver, ts_off, dur_off, old_ts, old_dur = mdhd_info
        new_ts = max(old_ts // multiplier, 1)
        new_dur = old_dur // multiplier
        struct.pack_into('>I', p, ts_off, new_ts)
        if ver == 0:
            struct.pack_into('>I', p, dur_off, new_dur)
        else:
            struct.pack_into('>Q', p, dur_off, new_dur)

    # Divide tkhd duration by multiplier for all tracks
    for trak_off, trak_sz, _ in _iter_boxes(p, moov_off+8, moov_off+moov_sz):
        tkhd_off, _ = _find_box(p, b"tkhd", trak_off+8, trak_off+trak_sz)
        if tkhd_off != -1:
            ver = p[tkhd_off+8]
            if ver == 0:
                old_dur = int.from_bytes(p[tkhd_off+28:tkhd_off+32], 'big')
                new_dur = old_dur // multiplier
                struct.pack_into('>I', p, tkhd_off+28, new_dur)
            else:
                old_dur = int.from_bytes(p[tkhd_off+36:tkhd_off+44], 'big')
                new_dur = old_dur // multiplier
                struct.pack_into('>Q', p, tkhd_off+36, new_dur)

    return bytes(p)


def add_balanced_sync_elst(data, multiplier=2):
    """Add edit list to video tracks with media_rate = multiplier (Balanced Sync).
    Ensures players play the video at multiplier speed, compensating for the divided timescale.
    """
    moov_off, moov_sz = _find_box(data, b"moov")
    if moov_off == -1:
        return data

    mvhd_info = find_mvhd_timescale(data)
    if mvhd_info is None:
        return data
    _, _, _, _, mvhd_ts, mvhd_dur = mvhd_info

    p = bytearray(data)
    moov_end = moov_off + moov_sz

    for trak_off, trak_sz, _ in _iter_boxes(p, moov_off+8, moov_off+moov_sz):
        mdia_off, mdia_sz = _find_box(p, b"mdia", trak_off+8, trak_off+trak_sz)
        if mdia_off == -1:
            continue
        hdlr_off, _ = _find_box(p, b"hdlr", mdia_off+8, mdia_off+mdia_sz)
        if hdlr_off == -1 or p[hdlr_off+16:hdlr_off+20] != b'vide':
            continue

        # Segment duration in movie timescale
        dur_ticks = mvhd_dur

        if dur_ticks <= 0:
            continue

        elst_ver = 1 if dur_ticks > 0xFFFFFFFF else 0
        elst_entry_sz = 20 if elst_ver == 1 else 12
        elst_size = 16 + elst_entry_sz  # header(8+8) + 1 entry
        edts_size = 8 + elst_size

        elst_body = bytearray(elst_size)
        elst_body[0:4] = struct.pack('>I', elst_size)
        elst_body[4:8] = b'elst'
        elst_body[8] = elst_ver
        elst_body[9:12] = b'\x00\x00\x00'
        elst_body[12:16] = struct.pack('>I', 1)
        if elst_ver == 1:
            struct.pack_into('>Q', elst_body, 16, dur_ticks)
            struct.pack_into('>q', elst_body, 24, 0)
            struct.pack_into('>h', elst_body, 32, multiplier)
            struct.pack_into('>h', elst_body, 34, 0)
        else:
            struct.pack_into('>I', elst_body, 16, dur_ticks)
            struct.pack_into('>i', elst_body, 20, 0)
            struct.pack_into('>h', elst_body, 24, multiplier)
            struct.pack_into('>h', elst_body, 26, 0)

        edts_bytes = struct.pack('>I4s', edts_size, b'edts') + bytes(elst_body)
        delta = len(edts_bytes)

        # Check if trak already has edts
        edts_off, edts_sz = _find_box(p, b"edts", trak_off+8, trak_off+trak_sz)
        if edts_off != -1:
            old_edts = p[edts_off:edts_off+edts_sz]
            if old_edts == edts_bytes:
                continue
            delta = delta - edts_sz
            if delta == 0:
                p[edts_off:edts_off+edts_sz] = edts_bytes
                continue
            new_data = bytearray(len(p) + delta)
            new_data[:edts_off] = p[:edts_off]
            new_data[edts_off:edts_off+len(edts_bytes)] = edts_bytes
            new_data[edts_off+len(edts_bytes):] = p[edts_off+edts_sz:]
            p = new_data
        else:
            # Insert edts at beginning of trak (right after trak header)
            new_data = bytearray(len(p) + delta)
            insert_pos = trak_off + 8
            new_data[:insert_pos] = p[:insert_pos]
            new_data[insert_pos:insert_pos+delta] = edts_bytes
            new_data[insert_pos+delta:] = p[insert_pos:]
            p = new_data

        # Update container sizes
        struct.pack_into('>I', p, trak_off, trak_sz + delta)
        old_moov_sz = int.from_bytes(p[moov_off:moov_off+4], 'big')
        struct.pack_into('>I', p, moov_off, old_moov_sz + delta)
        _adjust_stco(p, delta, moov_off+8, moov_off+8+old_moov_sz+delta)
        moov_end = moov_off + old_moov_sz + delta

    return bytes(p)


# ── Main 7-Pass Pipeline ──────────────────────────────────────────────

def patch_all(input_path, output_path, comment=None, log_func=None, method='balanced-sync', use_inflation=None):
    """8-pass pipeline. Inflation runs last (Pass 8) so all other modifications
    (codec spoofing, fingerprinting, comment, audio restore) are applied first."""
    if use_inflation is not None:
        if use_inflation:
            method = 'inflate'
        else:
            method = 'codec-spoof'

    if log_func:
        log_func(f"[JOB] starting pipeline (method: {method})")

    input_path = Path(input_path)
    output_path = Path(output_path)
    stem = input_path.stem
    suffix = input_path.suffix

    # Normalize — always inject '@akila' as comment unless user provides a custom one
    if comment is None or comment == "@akila":
        final_comment = "@akila"
    else:
        final_comment = comment

    original_data = input_path.read_bytes()

    valid, msg = validate_mp4(original_data)
    if not valid:
        if log_func:
            log_func(f"[ERROR] MP4 validation failed: {msg}")
        return False
    if log_func:
        log_func(f"[VALIDATE] MP4 structure: {msg}")

    original_audio_dur = read_audio_duration(original_data)
    if log_func and original_audio_dur is not None:
        log_func(f"[AUDIO] original duration={original_audio_dur}")

    # ── Pass 1: Move moov to front (pure Python, preserves all metadata) ──
    if log_func:
        log_func("")
        log_func("── 1/8  Python reloov (moov to front) ─────────────────────")
    data = bytearray(original_data)
    ftyp_off, ftyp_sz = _find_box(data, b"ftyp")
    moov_off, moov_sz = _find_box(data, b"moov")
    mdat_off, mdat_sz = _find_box(data, b"mdat")
    if ftyp_off == -1 or moov_off == -1 or mdat_off == -1:
        if log_func:
            log_func("[ERROR] missing ftyp, moov, or mdat")
        return False
    # Build: ftyp + moov + all other boxes (free, etc.) in original order
    rest = bytearray()
    pos = 0
    while pos + 8 <= len(data):
        sz = int.from_bytes(data[pos:pos+4], 'big')
        hdr = 8
        if sz == 1:
            if pos + 16 > len(data):
                break
            sz = int.from_bytes(data[pos+8:pos+16], 'big')
            hdr = 16
        elif sz == 0:
            sz = len(data) - pos
        if sz < hdr:
            break
        btype = data[pos+4:pos+8]
        if btype not in (b'ftyp', b'moov'):
            rest.extend(data[pos:pos+sz])
        pos += sz
    new_ftyp = data[ftyp_off:ftyp_off+ftyp_sz]
    new_moov = data[moov_off:moov_off+moov_sz]
    result = bytearray(new_ftyp + new_moov + rest)
    # Adjust stco entries by moov position delta
    orig_mdat_data = mdat_off + 8
    new_mdat_data = ftyp_sz + moov_sz + 8  # after ftyp, moov, and free's 8-byte header
    # Actually mdat is the next box in 'rest', so new_mdat_data = ftyp_sz + moov_sz + (rest starts)
    # rest starts at ftyp_sz + moov_sz, and the first box in rest is the free box (8 bytes) or mdat itself
    # Let's recalculate: mdat data starts at ftyp_sz + moov_sz + (mdat offset within rest)
    # Simpler: find mdat position in result
    new_mdat_off = result.find(b'mdat') - 4
    new_mdat_data = new_mdat_off + 8
    delta = new_mdat_data - orig_mdat_data
    _adjust_stco(result, delta, ftyp_sz + 8, ftyp_sz + 8 + moov_sz)
    data = bytes(result)
    if log_func:
        log_func(f"[RELOOV] {len(data):,} bytes, stco delta={delta}")
        _dump_atoms(data, "RELOOV", log_func)



    # ── Pass 2: mvhd Fingerprint ────────────────────────────────────────
    if log_func:
        log_func("")
        log_func("── 2/8  mvhd Fingerprint (next_track_id=9999, fixed date) ──")
    data = patch_mvhd_fingerprint(data)
    if log_func:
        log_func("[MVHD] done")

    # ── Pass 3: Udta Strip (remove ffmpeg encoder tag) ──────────────────
    if log_func:
        log_func("")
        log_func("── 3/8  Udta Strip ─────────────────────────────────────────")
    data = strip_udta(data)
    if log_func:
        log_func("[UDTA] done")

    # ── Pass 4: tkhd Fingerprint ────────────────────────────────────────
    if log_func:
        log_func("")
        log_func("── 4/8  tkhd Fingerprint (alternate_group) ────────────────")
    data = fingerprint_tkhd(data)
    if log_func:
        log_func("[TKHD] done")

    # ── Pass 5: Codec Spoofing (for all methods) ─────────────────────────
    if log_func:
        log_func("")
        log_func("── 5/8  Codec Spoofing (avc1→avc3, M4VH brand) ───────────────")
    data = patch_stsd_codec(data)
    data = patch_ftyp(data)
    if log_func:
        log_func("[CODEC] done")

    # ── Pass 6: Comment Udta Injection ──────────────────────────────────
    if log_func:
        log_func("")
        log_func("── 6/8  Comment Udta Injection ────────────────────────────")
    data = inject_comment_udta(data, final_comment)
    if log_func:
        log_func(f"[COMMENT] injected ({final_comment!r})")

    # ── Pass 7: Restore original audio duration ─────────────────────────
    if log_func:
        log_func("")
        log_func("── 7/8  Audio Duration Restore ────────────────────────────")
    data = patch_audio_duration(data, original_audio_dur)
    if log_func:
        log_func("[AUDIO] done")

    # ── Pass 8: Bypass Method (Inflation / Balanced Sync) ───────────────
    # Inflation runs LAST so all other modifications (fingerprinting, codec
    # spoof, comment, audio restore) are applied first.
    if method == 'inflate':
        if log_func:
            log_func("")
            log_func("── 8/8  Frame Count Inflation (10x) ────────────────────────────────")
        inflated = inflate_sample_table_video(data, multiplier=10)
        if inflated is None:
            if log_func:
                log_func("[ERROR] Frame inflation failed")
            return False
        data = inflated
        if log_func:
            log_func("[INFLATE] done")
    elif method == 'balanced-sync':
        if log_func:
            log_func("")
            log_func("── 8/8  Balanced Sync (Timescale Division + Playback Speed elst) ────────────")
        data = patch_timescale_multiplier(data, multiplier=2)
        data = add_balanced_sync_elst(data, multiplier=2)
        if log_func:
            log_func("[BALANCED-SYNC] done")

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

    if log_func:
        log_func(f"[DONE]  {output_path.name}")
    return True


TIKQUICK_ENCODE_ARGS = [
    "-vf", "fps=10000,scale=1920:1080,setdar=9/16,setparams=color_primaries=bt2020:color_trc=arib-std-b67:colorspace=bt2020nc",
    "-c:v", "libx264", "-preset", "slow", "-crf", "18",
    "-maxrate", "40M", "-bufsize", "40M",
    "-pix_fmt", "yuv420p",
    "-profile:v", "high", "-level", "4.2",
    "-c:a", "aac", "-b:a", "192k", "-ar", "48000",
    "-metadata", 'encoder=TikQuick Quality Method - https://tikquick.online/',
    "-metadata:s:v:0", 'encoder=TikQuick Quality Method - https://tikquick.online/',
    "-metadata:s:a:0", 'encoder=TikQuick Quality Method - https://tikquick.online/',
    "-movflags", "+faststart",
]


def tikquick_encode(input_path, output_path, extra_args=None, log_func=None):
    """Re-encode a patched MP4 with TikQuick-quality ffmpeg settings."""
    import subprocess
    cmd = ["ffmpeg", "-i", str(input_path)]
    if extra_args:
        cmd.extend(extra_args)
    else:
        cmd.extend(TIKQUICK_ENCODE_ARGS)
    cmd.append(str(output_path))
    if log_func:
        log_func(f"[ENCODE] {' '.join(cmd)}")
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
        if r.returncode != 0:
            if log_func:
                log_func(f"[ENCODE ERROR] {r.stderr[-500:]}")
            return False
        if log_func:
            log_func(f"[ENCODE] done  ({output_path.stat().st_size:,} bytes)")
        return True
    except FileNotFoundError:
        if log_func:
            log_func("[ENCODE ERROR] ffmpeg not found on PATH")
        return False
