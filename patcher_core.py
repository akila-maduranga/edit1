#!/usr/bin/env python3
"""
Core patching engine — original working approach (inject_fake_frames style).
"""

import struct
import subprocess
import time
import random
from pathlib import Path


_SCRIPT_DIR = Path(__file__).parent


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


def _find_in_container(data, box_type, container_off, container_sz):
    end = container_off + container_sz
    i = container_off + 8
    while i + 8 <= end:
        sz = int.from_bytes(data[i:i+4], 'big')
        bt = data[i+4:i+8]
        if sz == 0:
            sz = end - i
        if sz < 8:
            break
        if bt == box_type:
            return i, sz
        i += sz
    return -1, 0


def patch_timestamps(data):
    p = bytearray(data)
    for box_type in (b'mvhd', b'tkhd', b'mdhd'):
        off, sz = _find_in_container(p, box_type, 0, len(p))
        if off == -1:
            continue
        version = p[off+8]
        if version == 0:
            ct_off = off + 12
            if ct_off + 8 <= len(p):
                p[ct_off:ct_off+8] = b'\x00' * 8
        else:
            ct_off = off + 20
            if ct_off + 16 <= len(p):
                p[ct_off:ct_off+16] = b'\x00' * 16
    return bytes(p)


def patch_language(data):
    p = bytearray(data)
    off, sz = _find_in_container(p, b'mdhd', 0, len(p))
    if off != -1:
        version = p[off+8]
        lang_off = off + (28 if version == 0 else 36)
        if lang_off + 2 <= len(p):
            p[lang_off:lang_off+2] = b'\x55\xC4'
    return bytes(p)


# ── Frame inflation (old approach: 0-byte dummies + stts overflow) ──

def inflate_frames_old(data, multiplier=10):
    """Inject zero-size dummy frames + stts entry count overflow."""
    moov_off, moov_sz = _find_in_container(data, b'moov', 0, len(data))
    if moov_off == -1:
        return None

    # Find video stbl
    video_stbl_off = None
    pos = moov_off + 8
    moov_end = moov_off + moov_sz
    while pos + 8 <= moov_end:
        trak_sz = int.from_bytes(data[pos:pos+4], 'big')
        if data[pos+4:pos+8] != b'trak':
            pos += trak_sz
            continue
        mdia_off, mdia_sz = _find_in_container(data, b'mdia', pos, trak_sz)
        if mdia_off == -1:
            pos += trak_sz; continue
        hdlr_off, _ = _find_in_container(data, b'hdlr', mdia_off, mdia_sz)
        if hdlr_off == -1:
            pos += trak_sz; continue
        if data[hdlr_off+16:hdlr_off+20] != b'vide':
            pos += trak_sz; continue
        minf_off, minf_sz = _find_in_container(data, b'minf', mdia_off, mdia_sz)
        if minf_off == -1:
            pos += trak_sz; continue
        video_stbl_off, video_stbl_sz = _find_in_container(data, b'stbl', minf_off, minf_sz)
        if video_stbl_off != -1:
            break
        pos += trak_sz

    if video_stbl_off is None:
        return None

    stbl_off, stbl_sz = video_stbl_off, video_stbl_sz
    stbl_end = stbl_off + stbl_sz
    stsz_off, stsz_sz = _find_in_container(data, b'stsz', stbl_off, stbl_sz)
    stts_off, stts_sz = _find_in_container(data, b'stts', stbl_off, stbl_sz)
    if stsz_off == -1 or stts_off == -1:
        return None

    stsz_sample_count = int.from_bytes(data[stsz_off+16:stsz_off+20], 'big')
    uniform_size = int.from_bytes(data[stsz_off+12:stsz_off+16], 'big')
    total_frames = stsz_sample_count * multiplier
    diff = total_frames - stsz_sample_count

    result = bytearray(data)

    # Update STSZ: set sample_count + add zero-size entries
    old_stsz_data_len = stsz_sz - 8
    new_stsz_data = bytearray(data[stsz_off+8:stsz_off+stsz_sz])
    new_stsz_data[8:12] = total_frames.to_bytes(4, 'big')
    new_stsz_data += b'\x00\x00\x00\x00' * diff  # zero-size dummy entries
    growth = len(new_stsz_data) - old_stsz_data_len
    result[stsz_off+8:stsz_off+8+old_stsz_data_len] = new_stsz_data

    # Update STTS: add entry count overflow (each dummy = separate stts entry)
    old_stts_data_len = stts_sz - 8
    stts_data = bytearray(data[stts_off+8:stts_off+stts_sz])
    entry_count = int.from_bytes(stts_data[8:12], 'big')
    stts_data[8:12] = (entry_count + diff).to_bytes(4, 'big')
    result[stts_off+8:stts_off+8+old_stts_data_len] = bytes(stts_data)

    # Update container sizes
    for parent_off in (stbl_off, minf_off, mdia_off, pos, moov_off):
        old_sz = int.from_bytes(result[parent_off:parent_off+4], 'big')
        struct.pack_into('>I', result, parent_off, old_sz + growth)

    new_moov_sz = moov_sz + growth
    _adjust_stco(result, growth, moov_off+8, moov_off+8+new_moov_sz)

    return bytes(result)


# ── Metadata builder ────────────────────────────────────────────────

def build_metadata(comment):
    entries = {}
    if comment:
        entries[b'\xa9cmt'] = comment

    # Build direct udta children (TikTok reads these)
    udta_data = b''
    for tag_key, value in entries.items():
        value_bytes = value.encode('utf-8')
        tag_box = struct.pack('>I4s', 8 + len(value_bytes), tag_key) + value_bytes
        udta_data += tag_box

    # Build meta box: handler=mdir vendor=appl, empty ilst
    hdlr = struct.pack('>I4sI', 41, b'hdlr', 0)
    hdlr += struct.pack('>I4s', 0, b'mdir')
    hdlr += b'appl' + struct.pack('>II', 0, 0)
    hdlr += b'Metadata\x00'
    ilst = struct.pack('>I4s', 8, b'ilst')
    meta_content = b'\x00\x00\x00\x00' + hdlr + ilst
    meta = struct.pack('>I4s', 8 + len(meta_content), b'meta') + meta_content
    udta_data += meta
    return struct.pack('>I4s', 8 + len(udta_data), b'udta') + udta_data


# ── Main pipeline ───────────────────────────────────────────────────

def patch_all(input_path, output_path, comment=None, log_func=None):
    if log_func:
        log_func("[JOB] starting patch pipeline")

    input_path = Path(input_path)
    output_path = Path(output_path)
    stem = input_path.stem
    suffix = input_path.suffix

    if comment is None:
        ts = int(time.time())
        tag = f"{ts}_{random.randint(0, 0xFFFFFFFF):08x}"
        comment = f"Patched by method.akila - {tag}"

    # ── Step 1: FFmpeg remux (Faststart) ────────────────────────────────
    if log_func:
        log_func("")
        log_func("── 1/5  FFmpeg remux (Faststart) ──────────────────────────")
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

    data = bytearray(clean.read_bytes())
    if log_func:
        log_func(f"[READ] {len(data):,} bytes")

    # ── Step 2: Frame inflation (10x, zero-size dummies, stts overflow) ─
    if log_func:
        log_func("")
        log_func("── 2/5  Frame Inflation (10x) ──────────────────────────────")
    inflated = inflate_frames_old(data, multiplier=10)
    if inflated is None:
        if log_func:
            log_func("[ERROR] Frame inflation failed")
        try: clean.unlink(missing_ok=True)
        except: pass
        return False
    data = bytearray(inflated)
    if log_func:
        log_func("[INFLATE] done")

    # ── Step 3: Date zeroing + language spoof ────────────────────────────
    if log_func:
        log_func("")
        log_func("── 3/5  Date Zeroing + Language Spoof ────────────────────")
    data = bytearray(patch_timestamps(data))
    data = bytearray(patch_language(data))
    if log_func:
        log_func("[DATE/LANG] done")

    # ── Step 4: Metadata injection ───────────────────────────────────────
    if log_func:
        log_func("")
        log_func("── 4/5  Metadata Injection ────────────────────────────────")
    # Remove old udta
    moov_off = data.find(b'moov') - 4
    moov_sz = int.from_bytes(data[moov_off:moov_off+4], 'big')
    moov_end = moov_off + moov_sz
    udta_removed = 0
    pos = moov_off + 8
    while pos + 8 <= moov_end:
        atom_sz = int.from_bytes(data[pos:pos+4], 'big')
        if atom_sz < 8:
            break
        if data[pos+4:pos+8] == b'udta':
            del data[pos:pos + atom_sz]
            udta_removed = atom_sz
            moov_sz -= udta_removed
            moov_end -= udta_removed
            break
        pos += atom_sz

    # Inject new metadata
    md = build_metadata(comment)
    data[moov_end:moov_end] = md
    new_moov_sz = moov_sz + len(md)
    struct.pack_into('>I', data, moov_off, new_moov_sz)
    net_shift = len(md) - udta_removed
    if net_shift != 0:
        _adjust_stco(data, net_shift, moov_off, moov_off + new_moov_sz)
    if log_func:
        log_func(f"[META] injected {len(md)} bytes (udta_removed={udta_removed})")

    # ── Step 5: Free atom (target offset 237436) + xxxx trailer ────────────
    if log_func:
        log_func("")
        log_func("── 5/5  Free Padding + Trailer ────────────────────────────")

    # First, insert free(8) after ftyp
    ftyp_sz = int.from_bytes(data[0:4], 'big')
    if data[ftyp_sz:ftyp_sz+8] != b'\x00\x00\x00\x08free':
        data[ftyp_sz:ftyp_sz] = b'\x00\x00\x00\x08free'
        _adjust_stco(data, 8, moov_off + 8, moov_off + 8 + new_moov_sz)
        moov_off += 8
        if log_func:
            log_func("[FREE] inserted free(8) after ftyp")

    # Expand free to hit target offset
    target_offset = 237436
    ftyp_sz = int.from_bytes(data[0:4], 'big')
    moov_off = data.find(b'moov') - 4
    moov_sz = int.from_bytes(data[moov_off:moov_off+4], 'big')

    # Remove free between moov and mdat if present
    moov_end = moov_off + moov_sz
    ffmpeg_free = 0
    if data[moov_end:moov_end+8] == b'\x00\x00\x00\x08free':
        del data[moov_end:moov_end+8]
        ffmpeg_free = 8

    need = target_offset - 40 - moov_sz
    if need >= 8:
        new_free = struct.pack('>I4s', need, b'free') + b'\x00' * (need - 8)
        data[ftyp_sz:ftyp_sz+8] = new_free
        shift = need - 8
        moov_off += shift
        stco_delta = shift - ffmpeg_free
        _adjust_stco(data, stco_delta, moov_off + 8, moov_off + 8 + moov_sz)
        if log_func:
            log_func(f"[FREE] free {need} bytes, stco_delta={stco_delta:+d}")
    else:
        if log_func:
            log_func(f"[FREE] skip (need={need} < 8)")

    # xxxx fake trailer
    data += b'\x00\x00\x00\x04xxxx'
    if log_func:
        log_func("[TRAILER] xxxx appended")

    if log_func:
        log_func("")
        log_func("── Atom layout ────────────────────────────────────────────────")
        md_pos = data.find(b'mdat')
        mv_pos = data.find(b'moov')
        log_func(f"[VERIFY] mdat at {md_pos}, moov at {mv_pos}, front: {'YES' if mv_pos < md_pos else 'NO'}")
        log_func(f"[VERIFY] file size: {len(data):,} bytes")

    output_path.write_bytes(data)
    if log_func:
        log_func(f"[WRITE] {output_path.name}  ({len(data):,} bytes)")

    try: clean.unlink(missing_ok=True)
    except: pass

    if log_func:
        log_func(f"[DONE]  {output_path.name}")
    return True
