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


def find_atoms_of_type(atoms, box_type):
    found = []
    for atom in atoms:
        if atom['name'] == box_type:
            found.append(atom)
        if 'children' in atom:
            found.extend(find_atoms_of_type(atom['children'], box_type))
    return found


def patch_timestamps(data):
    p = bytearray(data)
    moov_pos = data.find(b'moov')
    if moov_pos >= 4:
        moov_size = int.from_bytes(data[moov_pos-4:moov_pos], 'big')
        tree, _ = read_atoms_in_range(data, moov_pos + 4, moov_pos + moov_size)
        for box_type in (b'mvhd', b'tkhd', b'mdhd'):
            for atom in find_atoms_of_type(tree, box_type):
                off = atom['start']
                version = p[off + 8]
                if version == 0:
                    p[off+12:off+20] = b'\x00' * 8
                else:
                    p[off+20:off+36] = b'\x00' * 16
    return bytes(p)


def patch_language(data):
    p = bytearray(data)
    moov_pos = data.find(b'moov')
    if moov_pos >= 4:
        moov_size = int.from_bytes(data[moov_pos-4:moov_pos], 'big')
        tree, _ = read_atoms_in_range(data, moov_pos + 4, moov_pos + moov_size)
        for atom in find_atoms_of_type(tree, b'mdhd'):
            off = atom['start']
            version = p[off + 8]
            lang_off = off + (28 if version == 0 else 36)
            if lang_off + 2 <= off + atom['size']:
                p[lang_off:lang_off+2] = b'\x55\xC4'
    return bytes(p)


# ── Tree-based box parsing (shared with patcher.py) ─────────────────

def read_atoms_in_range(data, offset, end_pos):
    atoms = []
    while offset + 8 <= end_pos and offset + 8 <= len(data):
        size = int.from_bytes(data[offset:offset+4], 'big')
        if size == 0:
            break
        if size == 1:
            size = int.from_bytes(data[offset+8:offset+16], 'big')
            header_size = 16
        else:
            header_size = 8
        atom_end = offset + size
        if atom_end > end_pos:
            atom_end = end_pos
        name = data[offset+4:offset+8]
        CONTAINERS = [b'moov', b'trak', b'mdia', b'minf', b'stbl']
        if name in CONTAINERS:
            children, _ = read_atoms_in_range(data, offset + header_size, atom_end)
            atoms.append({'name': name, 'children': children, 'start': offset, 'size': size})
        else:
            atoms.append({'name': name, 'data': bytes(data[offset+header_size:atom_end]),
                          'start': offset, 'size': size})
        offset = atom_end
    return atoms, offset


def find_atom(atoms, path):
    if not path:
        return atoms
    for atom in atoms:
        if atom['name'] == path[0]:
            if len(path) == 1:
                return atom
            if 'children' in atom:
                res = find_atom(atom['children'], path[1:])
                if res:
                    return res
    return None


# ── Frame inflation (old approach: 0-byte dummies + stts overflow) ──

def inflate_frames_old(data, multiplier=10):
    """Inject zero-size dummy frames + stts entry count overflow."""
    moov_pos = data.find(b'moov')
    if moov_pos < 4:
        return None
    moov_size_pos = moov_pos - 4
    moov_size = int.from_bytes(data[moov_size_pos:moov_size_pos+4], 'big')

    tree, _ = read_atoms_in_range(data, moov_pos + 4, moov_pos + moov_size)

    video_trak = None
    for atom in tree:
        if atom['name'] == b'trak':
            hdlr = find_atom(atom['children'], [b'mdia', b'hdlr'])
            if hdlr and b'vide' in hdlr['data']:
                video_trak = atom
                break
    if not video_trak:
        return None

    stbl = find_atom(video_trak['children'], [b'mdia', b'minf', b'stbl'])
    if not stbl:
        return None
    minf = find_atom(video_trak['children'], [b'mdia', b'minf'])
    mdia = find_atom(video_trak['children'], [b'mdia'])

    stsz = find_atom(stbl['children'], [b'stsz'])
    if not stsz:
        return None

    stsz_data = bytearray(stsz['data'])
    orig_count = int.from_bytes(stsz_data[8:12], 'big')
    total_frames = orig_count * multiplier
    diff = total_frames - orig_count
    if diff <= 0:
        return data

    new_entries = b'\x00\x00\x00\x00' * diff
    stsz_start = stsz['start']
    old_stsz_data_len = len(stsz['data'])
    stsz_data[8:12] = total_frames.to_bytes(4, 'big')
    new_stsz_data = bytes(stsz_data) + new_entries
    growth = len(new_stsz_data) - old_stsz_data_len

    result = bytearray(data)
    result[stsz_start:stsz_start + old_stsz_data_len] = new_stsz_data

    # STTS overflow: increase entry count (account for position shift)
    stts = find_atom(stbl['children'], [b'stts'])
    if stts:
        stts_new_start = stts['start']
        if stts['start'] > stsz_start:
            stts_new_start += growth
        stts_data = bytearray(stts['data'])
        entry_count = int.from_bytes(stts_data[8:12], 'big')
        stts_data[8:12] = (entry_count + diff).to_bytes(4, 'big')
        result[stts_new_start:stts_new_start + len(stts['data'])] = bytes(stts_data)

    # Update container sizes
    for parent in [stsz, stbl, minf, mdia, video_trak]:
        old_sz = parent['size']
        new_sz = old_sz + growth
        result[parent['start']:parent['start'] + 4] = new_sz.to_bytes(4, 'big')
    moov_size += growth
    result[moov_size_pos:moov_size_pos+4] = moov_size.to_bytes(4, 'big')

    # Adjust stco/co64 for all tracks (account for position shift)
    for trak in tree:
        if trak['name'] == b'trak':
            t_stbl = find_atom(trak['children'], [b'mdia', b'minf', b'stbl'])
            if not t_stbl:
                continue
            for child in t_stbl['children']:
                if child['name'] not in (b'stco', b'co64'):
                    continue
                entry_size = 4 if child['name'] == b'stco' else 8
                co_new_start = child['start']
                if child['start'] > stsz_start:
                    co_new_start += growth
                co_data = bytearray(child['data'])
                entry_count = int.from_bytes(co_data[4:8], 'big')
                for i in range(entry_count):
                    idx = 8 + i * entry_size
                    val = int.from_bytes(co_data[idx:idx+entry_size], 'big')
                    co_data[idx:idx+entry_size] = (val + growth).to_bytes(entry_size, 'big')
                result[co_new_start:co_new_start + len(child['data'])] = bytes(co_data)

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
