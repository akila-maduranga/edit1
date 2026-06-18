#!/usr/bin/env python3
"""
TikTok bypass patcher — standalone CLI (original working approach).
"""

import sys
import subprocess
import struct
import time
from patcher_core import patch_timestamps, patch_language, _adjust_stco


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


def inject_fake_frames(data, target_frames=None, pre_shift=0, stts_overflow=True):
    moov_pos = data.find(b'moov')
    if moov_pos < 4:
        print("[-] moov not found")
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
        print("[-] Video track not found")
        return None

    stbl = find_atom(video_trak['children'], [b'mdia', b'minf', b'stbl'])
    if not stbl:
        print("[-] stbl not found")
        return None
    minf = find_atom(video_trak['children'], [b'mdia', b'minf'])
    mdia = find_atom(video_trak['children'], [b'mdia'])

    stsz = find_atom(stbl['children'], [b'stsz'])
    if not stsz:
        print("[-] stsz not found")
        return None

    stsz_data = bytearray(stsz['data'])
    orig_count = int.from_bytes(stsz_data[8:12], 'big')
    if target_frames is None:
        target_frames = orig_count * 10
    diff = target_frames - orig_count
    if diff <= 0:
        print(f"[*] Already {orig_count} frames")
        return data

    print(f"[*] STSZ: {orig_count} -> {target_frames}")
    new_entries = b'\x00\x00\x00\x00' * diff

    result = bytearray(data)

    stsz_start_in_file = stsz['start']
    old_stsz_data_len = len(stsz['data'])
    stsz_data[8:12] = target_frames.to_bytes(4, 'big')
    new_stsz_data = bytes(stsz_data) + new_entries
    growth = len(new_stsz_data) - old_stsz_data_len

    result[stsz_start_in_file:stsz_start_in_file + old_stsz_data_len] = new_stsz_data

    if stts_overflow:
        stts = find_atom(stbl['children'], [b'stts'])
        if stts:
            stts_data = bytearray(stts['data'])
            entry_count = int.from_bytes(stts_data[8:12], 'big')
            stts_data[8:12] = (entry_count + diff).to_bytes(4, 'big')
            result[stts['start']:stts['start'] + len(stts['data'])] = bytes(stts_data)
            print(f"[*] STTS: entries {entry_count} -> {entry_count + diff}")

    for parent in [stsz, stbl, minf, mdia, video_trak]:
        old_sz = parent['size']
        new_sz = old_sz + growth
        result[parent['start']:parent['start'] + 4] = new_sz.to_bytes(4, 'big')
    new_moov_size = moov_size + growth
    result[moov_size_pos:moov_size_pos+4] = new_moov_size.to_bytes(4, 'big')

    video_stsz_start = stsz['start']
    for trak in tree:
        if trak['name'] == b'trak':
            t_stbl = find_atom(trak['children'], [b'mdia', b'minf', b'stbl'])
            if not t_stbl:
                continue
            for child in t_stbl['children']:
                if child['name'] == b'stco':
                    pos_shift = growth if child['start'] > video_stsz_start else 0
                    co_data = bytearray(child['data'])
                    entry_count = int.from_bytes(co_data[4:8], 'big')
                    for i in range(entry_count):
                        idx = 8 + i * 4
                        val = int.from_bytes(co_data[idx:idx+4], 'big')
                        new_val = val + growth + pre_shift
                        co_data[idx:idx+4] = new_val.to_bytes(4, 'big')
                    result[child['start'] + pos_shift:child['start'] + pos_shift + len(child['data'])] = bytes(co_data)
    return bytes(result)


def build_metadata_tree(comment):
    entries = {}
    if comment:
        entries[b'\xa9cmt'] = comment

    udta_data = b''
    for tag_key, value in entries.items():
        value_bytes = value.encode('utf-8')
        tag_box = struct.pack('>I4s', 8 + len(value_bytes), tag_key) + value_bytes
        udta_data += tag_box

    hdlr = struct.pack('>I4sI', 41, b'hdlr', 0)
    hdlr += struct.pack('>I4s', 0, b'mdir')
    hdlr += b'appl' + struct.pack('>II', 0, 0)
    hdlr += b'Metadata\x00'
    ilst = struct.pack('>I4s', 8, b'ilst')
    meta_content = b'\x00\x00\x00\x00' + hdlr + ilst
    meta = struct.pack('>I4s', 8 + len(meta_content), b'meta') + meta_content
    udta_data += meta
    return struct.pack('>I4s', 8 + len(udta_data), b'udta') + udta_data


def patch_video(input_path, output_path, comment="Patched with VideoBoost", stts_overflow=True):
    if not __import__('os').path.exists(input_path):
        print(f"Error: Input file '{input_path}' not found.")
        return

    ffmpeg_cmd = [
        "ffmpeg", "-y", "-i", input_path,
        "-c", "copy",
        "-brand", "isom",
        "-video_track_timescale", "90000",
        "-movflags", "+faststart",
        "-metadata:s:a:0", "handler_name=SoundHandler",
    ]
    ffmpeg_cmd.append(output_path)

    print("FFmpeg remux...")
    start = time.time()
    result = subprocess.run(ffmpeg_cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"FFmpeg failed:\n{result.stderr[:500]}")
        return
    print(f"FFmpeg done ({time.time()-start:.2f}s)")

    with open(output_path, 'rb') as f:
        data = bytearray(f.read())

    # Insert free atom after ftyp
    ftyp_size = int.from_bytes(data[0:4], 'big')
    next_type = data[ftyp_size+4:ftyp_size+8]
    if next_type == b'free':
        print("Free atom already present after ftyp — skipping")
        pre_shift_extra = 0
    else:
        data[ftyp_size:ftyp_size] = b'\x00\x00\x00\x08free'
        print("Free atom: inserted after ftyp (size=8)")
        pre_shift_extra = 8

    # Date zeroing
    data = bytearray(patch_timestamps(data))

    # Language spoofing
    data = bytearray(patch_language(data))

    # Build metadata tree
    md_tree = build_metadata_tree(comment)
    md_growth = len(md_tree)
    print(f"Metadata tree: {md_growth} bytes")

    # Frame inflation
    patched = inject_fake_frames(data, pre_shift=pre_shift_extra, stts_overflow=stts_overflow)
    if patched is None:
        print("Injection failed")
        return
    patched = bytearray(patched)

    # Remove old udta and inject metadata
    moov_atom_start = patched.find(b'moov') - 4
    current_moov_size = int.from_bytes(patched[moov_atom_start:moov_atom_start+4], 'big')
    moov_end = moov_atom_start + current_moov_size

    pos = moov_atom_start + 8
    udta_removed = 0
    while pos + 8 <= moov_end:
        atom_size = int.from_bytes(patched[pos:pos+4], 'big')
        atom_type = patched[pos+4:pos+8]
        if atom_size < 8:
            break
        if atom_type == b'udta':
            del patched[pos:pos + atom_size]
            udta_removed = atom_size
            current_moov_size -= udta_removed
            moov_end -= udta_removed
            break
        pos += atom_size

    patched[moov_end:moov_end] = md_tree
    new_moov_size = current_moov_size + md_growth
    patched[moov_atom_start:moov_atom_start+4] = new_moov_size.to_bytes(4, 'big')
    net_shift = md_growth - udta_removed
    if net_shift != 0:
        _adjust_stco(patched, net_shift, moov_atom_start, moov_atom_start + new_moov_size)
    print(f"Metadata injected: moov {current_moov_size} -> {new_moov_size} (udta_removed={udta_removed})")

    # Expand padding after ftyp, target offset=237436
    target_offset = 237436
    ftyp_size = int.from_bytes(patched[0:4], 'big')
    if patched[ftyp_size:ftyp_size+8] == b'\x00\x00\x00\x08free':
        need = target_offset - 40 - new_moov_size
        if need >= 8:
            ffmpeg_free_removed = 0
            moov_end = moov_atom_start + new_moov_size
            if patched[moov_end:moov_end+8] == b'\x00\x00\x00\x08free':
                del patched[moov_end:moov_end + 8]
                ffmpeg_free_removed = 8
            new_free = struct.pack('>I4s', need, b'free') + b'\x00' * (need - 8)
            patched[ftyp_size:ftyp_size+8] = new_free
            shift = need - 8
            moov_atom_start += shift
            stco_delta = shift - ffmpeg_free_removed
            if stco_delta != 0:
                _adjust_stco(patched, stco_delta, moov_atom_start, moov_atom_start + new_moov_size)
            print(f"Free atom: 8 -> {need} (stco_delta={stco_delta:+d})")
    else:
        print("Expected free(8) after ftyp not found — skipping padding")

    # Fake trailer
    patched += b'\x00\x00\x00\x04xxxx'
    print("Fake atom: xxxx(size=4) appended at end")

    with open(output_path, 'wb') as f:
        f.write(patched)
    print(f"Done! Output: {output_path}")


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="TikTok Patcher CLI")
    p.add_argument("input", help="Input MP4 file")
    p.add_argument("-o", "--output", default="enhanced_output.mp4", help="Output file")
    p.add_argument("--tag", default="Patched with VideoBoost", help="Comment/social tag")
    p.add_argument("--no-stts", action="store_true", help="Disable STTS overflow exploit")
    args = p.parse_args()
    patch_video(args.input, args.output, comment=args.tag, stts_overflow=not args.no_stts)
