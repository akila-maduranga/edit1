import struct
import subprocess
import shutil
from pathlib import Path

# ==========================================
# MP4 Box Parser & Writer
# ==========================================
class Box:
    def __init__(self, box_type, data=b'', children=None):
        self.box_type = box_type
        self.data = data
        self.children = children if children is not None else []

    def size(self):
        s = 8
        if self.children:
            for c in self.children:
                s += c.size()
        else:
            s += len(self.data)
        return s

    def build(self):
        s = self.size()
        if s > 0xFFFFFFFF:
            out = struct.pack('>I', 1) + self.box_type + struct.pack('>Q', s)
        else:
            out = struct.pack('>I', s) + self.box_type
            
        if self.children:
            for c in self.children:
                out += c.build()
        else:
            out += self.data
        return out

def parse_boxes(data, start=0, end=None):
    if end is None:
        end = len(data)
    boxes = []
    pos = start
    while pos + 8 <= end:
        size = struct.unpack('>I', data[pos:pos+4])[0]
        header_size = 8
        if size == 1:
            if pos + 16 > end: break
            size = struct.unpack('>Q', data[pos+8:pos+16])[0]
            header_size = 16
        elif size == 0:
            size = end - pos
            
        if size < header_size or pos + size > end:
            break
            
        box_type = data[pos+4:pos+8]
        box_data = data[pos+header_size:pos+size]
        
        container_types = [b'moov', b'trak', b'mdia', b'minf', b'stbl', b'edts', b'udta', b'dinf', b'mvex']
        if box_type in container_types:
            children = parse_boxes(box_data, 0, len(box_data))
            boxes.append(Box(box_type, b'', children))
        else:
            boxes.append(Box(box_type, box_data))
            
        pos += size
    return boxes

# ==========================================
# Table Inflators (Fix 1)
# ==========================================
def inflate_stts(box, loop_count):
    data = box.data
    version_flags = data[:4]
    entry_count = struct.unpack('>I', data[4:8])[0]
    entries = data[8:]
    
    new_entries = b''
    for _ in range(loop_count):
        new_entries += entries
        
    new_entry_count = entry_count * loop_count
    new_data = version_flags + struct.pack('>I', new_entry_count) + new_entries
    return Box(b'stts', new_data)

def inflate_stsz(box, loop_count):
    data = box.data
    version_flags = data[:4]
    default_size = struct.unpack('>I', data[4:8])[0]
    entry_count = struct.unpack('>I', data[8:12])[0]
    entries = data[12:]
    
    new_entries = b''
    for _ in range(loop_count):
        new_entries += entries
        
    new_entry_count = entry_count * loop_count
    new_data = version_flags + struct.pack('>I', default_size) + struct.pack('>I', new_entry_count) + new_entries
    return Box(b'stsz', new_data)

def inflate_stsc(box, loop_count, orig_total_chunks):
    data = box.data
    version_flags = data[:4]
    entry_count = struct.unpack('>I', data[4:8])[0]
    entries = data[8:]
    
    new_entries = b''
    for i in range(loop_count):
        for j in range(entry_count):
            offset = j * 12
            first_chunk = struct.unpack('>I', entries[offset:offset+4])[0]
            samples_per_chunk = struct.unpack('>I', entries[offset+4:offset+8])[0]
            sample_desc_idx = struct.unpack('>I', entries[offset+8:offset+12])[0]
            
            new_first_chunk = first_chunk + (i * orig_total_chunks)
            new_entries += struct.pack('>III', new_first_chunk, samples_per_chunk, sample_desc_idx)
            
    new_entry_count = entry_count * loop_count
    new_data = version_flags + struct.pack('>I', new_entry_count) + new_entries
    return Box(b'stsc', new_data)

def inflate_stco(box, loop_count):
    data = box.data
    version_flags = data[:4]
    entry_count = struct.unpack('>I', data[4:8])[0]
    entries = data[8:]
    
    new_entries = b''
    for _ in range(loop_count):
        new_entries += entries
        
    new_entry_count = entry_count * loop_count
    new_data = version_flags + struct.pack('>I', new_entry_count) + new_entries
    return Box(b'stco', new_data)

def inflate_co64(box, loop_count):
    data = box.data
    version_flags = data[:4]
    entry_count = struct.unpack('>I', data[4:8])[0]
    entries = data[8:]
    
    new_entries = b''
    for _ in range(loop_count):
        new_entries += entries
        
    new_entry_count = entry_count * loop_count
    new_data = version_flags + struct.pack('>I', new_entry_count) + new_entries
    return Box(b'co64', new_data)

def inflate_ctts(box, loop_count):
    data = box.data
    version_flags = data[:4]
    entry_count = struct.unpack('>I', data[4:8])[0]
    entries = data[8:]
    
    new_entries = b''
    for _ in range(loop_count):
        new_entries += entries
        
    new_entry_count = entry_count * loop_count
    new_data = version_flags + struct.pack('>I', new_entry_count) + new_entries
    return Box(b'ctts', new_data)

def inflate_stss(box, loop_count, orig_total_samples):
    data = box.data
    version_flags = data[:4]
    entry_count = struct.unpack('>I', data[4:8])[0]
    entries = data[8:]
    
    new_entries = b''
    for i in range(loop_count):
        for j in range(entry_count):
            offset = j * 4
            sample_num = struct.unpack('>I', entries[offset:offset+4])[0]
            new_sample_num = sample_num + (i * orig_total_samples)
            new_entries += struct.pack('>I', new_sample_num)
            
    new_entry_count = entry_count * loop_count
    new_data = version_flags + struct.pack('>I', new_entry_count) + new_entries
    return Box(b'stss', new_data)

# ==========================================
# Track & Header Inflators
# ==========================================
def inflate_mvhd(mvhd, loop_count):
    data = mvhd.data
    version = data[0]
    if version == 0:
        duration = struct.unpack('>I', data[16:20])[0]
        new_duration = duration * loop_count
        new_data = data[:16] + struct.pack('>I', new_duration) + data[20:]
    else:
        duration = struct.unpack('>Q', data[24:32])[0]
        new_duration = duration * loop_count
        new_data = data[:24] + struct.pack('>Q', new_duration) + data[32:]
    return Box(b'mvhd', new_data)

def inflate_tkhd(tkhd, loop_count):
    data = tkhd.data
    version = data[0]
    if version == 0:
        duration = struct.unpack('>I', data[20:24])[0]
        new_duration = duration * loop_count
        new_data = data[:20] + struct.pack('>I', new_duration) + data[24:]
    else:
        duration = struct.unpack('>Q', data[28:36])[0]
        new_duration = duration * loop_count
        new_data = data[:28] + struct.pack('>Q', new_duration) + data[36:]
    return Box(b'tkhd', new_data)

def inflate_mdhd(mdhd, loop_count):
    data = mdhd.data
    version = data[0]
    if version == 0:
        duration = struct.unpack('>I', data[16:20])[0]
        new_duration = duration * loop_count
        new_data = data[:16] + struct.pack('>I', new_duration) + data[20:]
    else:
        duration = struct.unpack('>Q', data[24:32])[0]
        new_duration = duration * loop_count
        new_data = data[:24] + struct.pack('>Q', new_duration) + data[32:]
    return Box(b'mdhd', new_data)

def inflate_elst(elst, loop_count):
    data = elst.data
    version = data[0]
    flags = data[1:4]
    entry_count = struct.unpack('>I', data[4:8])[0]
    entries = data[8:]
    
    new_entries = b''
    entry_size = 12 if version == 0 else 20
    for i in range(entry_count):
        entry = entries[i*entry_size : (i+1)*entry_size]
        if version == 0:
            duration = struct.unpack('>I', entry[:4])[0]
            new_duration = duration * loop_count
            new_entries += struct.pack('>I', new_duration) + entry[4:]
        else:
            duration = struct.unpack('>Q', entry[:8])[0]
            new_duration = duration * loop_count
            new_entries += struct.pack('>Q', new_duration) + entry[8:]
            
    new_data = struct.pack('>B', version) + flags + struct.pack('>I', entry_count) + new_entries
    return Box(b'elst', new_data)

def inflate_stbl(stbl, loop_count):
    orig_total_chunks = 0
    orig_total_samples = 0
    
    for child in stbl.children:
        if child.box_type == b'stco' or child.box_type == b'co64':
            orig_total_chunks = struct.unpack('>I', child.data[4:8])[0]
        elif child.box_type == b'stts':
            count = struct.unpack('>I', child.data[4:8])[0]
            entries = child.data[8:]
            for i in range(count):
                sc = struct.unpack('>I', entries[i*8:i*8+4])[0]
                orig_total_samples += sc

    new_children = []
    for child in stbl.children:
        if child.box_type == b'stts':
            new_children.append(inflate_stts(child, loop_count))
        elif child.box_type == b'stsz':
            new_children.append(inflate_stsz(child, loop_count))
        elif child.box_type == b'stsc':
            new_children.append(inflate_stsc(child, loop_count, orig_total_chunks))
        elif child.box_type == b'stco':
            new_children.append(inflate_stco(child, loop_count))
        elif child.box_type == b'co64':
            new_children.append(inflate_co64(child, loop_count))
        elif child.box_type == b'ctts':
            new_children.append(inflate_ctts(child, loop_count))
        elif child.box_type == b'stss':
            new_children.append(inflate_stss(child, loop_count, orig_total_samples))
        else:
            new_children.append(child)
    return Box(b'stbl', b'', new_children)

def inflate_trak(trak, loop_count):
    new_trak_children = []
    for child in trak.children:
        if child.box_type == b'tkhd':
            new_trak_children.append(inflate_tkhd(child, loop_count))
        elif child.box_type == b'mdia':
            new_mdia_children = []
            for mdia_child in child.children:
                if mdia_child.box_type == b'mdhd':
                    new_mdia_children.append(inflate_mdhd(mdia_child, loop_count))
                elif mdia_child.box_type == b'minf':
                    new_minf_children = []
                    for minf_child in mdia_child.children:
                        if minf_child.box_type == b'stbl':
                            new_minf_children.append(inflate_stbl(minf_child, loop_count))
                        else:
                            new_minf_children.append(minf_child)
                    new_mdia_children.append(Box(b'minf', b'', new_minf_children))
                else:
                    new_mdia_children.append(mdia_child)
            new_trak_children.append(Box(b'mdia', b'', new_mdia_children))
        elif child.box_type == b'edts':
            new_edts_children = []
            for edts_child in child.children:
                if edts_child.box_type == b'elst':
                    new_edts_children.append(inflate_elst(edts_child, loop_count))
                else:
                    new_edts_children.append(edts_child)
            new_trak_children.append(Box(b'edts', b'', new_edts_children))
        else:
            new_trak_children.append(child)
    return Box(b'trak', b'', new_trak_children)

def inflate_moov(moov, loop_count):
    new_moov_children = []
    for child in moov.children:
        if child.box_type == b'mvhd':
            new_moov_children.append(inflate_mvhd(child, loop_count))
        elif child.box_type == b'trak':
            new_moov_children.append(inflate_trak(child, loop_count))
        else:
            new_moov_children.append(child)
    return Box(b'moov', b'', new_moov_children)

def inflate_sample_table_video(data, loop_count=10):
    moov_off, moov_sz = _find_box(data, b'moov')
    if moov_off == -1:
        return data
        
    moov_data = data[moov_off:moov_off+moov_sz]
    moov_box = parse_boxes(moov_data)[0]
    
    new_moov_box = inflate_moov(moov_box, loop_count)
    new_moov_data = new_moov_box.build()
    
    new_data = bytearray()
    new_data.extend(data[:moov_off])
    new_data.extend(new_moov_data)
    new_data.extend(data[moov_off+moov_sz:])
    
    return bytes(new_data)

# ==========================================
# Offset Adjuster & reloov_end (Fix 2)
# ==========================================
def _find_box(data, box_type, start=0, end=None):
    if end is None:
        end = len(data)
    pos = start
    while pos + 8 <= end:
        size = int.from_bytes(data[pos:pos+4], 'big')
        header_size = 8
        if size == 1:
            if pos + 16 > end: break
            size = int.from_bytes(data[pos+8:pos+16], 'big')
            header_size = 16
        elif size == 0:
            size = end - pos
            
        if size < header_size or pos + size > end:
            break
            
        btype = data[pos+4:pos+8]
        if btype == box_type:
            return pos, size
            
        pos += size
    return -1, 0

def _adjust_stco(data, delta, start, end):
    pos = start
    while pos + 8 <= end:
        size = int.from_bytes(data[pos:pos+4], 'big')
        header_size = 8
        if size == 1:
            if pos + 16 > end: break
            size = int.from_bytes(data[pos+8:pos+16], 'big')
            header_size = 16
        elif size == 0:
            size = end - pos
            
        if size < header_size or pos + size > end:
            break
            
        btype = data[pos+4:pos+8]
        
        if btype in (b'moov', b'trak', b'mdia', b'minf', b'stbl', b'edts', b'udta', b'dinf', b'mvex'):
            _adjust_stco(data, delta, pos + header_size, pos + size)
        elif btype == b'stco':
            entry_count = int.from_bytes(data[pos+8:pos+12], 'big')
            entries_start = pos + 12
            for i in range(entry_count):
                idx = entries_start + i * 4
                if idx + 4 > pos + size: break
                offset = int.from_bytes(data[idx:idx+4], 'big')
                new_offset = offset + delta
                data[idx:idx+4] = (new_offset & 0xFFFFFFFF).to_bytes(4, 'big')
        elif btype == b'co64':
            entry_count = int.from_bytes(data[pos+8:pos+12], 'big')
            entries_start = pos + 12
            for i in range(entry_count):
                idx = entries_start + i * 8
                if idx + 8 > pos + size: break
                offset = int.from_bytes(data[idx:idx+8], 'big')
                new_offset = offset + delta
                data[idx:idx+8] = new_offset.to_bytes(8, 'big')
                
        pos += size

def reloov_end(data):
    ftyp_off, ftyp_sz = _find_box(data, b'ftyp')
    moov_off, moov_sz = _find_box(data, b'moov')
    if -1 in (ftyp_off, moov_off) or ftyp_off != 0:
        return data

    rest = bytearray()
    pos = 0
    while pos + 8 <= len(data):
        sz = int.from_bytes(data[pos:pos+4], 'big')
        hdr = 8
        if sz == 1:
            if pos + 16 > len(data): break
            sz = int.from_bytes(data[pos+8:pos+16], 'big')
            hdr = 16
        elif sz == 0:
            break
        if sz < hdr: break
        btype = data[pos+4:pos+8]
        if btype not in (b'ftyp', b'moov'):
            rest.extend(data[pos:pos+sz])
        pos += sz

    new_data = bytearray()
    new_data.extend(data[ftyp_off:ftyp_off+ftyp_sz])
    new_data.extend(rest)
    new_data.extend(data[moov_off:moov_off+moov_sz])

    old_mdat_off, _ = _find_box(data, b'mdat')
    new_mdat_off, _ = _find_box(bytes(new_data), b'mdat')
    
    if old_mdat_off != -1 and new_mdat_off != -1:
        mdat_delta = new_mdat_off - old_mdat_off
        new_moov_off = ftyp_sz + len(rest)
        _adjust_stco(new_data, mdat_delta, new_moov_off, new_moov_off + moov_sz)
        
    return bytes(new_data)

# ==========================================
# Main Entry Points (File I/O Wrappers)
# ==========================================
def tikquick_encode(input_path, output_path, log_func=None, **kwargs):
    """Re-encodes the video to TikQuick quality using ffmpeg."""
    try:
        if not shutil.which("ffmpeg"):
            if log_func: log_func("[ERROR] ffmpeg not found in PATH.")
            return False
            
        if log_func: log_func("[ENCODE] Starting TikQuick quality encode...")
        
        # TikQuick standard settings: 1080p, H.264, AAC, faststart
        cmd = [
            "ffmpeg", "-y", "-i", str(input_path),
            "-c:v", "libx264", "-preset", "medium", "-crf", "23",
            "-vf", "scale='min(1080,iw)':-2",
            "-c:a", "aac", "-b:a", "128k",
            "-movflags", "+faststart",
            str(output_path)
        ]
        
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        if result.returncode != 0:
            if log_func: log_func(f"[ERROR] ffmpeg failed:\n{result.stderr[-500:]}")
            return False
            
        if log_func: log_func("[ENCODE] Encoding complete.")
        return True
    except Exception as e:
        if log_func: log_func(f"[ERROR] {e}")
        return False

def patch_all(input_path, output_path, comment=None, log_func=None, method='inflate', **kwargs):
    """Reads input file, applies patches, and writes to output path."""
    try:
        if log_func: log_func(f"[PATCH] Reading input file: {input_path}")
        with open(input_path, 'rb') as f:
            data = f.read()
            
        if method == 'inflate':
            if log_func: log_func("[PATCH] Inflating sample tables 10x...")
            data = inflate_sample_table_video(data, loop_count=10)
            
        if log_func: log_func("[PATCH] Relocating moov to end and fixing offsets...")
        data = reloov_end(data)
        
        if comment:
            # Placeholder for comment injection logic if needed later
            if log_func: log_func(f"[PATCH] Comment received but injection is skipped in this build.")
            
        with open(output_path, 'wb') as f:
            f.write(data)
            
        if log_func: log_func(f"[PATCH] Successfully patched to: {output_path}")
        return True
        
    except Exception as e:
        if log_func: log_func(f"[ERROR] {e}")
        return False
