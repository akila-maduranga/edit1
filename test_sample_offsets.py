import struct
from patcher_core import _sample_offsets, _find_box, _iter_boxes

def box(t, body):
    return struct.pack('>I4s', 8 + len(body), t) + body

SAMPLE_SIZE = 104
avcC_body = b'\x01\x64\x00\x28\xff\xe0\x00\x19' + b'\x00'*25
avc1_body = struct.pack('>II', 0, 1) + b'\x00'*16 + struct.pack('>HH', 640, 480) + b'\x00\x48\x00\x00\x00\x48\x00\x00\x00\x00\x00\x00\x00\x01\x00\x18\xff\xff\xff\xff' + avcC_body

stco_data = struct.pack('>II', 0, 10) + struct.pack('>10I', *([0]*10))
stsc_data = struct.pack('>II', 0, 1) + struct.pack('>III', 1, 1, 1)
stsz_data = struct.pack('>III', 0, 0, 10) + struct.pack('>10I', *([SAMPLE_SIZE]*10))

stco = box(b'stco', stco_data)
stsc = box(b'stsc', stsc_data)
stsz = box(b'stsz', stsz_data)
stts = box(b'stts', struct.pack('>II', 0, 1) + struct.pack('>II', 10, 3000))
stss = box(b'stss', struct.pack('>II', 0, 1) + struct.pack('>I', 1))
stsd = box(b'stsd', struct.pack('>II', 0, 1) + avc1_body)
stbl = box(b'stbl', stts + stss + stsz + stsc + stco + stsd)

vmhd = box(b'vmhd', struct.pack('>I', 0x00000001) + struct.pack('>II', 0, 0))
minf = box(b'minf', vmhd + stbl)
hdlr = box(b'hdlr', struct.pack('>I', 0) + struct.pack('>I', 0) + b'vide' + b'\x00'*16 + b'VideoHandler\x00')
mdhd = box(b'mdhd', struct.pack('>I', 0) + struct.pack('>III', 0, 0, 90000) + struct.pack('>I', 300000) + struct.pack('>HH', 0x55c4, 0))
mdia = box(b'mdia', mdhd + hdlr + minf)
tkhd = box(b'tkhd', struct.pack('>I', 0x00000007) + b'\x00'*8 + struct.pack('>I', 1) + b'\x00'*100)
trak = box(b'trak', tkhd + mdia)
mvhd = box(b'mvhd', b'\x00'*4 + b'\x00'*8 + struct.pack('>I', 90000) + struct.pack('>I', 300000) + b'\x00'*80)
moov = box(b'moov', mvhd + trak)
ftyp = box(b'ftyp', b'isom\x00\x00\x02\x00isomiso2avc1mp41')
file_prefix = ftyp + moov
mdat_off = len(file_prefix)

mdat_body = bytearray()
for i in range(10):
    nal_type = 0x65 if i == 0 else 0x41
    nal = bytes([nal_type]) + b'\x00' * 99
    mdat_body += struct.pack('>I', len(nal)) + nal
mdat = box(b'mdat', bytes(mdat_body))

# Build full file
data = bytearray(file_prefix + mdat)
stco_pos = data.find(b'stco') - 4  # box start
for i in range(10):
    off = mdat_off + 8 + i * SAMPLE_SIZE
    struct.pack_into('>I', data, stco_pos + 16 + i * 4, off)
struct.pack_into('>I', data, data.find(b'mdat') - 4, len(mdat))

# Now use the function's logic to find stbl and call _sample_offsets
moov_off = data.find(b'moov') - 4
moov_sz = struct.unpack('>I', data[moov_off:moov_off+4])[0]

for trak_off, trak_sz, _ in _iter_boxes(data, moov_off+8, moov_off+moov_sz):
    mdia_off, mdia_sz = _find_box(data, b'mdia', trak_off+8, trak_off+trak_sz)
    if mdia_off == -1: continue
    hdlr_off, _ = _find_box(data, b'hdlr', mdia_off+8, mdia_off+mdia_sz)
    if hdlr_off == -1 or data[hdlr_off+16:hdlr_off+20] != b'vide': continue
    minf_off, minf_sz = _find_box(data, b'minf', mdia_off+8, mdia_off+mdia_sz)
    if minf_off == -1: continue
    stbl_off, stbl_sz = _find_box(data, b'stbl', minf_off+8, minf_off+minf_sz)
    if stbl_off == -1: continue
    print('stbl at', stbl_off, 'size', stbl_sz)
    
    stco_found, stco_sz = _find_box(data, b'stco', stbl_off+8, stbl_off+stbl_sz)
    stsc_found, _ = _find_box(data, b'stsc', stbl_off+8, stbl_off+stbl_sz)
    stsz_found, _ = _find_box(data, b'stsz', stbl_off+8, stbl_off+stbl_sz)
    print('stco at', stco_found, 'sz', stco_sz)
    print('stsc at', stsc_found)
    print('stsz at', stsz_found)
    
    # Read stco entries
    cnt = struct.unpack('>I', data[stco_found+12:stco_found+16])[0]
    print('stco count:', cnt)
    for i in range(cnt):
        v = struct.unpack('>I', data[stco_found+16+i*4:stco_found+20+i*4])[0]
        print('  stco[%d] = %d' % (i, v))
    
    # Call _sample_offsets
    result = _sample_offsets(data, stco_found, stsc_found, stsz_found, 10)
    print('_sample_offsets returned:', len(result) if result else None, 'entries')
    if result:
        for i, v in enumerate(result):
            print('  sample[%d] = %d' % (i, v))
    else:
        print('  EMPTY!')
