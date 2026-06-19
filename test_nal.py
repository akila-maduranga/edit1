import struct
from patcher_core import inflate_sample_table_video, _find_box, _iter_boxes

def box(t, body):
    return struct.pack('>I4s', 8 + len(body), t) + body

SAMPLE_SIZE = 104
avcC_body = b'\x01\x64\x00\x28\xff\xe0\x00\x19' + b'\x00'*25
avcC = box(b'avcC', avcC_body)
avc1_body = struct.pack('>IH', 0, 1)  # 6 reserved + 2 data_ref_idx
avc1_body += struct.pack('>HH', 0, 0)  # version + revision
avc1_body += b'\x00\x00\x00\x00'  # vendor
avc1_body += struct.pack('>II', 0, 0)  # temporal + spatial quality
avc1_body += struct.pack('>HH', 640, 480)  # width, height
avc1_body += struct.pack('>II', 0x00480000, 0x00480000)  # hres, vres
avc1_body += struct.pack('>I', 0)  # data size
avc1_body += struct.pack('>H', 1)  # frame count
avc1_body += b'\x00'  # compressor name length
avc1_body += b'\x00' * 31  # compressor name
avc1_body += struct.pack('>H', 0x0018)  # depth
avc1_body += struct.pack('>h', -1)  # color table id
avc1_body += avcC  # proper avcC box nested inside avc1
avc1 = box(b'avc1', avc1_body)

stco = box(b'stco', struct.pack('>II', 0, 10) + struct.pack('>10I', *([0]*10)))
stsc = box(b'stsc', struct.pack('>II', 0, 1) + struct.pack('>III', 1, 1, 1))
stsz = box(b'stsz', struct.pack('>III', 0, 0, 10) + struct.pack('>10I', *([SAMPLE_SIZE]*10)))
stss = box(b'stss', struct.pack('>II', 0, 1) + struct.pack('>I', 1))
stts = box(b'stts', struct.pack('>II', 0, 1) + struct.pack('>II', 10, 3000))
stsd = box(b'stsd', struct.pack('>II', 0, 1) + avc1)
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
data = bytearray(file_prefix + mdat)

# Set stco offsets correctly
stco_off = data.find(b'stco') - 4  # box start
if stco_off < 0:
    raise AssertionError('stco not found')
for i in range(10):
    off = mdat_off + 8 + i * SAMPLE_SIZE
    struct.pack_into('>I', data, stco_off + 16 + i * 4, off)
struct.pack_into('>I', data, data.find(b'mdat') - 4, len(mdat))

print('Data size: %d, mdat at %d' % (len(data), mdat_off))
print('stco at', stco_off)

result = inflate_sample_table_video(bytes(data), multiplier=3)
if result is None:
    print('FAIL: returned None')
    exit(1)

print('\nSuccess: %d bytes' % len(result))

# Walk to find video stco and verify
moov_addr = result.find(b'moov') - 4
moov_sz = struct.unpack('>I', result[moov_addr:moov_addr+4])[0]
for toff, tsz, typ in _iter_boxes(result, moov_addr+8, moov_addr+moov_sz):
    if typ != b'trak': continue
    for coff, csz, ctyp in _iter_boxes(result, toff+8, toff+tsz):
        if ctyp != b'mdia': continue
        for doff, dsz, dtype in _iter_boxes(result, coff+8, coff+csz):
            if dtype != b'minf': continue
            for eoff, esz, etype in _iter_boxes(result, doff+8, doff+dsz):
                if etype != b'stbl': continue
                stbl_sz = esz
                for foff, fsz, ftype in _iter_boxes(result, eoff+8, eoff+esz):
                    if ftype == b'stco':
                        cnt = struct.unpack('>I', result[foff+12:foff+16])[0]
                        offs = [struct.unpack('>I', result[foff+16+i*4:foff+20+i*4])[0] for i in range(cnt)]
                        print('stco: %d entries' % cnt)
                        errors = []
                        for i, abs_off in enumerate(offs):
                            if i < 10:
                                expected = 0x65 if i == 0 else 0x41
                                label = 'orig %d' % i
                            else:
                                expected = 0x01
                                label = 'copy %d' % (i-10)
                            if abs_off + 5 > len(result):
                                errors.append('%s off=%d out of bounds!' % (label, abs_off))
                                continue
                            hdr = result[abs_off + 4]
                            if hdr != expected:
                                errors.append('%s off=%d hdr=0x%02x expected=0x%02x' % (label, abs_off, hdr, expected))
                        if errors:
                            print('  NAL ERRORS:')
                            for e in errors: print('    '+e)
                        else:
                            print('  PASS: all NAL headers correct')
                        if len(set(offs)) == len(offs):
                            print('  PASS: all unique')
                        else:
                            dups = len(offs) - len(set(offs))
                            print('  FAIL: %d duplicate stco entries' % dups)
                            for o in sorted(set(offs)):
                                c = offs.count(o)
                                if c > 1: print('    dup: %d x%d' % (o, c))
