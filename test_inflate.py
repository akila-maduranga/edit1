import struct, hashlib
from patcher_core import inflate_sample_table_video, _find_box, _iter_boxes

def box(t, body):
    return struct.pack('>I4s', 8 + len(body), t) + body

# ── Build valid MP4 with correct sizes ──
ftyp = box(b'ftyp', b'isom\x00\x00\x02\x00isomiso2avc1mp41')

SAMPLE_SIZE = 104  # 4-byte length prefix + 100-byte NAL
avcC_body = b'\x01\x64\x00\x28\xff\xe0\x00\x19' + b'\x00'*25
avcC = box(b'avcC', avcC_body)
avc1_body = struct.pack('>II', 0, 1) + b'\x00'*16 + struct.pack('>HH', 640, 480) + b'\x00\x48\x00\x00\x00\x48\x00\x00\x00\x00\x00\x00\x00\x01\x00\x18\xff\xff\xff\xff' + avcC_body
avc1 = box(b'avc1', avc1_body)
stsd = box(b'stsd', struct.pack('>II', 0, 1) + avc1)

stco_body = struct.pack('>II', 0, 10)
for i in range(10):
    stco_body += struct.pack('>I', 0)
stco = box(b'stco', stco_body)
stsc = box(b'stsc', struct.pack('>II', 0, 1) + struct.pack('>III', 1, 1, 1))
stsz = box(b'stsz', struct.pack('>III', 0, 0, 10) + struct.pack('>10I', *([SAMPLE_SIZE]*10)))
stss = box(b'stss', struct.pack('>II', 0, 1) + struct.pack('>I', 1))
stts = box(b'stts', struct.pack('>II', 0, 1) + struct.pack('>II', 10, 3000))
stbl = box(b'stbl', stts + stss + stsz + stsc + stco + stsd)
vmhd = box(b'vmhd', struct.pack('>I', 0x00000001) + struct.pack('>II', 0, 0))
minf = box(b'minf', vmhd + stbl)
dref = box(b'dref', struct.pack('>II', 0, 1) + box(b'url ', struct.pack('>I', 0x00000001)))
dinf = box(b'dinf', dref)
hdlr = box(b'hdlr', struct.pack('>I', 0) + struct.pack('>I', 0) + b'vide' + struct.pack('>I', 0) + struct.pack('>I', 0) + b'VideoHandler\x00')
mdhd = box(b'mdhd', struct.pack('>I', 0) + struct.pack('>III', 0, 0, 90000) + struct.pack('>I', 300000) + struct.pack('>HH', 0x55c4, 0))
mdia = box(b'mdia', mdhd + hdlr + minf + dinf)
tkhd_body = struct.pack('>I', 0x00000007) + struct.pack('>II', 0, 0) + struct.pack('>I', 1) + struct.pack('>I', 0) + struct.pack('>I', 300000) * 1 + struct.pack('>II', 0, 0) + struct.pack('>i', 0) + struct.pack('>i', 0) + struct.pack('>9I', 0x00010000, 0, 0, 0, 0x00010000, 0, 0, 0, 0x40000000) + struct.pack('>II', 640<<16, 480<<16)
tkhd = box(b'tkhd', tkhd_body)
trak = box(b'trak', tkhd + mdia)
mvhd_body = struct.pack('>I', 0) + struct.pack('>II', 0, 0) + struct.pack('>I', 90000) + struct.pack('>I', 300000) + struct.pack('>I', 0x00010000) + struct.pack('>H', 0x0100) + struct.pack('>H', 0) + struct.pack('>II', 0, 0) + struct.pack('>9I', 0x00010000, 0, 0, 0, 0x00010000, 0, 0, 0, 0x40000000) + struct.pack('>IIII', 0, 0, 0, 2)
mvhd = box(b'mvhd', mvhd_body)
moov = box(b'moov', mvhd + trak)

file_prefix = ftyp + moov
mdat_off = len(file_prefix)
mdat_body = bytearray()
for i in range(10):
    nal = (b'\x65' if i == 0 else b'\x41') + b'\x00' * 99
    mdat_body += struct.pack('>I', len(nal)) + nal
assert len(mdat_body) // 10 == SAMPLE_SIZE, 'Wrong sample size'
mdat = box(b'mdat', bytes(mdat_body))

data = bytearray(file_prefix + mdat)
for i in range(10):
    off = mdat_off + 8 + i * SAMPLE_SIZE
    struct.pack_into('>I', data, data.find(b'stco') + 16 + i * 4, off)
struct.pack_into('>I', data, data.find(b'mdat') - 4, len(mdat))

print('Original: %d bytes, mdat at offset %d (%d bytes)' % (len(data), mdat_off, len(mdat)))

result = inflate_sample_table_video(bytes(data), multiplier=3)
if result is None:
    print('FAIL: returned None')
else:
    print('Success: %d bytes' % len(result))
    extra = 2 * 10 * SAMPLE_SIZE
    expected = len(data) + extra
    print('Expected ~%d (diff: %d)' % (expected, len(result) - expected))

    moov_s = result.find(b'moov') - 4
    moov_sz = struct.unpack('>I', result[moov_s:moov_s+4])[0]
    for toff, tsz, _ in _iter_boxes(result, moov_s+8, moov_s+moov_sz):
        mdoff, _ = _find_box(result, b'mdia', toff+8, toff+tsz)
        if mdoff == -1: continue
        hoff, _ = _find_box(result, b'hdlr', mdoff+8, mdoff+struct.unpack('>I', result[mdoff:mdoff+4])[0])
        if hoff == -1: continue
        if result[hoff+16:hoff+20] != b'vide': continue
        mifoff, mifsz = _find_box(result, b'minf', mdoff+8, mdoff+struct.unpack('>I', result[mdoff:mdoff+4])[0])
        if mifoff == -1: continue
        sboff, sbsz = _find_box(result, b'stbl', mifoff+8, mifoff+struct.unpack('>I', result[mifoff:mifoff+4])[0])
        if sboff == -1: continue
        sco, _ = _find_box(result, b'stco', sboff+8, sboff+sbsz)
        if sco == -1: continue
        cnt = struct.unpack('>I', result[sco+12:sco+16])[0]
        offs = [struct.unpack('>I', result[sco+16+i*4:sco+20+i*4])[0] for i in range(cnt)]
        print('stco: %d entries, %d unique' % (cnt, len(set(offs))))
        if len(set(offs)) != cnt:
            for o in sorted(set(offs)):
                c = offs.count(o)
                if c > 1: print('  dup: %d x%d' % (o, c))
        else:
            print('PASS: all unique')

        moff = result.find(b'mdat') - 4
        msz = struct.unpack('>I', result[moff:moff+4])[0]
        orig_msz = struct.unpack('>I', data[data.find(b'mdat')-4:data.find(b'mdat')])[0]
        print('mdat: %d -> %d (expected +%d)' % (orig_msz, msz, extra))
        if msz == orig_msz + extra:
            print('PASS: mdat size correct')
        else:
            print('FAIL: mdat size wrong')
