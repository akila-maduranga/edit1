import sys
sys.path.insert(0, r'E:\New folder (7)\New folder (9)')
from patcher_core import _find_box, _iter_boxes, _adjust_stco, rebuild_elst_bypass

data = open(r'E:\Movies\video_20260619_163846.mp4', 'rb').read()

# reloov
ftyp_off, ftyp_sz = _find_box(data, b'ftyp')
moov_off, moov_sz = _find_box(data, b'moov')
mdat_off, mdat_sz = _find_box(data, b'mdat')
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
        sz = len(data) - pos
    if sz < hdr: break
    if data[pos+4:pos+8] not in (b'ftyp', b'moov'):
        rest.extend(data[pos:pos+sz])
    pos += sz
new_moov = data[moov_off:moov_off+moov_sz]
result = bytearray(data[ftyp_off:ftyp_off+ftyp_sz] + new_moov + rest)
new_mdat_off = result.find(b'mdat') - 4
delta = (new_mdat_off + 8) - (mdat_off + 8)
_adjust_stco(result, delta, ftyp_sz + 8, ftyp_sz + 8 + moov_sz)
data = bytes(result)

# Before elst
moov_off, moov_sz = _find_box(data, b'moov')
print('Before elst:', 'moov at', moov_off, 'size', moov_sz)
for t_off, t_sz, _ in _iter_boxes(data, moov_off+8, moov_off+moov_sz):
    print('  box at', t_off, 'type', data[t_off+4:t_off+8], 'size', t_sz)
    if data[t_off+4:t_off+8] == b'trak':
        mdia_off, mdia_sz = _find_box(data, b'mdia', t_off+8, t_off+t_sz)
        if mdia_off != -1:
            hdlr_off, _ = _find_box(data, b'hdlr', mdia_off+8, mdia_off+mdia_sz)
            hdlr_type = data[hdlr_off+16:hdlr_off+20] if hdlr_off != -1 else b'NONE'
        else:
            hdlr_type = b'NONE'
        print('    mdia at', mdia_off, 'hdlr:', hdlr_type)

# After elst
data2 = rebuild_elst_bypass(data)
moov_off2, moov_sz2 = _find_box(data2, b'moov')
print()
print('After elst:', 'moov at', moov_off2, 'size', moov_sz2)
for t_off, t_sz, _ in _iter_boxes(data2, moov_off2+8, moov_off2+moov_sz2):
    print('  trak at', t_off, 'size', t_sz)
    mdia_off, mdia_sz = _find_box(data2, b'mdia', t_off+8, t_off+t_sz)
    print('    mdia at', mdia_off, 'sz', mdia_sz)
