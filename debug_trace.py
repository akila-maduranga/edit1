import sys
sys.path.insert(0, r'E:\New folder (7)\New folder (9)')
from patcher_core import (
    _find_box, _iter_boxes, _adjust_stco, read_audio_duration,
    patch_mvhd_fingerprint, strip_udta, fingerprint_tkhd,
    patch_stsd_codec, patch_ftyp, inject_comment_udta, patch_audio_duration,
    rebuild_elst_bypass
)

# Run all 8 prior passes
data = open(r'E:\Movies\video_20260619_163846.mp4', 'rb').read()
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
data = rebuild_elst_bypass(data)
data = patch_mvhd_fingerprint(data)
data = strip_udta(data)
data = fingerprint_tkhd(data)
data = patch_stsd_codec(data)
data = patch_ftyp(data)
data = inject_comment_udta(data, '@akila')
dur = read_audio_duration(data)
if dur:
    data = patch_audio_duration(data, dur)
print('After 8 passes: len=', len(data))

# Now trace inflate_sample_table_video manually
data2 = data  # copy reference

# Find video stbl
moov_off, moov_sz = _find_box(data2, b'moov')
mdat_off, mdat_sz = _find_box(data2, b'mdat')
print(f'moov={moov_off} sz={moov_sz}  mdat={mdat_off} sz={mdat_sz}')

for t_off, t_sz, _ in _iter_boxes(data2, moov_off+8, moov_off+moov_sz):
    if data2[t_off+4:t_off+8] != b'trak': continue
    mdia_off, mdia_sz = _find_box(data2, b'mdia', t_off+8, t_off+t_sz)
    if mdia_off == -1: continue
    h_off, _ = _find_box(data2, b'hdlr', mdia_off+8, mdia_off+mdia_sz)
    if h_off == -1: continue
    hdlr = data2[h_off+16:h_off+20]
    if hdlr != b'vide': continue
    print(f'Video trak at {t_off} sz={t_sz}')
    print(f'  mdia at {mdia_off} sz={mdia_sz}')
    print(f'  hdlr at {h_off} type={hdlr}')
    minf_off, minf_sz = _find_box(data2, b'minf', mdia_off+8, mdia_off+mdia_sz)
    stbl_off, stbl_sz = _find_box(data2, b'stbl', minf_off+8, minf_off+minf_sz)
    print(f'  minf at {minf_off} sz={minf_sz}')
    print(f'  stbl at {stbl_off} sz={stbl_sz}')
    
    stbl_end = stbl_off + stbl_sz
    for bo, bs, _ in _iter_boxes(data2, stbl_off+8, stbl_end):
        print(f'  stbl child: {data2[bo+4:bo+8]} at {bo} sz={bs}')
