import sys
sys.path.insert(0, r'E:\New folder (7)\New folder (9)')
from patcher_core import (
    _find_box, _iter_boxes, _adjust_stco, read_audio_duration,
    patch_mvhd_fingerprint, strip_udta, fingerprint_tkhd,
    patch_stsd_codec, patch_ftyp, inject_comment_udta, patch_audio_duration,
    rebuild_elst_bypass, inflate_sample_table_video
)

data = open(r'E:\Movies\video_20260619_163846.mp4', 'rb').read()

# All 8 prior passes
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

# Manual inflation debug
moov_off, moov_sz = _find_box(data, b'moov')
mdat_off, mdat_sz = _find_box(data, b'mdat')
print('moov=%s mdat=%s' % ((moov_off, moov_sz), (mdat_off, mdat_sz)))

for t_off, t_sz, _ in _iter_boxes(data, moov_off+8, moov_off+moov_sz):
    print('trak at %d sz=%d' % (t_off, t_sz))
    mdia_off, mdia_sz = _find_box(data, b'mdia', t_off+8, t_off+t_sz)
    if mdia_off == -1:
        print('  mdia not found')
        continue
    print('  mdia at %d sz=%d' % (mdia_off, mdia_sz))
    hdlr_off, _ = _find_box(data, b'hdlr', mdia_off+8, mdia_off+mdia_sz)
    if hdlr_off == -1:
        print('  hdlr not found')
        continue
    hdlr_type = data[hdlr_off+16:hdlr_off+20]
    print('  hdlr at %d type=%s' % (hdlr_off, hdlr_type))
    if hdlr_type != b'vide': continue
    minf_off, minf_sz = _find_box(data, b'minf', mdia_off+8, mdia_off+mdia_sz)
    if minf_off == -1:
        print('minf not found for video trak!')
        continue
    print('video minf at %d sz=%d' % (minf_off, minf_sz))
    stbl_off, stbl_sz = _find_box(data, b'stbl', minf_off+8, minf_off+minf_sz)
    if stbl_off == -1:
        print('stbl not found!')
        continue
    print('video stbl at %d sz=%d' % (stbl_off, stbl_sz))
    stbl_end = stbl_off + stbl_sz
    
    stts_off, stts_sz = _find_box(data, b'stts', stbl_off+8, stbl_end)
    stsz_off, stsz_sz = _find_box(data, b'stsz', stbl_off+8, stbl_end)
    stco_off, stco_sz = _find_box(data, b'stco', stbl_off+8, stbl_end)
    if stco_off == -1:
        stco_off, stco_sz = _find_box(data, b'co64', stbl_off+8, stbl_end)
    stsc_off, stsc_sz = _find_box(data, b'stsc', stbl_off+8, stbl_end)
    print('stts=%s stsz=%s stco=%s stsc=%s' % ((stts_off, stts_sz), (stsz_off, stsz_sz), (stco_off, stco_sz), (stsc_off, stsc_sz)))
    break
