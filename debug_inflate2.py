import sys
sys.path.insert(0, r'E:\New folder (7)\New folder (9)')
from patcher_core import (
    _find_box, _iter_boxes, _adjust_stco, read_audio_duration,
    patch_mvhd_fingerprint, strip_udta, fingerprint_tkhd,
    patch_stsd_codec, patch_ftyp, inject_comment_udta, patch_audio_duration,
    rebuild_elst_bypass, inflate_sample_table_video
)

data = open(r'E:\Movies\video_20260619_163846.mp4', 'rb').read()

# Pass 1: reloov
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
print('Pass 1 reloov: moov=%s' % (_find_box(data, b'moov'),))

# Pass 2: elst bypass
data = rebuild_elst_bypass(data)
print('Pass 2 elst: moov=%s' % (_find_box(data, b'moov'),))
moov_off, moov_sz = _find_box(data, b'moov')
print('  moov size=%d' % moov_sz)
for t_off, t_sz, _ in _iter_boxes(data, moov_off+8, moov_off+moov_sz):
    mdia_off, _ = _find_box(data, b'mdia', t_off+8, t_off+t_sz)
    if mdia_off == -1: continue
    hdr_off, _ = _find_box(data, b'hdlr', mdia_off+8, mdia_off+1000)
    if hdr_off == -1: continue
    hdlr_type = data[hdr_off+16:hdr_off+20]
    print('  trak hdlr=%s mdia_sz=%d' % (hdlr_type, mdia_sz if mdia_off != -1 else -1))
    if hdlr_type == b'vide':
        minf_off, minf_sz = _find_box(data, b'minf', mdia_off+8, mdia_off+mdia_sz)
        print('    minf=%s' % ((minf_off, minf_sz),))
        if minf_off != -1:
            stbl_off, stbl_sz = _find_box(data, b'stbl', minf_off+8, minf_off+minf_sz)
            print('    stbl=%s' % ((stbl_off, stbl_sz),))
            if stbl_off != -1:
                stsd_off, _ = _find_box(data, b'stsd', stbl_off+8, stbl_off+stbl_sz)
                print('    stsd=%s' % ((stsd_off,),))
                if stsd_off != -1:
                    entry_type = data[stsd_off+16:stsd_off+20]
                    print('    stsd entry type=%s' % entry_type)

# Pass 3-8
data = patch_mvhd_fingerprint(data)
data = strip_udta(data)
data = fingerprint_tkhd(data)
data = patch_stsd_codec(data)
data = patch_ftyp(data)
data = inject_comment_udta(data, '@akila')
dur = read_audio_duration(data)
if dur:
    data = patch_audio_duration(data, dur)
print('Pass 3-8 done: moov=%s' % (_find_box(data, b'moov'),))

# Pass 9: inflation
print('Calling inflate_sample_table_video...')
result = inflate_sample_table_video(data, multiplier=5)
if result is None:
    print('INFLATION FAILED')
else:
    print('INFLATION OK, size=%d' % len(result))
