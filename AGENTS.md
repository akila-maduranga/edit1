## Goal  
Prevent TikTok duration-doubling bug and ensure correct processing of stsz-inflated files.

## Constraints & Preferences
- Must work on real TikTok uploads, not just ffmpeg decode.
- Original test file: `E:\Movies\video_20260619_163846.mp4` (148MB, 64-bit box sizes, `co64` chunk offsets).
- Only low‑level bitstream editing (no full remux on device).

## Key Discovery
- **TikTok re-encodes every uploaded video** — the original unmodified file also gets compressed.
- The stsz inflation approach cannot prevent re-encoding. Its only purpose is to prevent TikTok from doubling the video duration (a bug that occurs when stsz entry count exceeds actual frame count).
- The "tikquick" bypass is about **consistent duration handling**, not preventing re-encode.

## What Works
- **Minimal approach** (inflate stsz count only, keep stco/stsc unchanged, pre-set mvhd/tkhd/mdhd durations to match): TikTok processes the file without errors, no duration doubling. Re-encode still happens but the video plays correctly.
- **Complete table rebuild** (stts/stsz/stsc/stco all consistent, fake frames with anchor sizes): TikTok also processes (doesn't get stuck). Both approaches work — choose minimal for simplicity.

## What Doesn't Work
- **Zero-size fake frames with new stco entries**: TikTok gets stuck in processing (handler encounters zero-size AVCC samples and hangs).
- **Fake frames with real P-frame data**: Still gets stuck in processing (why is unknown — possibly TikTok's decoder checks total stsz sum vs file size).

## Progress
### Done
- Investigated three inflation strategies:
  1. **Filler‑based**: appended 8‑byte H.264 filler frames → failed (stsc complexity).
  2. **Zero‑size only**: kept stco/stsc unchanged → ffmpeg OK, TikTok doubled duration.
  3. **Complete table rebuild**: all tables consistent → works but re-encode inevitable.
- Fixed `strip_udta` (patcher_core.py:246): added `if moov_off < mdat_off:` guard.
- Fixed `inject_comment_udta` (patcher_core.py:789): same guard added.
- Fixed stsz body size bug (was `20 + new_total*4` instead of `12 + new_total*4`).
- Fixed stsc simplification bug (original alternates spc 1/2; can't simplify to all spc=1).
- Fixed fake frame delta (was `1` tick, now uses `avg_delta` = ~1500 ticks so total duration matches inflated frame count).
- Fixed audio duration mismatch (inflated audio mdhd to match video multiplier).
- Fixed version reads in `inflate_sample_table_video`: `+12`→`+8` for mvhd/tkhd/mdhd duration — was reading creation_time MSB as version, overwriting hdlr type.
- Fixed `reloov_end` moov detection: when `sz==0` (filler tail of zeros), `break` instead of `sz = len(data)-pos` — was swallowing moov into zeroed box.

### In Progress
- (none)

### Blocked
- No way to prevent TikTok re-encoding entirely (server-side policy).

## Current Best Approach
**Complete table rebuild** (via `patch_all` with `method='inflate'`):
1. 8-pass pipeline: reloov → mvhd fingerprint → udta strip → tkhd fingerprint → codec spoofing → audio duration restore → inflation (5x–10x) → reloov_end
2. Inflation inserts 8-byte filler NALs (`\x00\x00\x00\x01\x0c\x80` + zeros), rebuilds stts/stsz/stsc/stco tables, sets durations to match.
3. reloov_end moves moov to end of file (TikTok reference layout), adjusts stco entries.
4. "No fake atoms" policy: no edts/elst bypass, no comment injection — only structural MP4 edits.

## Relevant Files
- `E:\New folder (7)\New folder (9)\patcher_core.py`: core engine — 8-pass pipeline, `reloov_end()`, `inflate_sample_table_video`, fingerprinting, codec spoofing.
- `E:\New folder (7)\New folder (9)\test_pipeline.py`: test harness.
- `E:\Movies\test_final.mp4`: pipeline output.
- `E:\Movies\video_20260619_163846.mp4`: original source file.
- `E:\Movies\log.txt`: pipeline execution log.
