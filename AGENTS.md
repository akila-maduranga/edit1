## Goal
- ~~Bypass TikTok re-encode detection via stsz frame count inflation while keeping video fully decodable (no H.264/AAC errors, correct duration).~~
- **REVISED**: Prevent TikTok duration-doubling bug and ensure correct processing of stsz-inflated files. TikTok re-encodes ALL uploads regardless.

## Constraints & Preferences
- Must work on real TikTok uploads, not just ffmpeg decode.
- Original file is `E:\Movies\Video 202sasgwrg6.mp4` (moov‑after‑mdat layout).
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

### In Progress
- Understanding that TikTok always re-encodes and stsz inflation is only for duration correction.

### Blocked
- No way to prevent TikTok re-encoding entirely (server-side policy).

## Current Best Approach
**Minimal approach** (in `inflate_stsz_only`):
1. Inflate only stsz entry count (append zero-size entries)
2. Inflate only stts entry count (append entries with avg_delta)
3. Set mvhd/tkhd/mdhd durations to match new stsz count
4. Keep original stco/stsc UNCHANGED
5. File plays locally (948 real frames, decoder ignores extra stsz entries)
6. TikTok sees consistent stsz=6323, mvhd=105s ratio, doesn't double duration

**For best results**: also add fingerprinting patches (stsd codec avc1→avc3, ftyp brand, mvhd fingerprint, edit list rebuild).

## Relevant Files
- `C:\Users\Akila\AppData\Local\Temp\opencode\gen_tikquick.py`: `inflate_stsz_only` with current best approach.
- `E:\New folder (7)\New folder (9)\patcher_core.py`: core patching functions.
- `E:\Movies\test_tikquick_stsz.mp4`: output file.
- `E:\Movies\Video 202sasgwrg6.mp4`: original source file.
