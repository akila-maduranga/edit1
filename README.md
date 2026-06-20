# TikTok MP4 Patcher

Prevents TikTok's duration-doubling bug when uploading stsz-inflated MP4 files.
TikTok **always re-encodes** uploaded videos regardless of file structure.

## How it works

TikTok has a bug where it doubles the reported duration when stsz entry count
exceeds the actual frame count. This tool inflates the sample table while
keeping all duration fields (mvhd/tkhd/mdhd) consistent with the inflated count,
preventing the duration-doubling bug.

**Minimal approach:** inflate stts+stsz entry counts, set mvhd/tkhd/mdhd durations
to match the new count. Keep original stco/stsc unchanged. Decoders ignore extra
entries since no actual data is referenced.

## Pipeline

1. **moov relocate** — moves moov atom to front of file (pure Python)
2. **mvhd fingerprint** — randomizes creation/modification times and
   next_track_id to avoid fingerprinting
3. **udta strip** — removes ffmpeg/HandBrake encoder tags
4. **tkhd fingerprint** — sets alternate_group for all tracks to same ID
5. **Bypass method** (choose one):
   - `inflate` — inflate stts/stsz count (default 5×)
   - `balanced-sync` — divide timescale + add playback-speed edit list
   - `codec-spoof` — avc1→avc3, M4VH brand, fingerprint patches
6. **Comment injection** — embeds iTunes-style metadata comment
7. **Audio duration fix** — restores original audio track duration

## Requirements

- Python 3.10+

## Quick start (CLI)

```bash
python patcher.py input.mp4 -o output.mp4 --method balanced-sync
```

Flags:
- `--method` — bypass method: `balanced-sync` (default), `inflate`, or `codec-spoof`
- `--comment` — set metadata comment
- `-o` — output path (default: `patched_output.mp4`)

## Quick start (Web UI)

```bash
pip install -r requirements.txt
export PATCHER_AUTH_TOKEN=mysecret   # optional auth
python app.py          # http://0.0.0.0:5000
```

## File layout

```
patcher_core.py          # Core binary patching engine
patcher.py               # CLI entry point
app.py                   # Flask web UI
templates/index.html     # Single-page upload UI
uploads/                 # Temp upload dir (auto-cleaned)
outputs/                 # Patched files (served for download)
requirements.txt
tiktok-patcher.service   # systemd unit (VPS)
nginx.conf               # Nginx reverse-proxy snippet (VPS)
```
