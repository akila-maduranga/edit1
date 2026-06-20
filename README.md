# TikTok MP4 Patcher

Frame-count inflation tool that prevents TikTok from re-encoding uploaded
videos by making the encoder see an unusually high frame count.

## How it works

TikTok's encoder skips re-encoding when it encounters a frame count well
above its expected range. This tool inflates the video track's sample table
(stts/stsz/stco) by 5×, appending H.264 filler NALs to the mdat box so
each fake frame has valid (but empty) data. The encoder passes the file
through without re-encoding.

**Trade-off:** The inflated stts table adds ~31s of frozen-last-frame at
the end of a 16s video (freeze ≈ real_duration × 2). This is inherent to
the approach — TikTok always plays all stts entries.

## Pipeline

1. **moov relocate** — moves moov atom to front of file (Python-based,
   no ffmpeg dependency for remux)
2. **mvhd fingerprint** — randomizes creation/modification times and
   next_track_id to break surface-level fingerprints
3. **udta strip** — removes ffmpeg/HandBrake encoder tags from user-data
4. **tkhd fingerprint** — sets alternate_group to avoid track dedup
5. **Frame inflation** — 5× sample table expansion with 512B NAL filler,
   fake_delta=750, container durations clipped to real content
6. **Comment injection** — embeds iTunes-style metadata comment
7. **Audio duration fix** — restores original audio track duration

## Requirements

- Python 3.10+
- `ffmpeg` on PATH (for `app.py` remux only; CLI works without it)

## Quick start (CLI)

```bash
python patcher.py input.mp4 -o output.mp4 --inflate
```

Flags:
- `--inflate` — enable frame-count inflation (required for no-compress)
- `--comment` — set metadata comment (default: `@akila`)
- `-o` — output path (default: `patched_output.mp4`)

## Quick start (Web UI)

```bash
pip install -r requirements.txt
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
