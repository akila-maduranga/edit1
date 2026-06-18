#!/usr/bin/env python3
"""
NoBlur-style TikTok bypass patcher — standalone CLI.

Delegates all patching to patcher_core.patch_all (7-pass pipeline).
"""

import sys
import argparse
from patcher_core import patch_all


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="NoBlur TikTok Patcher CLI")
    p.add_argument("input", help="Input MP4 file")
    p.add_argument("-o", "--output", default="patched_output.mp4", help="Output path")
    p.add_argument("--comment", default=None,
                   help="\xa9cmt comment (default: auto-generated timestamped tag)")
    p.add_argument("--no-inflate", action="store_true",
                   help="Disable frame count inflation; use brand/bitrate spoofing instead")
    p.add_argument("--brand-only", action="store_true",
                   help="Skip avc3, only spoof ftyp brand to M4VH")
    p.add_argument("--minimal", action="store_true",
                   help="Skip mvhd/udta/tkhd passes; only remux + brand + bitrate")
    args = p.parse_args()

    def log(msg):
        print(msg)

    ok = patch_all(args.input, args.output, comment=args.comment, log_func=log,
                   use_inflation=not args.no_inflate,
                   brand_spoof_only=args.brand_only,
                   minimal=args.minimal)
    sys.exit(0 if ok else 1)
