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
    p.add_argument("--multiplier", type=int, default=2, choices=[1, 2, 3, 4, 5],
                   help="Frame inflation multiplier (default: 2)")
    p.add_argument("--no-edts", action="store_true",
                   help="Skip edts/elst ZeroLoss bypass")
    p.add_argument("--mvhd", action="store_true",
                   help="Enable mvhd matrix patch")
    p.add_argument("--tkhd", action="store_true",
                   help="Enable tkhd matrix reset")
    args = p.parse_args()

    def log(msg):
        print(msg)

    ok = patch_all(
        args.input, args.output,
        comment=args.comment, log_func=log,
        multiplier=args.multiplier,
        edts_bypass=not args.no_edts,
        mvhd_patch=args.mvhd,
        tkhd_reset=args.tkhd,
    )
    sys.exit(0 if ok else 1)
