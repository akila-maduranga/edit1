#!/usr/bin/env python3
"""
TikTok MP4 Patcher — standalone CLI.

Delegates all patching to patcher_core.patch_all (7-pass pipeline).
Optionally re-encodes with TikQuick-quality ffmpeg settings.
"""

import sys
import argparse
from pathlib import Path
from patcher_core import patch_all, tikquick_encode


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="TikQuick TikTok Patcher CLI")
    p.add_argument("input", help="Input MP4 file")
    p.add_argument("-o", "--output", default="patched_output.mp4", help="Output path")
    p.add_argument("--comment", default=None,
                   help="\xa9cmt comment (default: none)")
    p.add_argument("--method", default="balanced-sync", choices=["balanced-sync", "inflate", "codec-spoof"],
                   help="Bypass method (default: balanced-sync)")
    p.add_argument("--inflate", action="store_true",
                   help="Enable frame count inflation (equivalent to --method inflate)")
    p.add_argument("--encode", action="store_true",
                   help="Re-encode with TikQuick-quality ffmpeg settings after patching")
    args = p.parse_args()

    def log(msg):
        print(msg)

    method = "inflate" if args.inflate else args.method

    if args.encode:
        inter = Path(args.input).stem + "_patched_tmp.mp4"
        ok = patch_all(args.input, inter, comment=args.comment, log_func=log, method=method)
        if not ok:
            sys.exit(1)
        ok = tikquick_encode(inter, args.output, log_func=log)
        Path(inter).unlink(missing_ok=True)
    else:
        ok = patch_all(args.input, args.output, comment=args.comment, log_func=log, method=method)

    sys.exit(0 if ok else 1)
