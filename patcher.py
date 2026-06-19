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
                   help="\xa9cmt comment (default: none)")
    p.add_argument("--no-inflate", action="store_true",
                   help="Disable frame count inflation; use codec/brand spoofing instead")
    args = p.parse_args()

    def log(msg):
        print(msg)

    ok = patch_all(args.input, args.output, comment=args.comment, log_func=log,
                   use_inflation=not args.no_inflate)
    sys.exit(0 if ok else 1)
