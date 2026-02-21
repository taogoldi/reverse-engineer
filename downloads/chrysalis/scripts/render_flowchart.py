#!/usr/bin/env python3
"""
Render pipeline_flowchart.dot to PNG (requires Graphviz 'dot').

We keep the DOT in-repo so the flowchart is versionable and can be edited.
On macOS you can install Graphviz via Homebrew:
  brew install graphviz

Then:
  python render_flowchart.py --out output/pipeline_flowchart.png
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
from pathlib import Path
from typing import Optional


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Render pipeline_flowchart.dot to a PNG using graphviz.")
    ap.add_argument("--dot", default="docs/pipeline_flowchart.dot", help="Input DOT file")
    ap.add_argument("--out", default="output/pipeline_flowchart.png", help="Output PNG path")
    args = ap.parse_args(argv)

    dot_exe = shutil.which("dot")
    if not dot_exe:
        print("[!] Graphviz 'dot' was not found on PATH.")
        print("[!] Install graphviz (e.g. 'brew install graphviz'), then rerun.")
        print(f"    dot -Tpng {args.dot} -o {args.out}")
        return 2

    dot_path = Path(args.dot)
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    subprocess.check_call([dot_exe, "-Tpng", str(dot_path), "-o", str(out_path)])
    print(f"[+] Wrote {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
