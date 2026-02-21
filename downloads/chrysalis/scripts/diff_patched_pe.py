#!/usr/bin/env python3
"""
Diff an original container PE vs a patched PE and report the changed ranges.

Why this exists:
- `main_module_patched.exe` is still the Bitdefender container, so it's noisy.
- The malware-relevant bytes are the *changed* regions.
- This script gives you exact file offsets and RVA/VA mappings to jump to in IDA/Ghidra.

It groups contiguous changed bytes into ranges and writes:
- human-readable text summary
- JSON ranges for tooling
"""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import pefile


@dataclass
class Range:
    start: int  # inclusive file offset
    end: int    # exclusive file offset

    @property
    def size(self) -> int:
        return self.end - self.start


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def group_changed_ranges(orig: bytes, patched: bytes) -> list[Range]:
    if len(orig) != len(patched):
        raise ValueError(f"size mismatch: orig={len(orig)} patched={len(patched)}")

    out: list[Range] = []
    i = 0
    n = len(orig)
    while i < n:
        if orig[i] == patched[i]:
            i += 1
            continue
        start = i
        i += 1
        while i < n and orig[i] != patched[i]:
            i += 1
        out.append(Range(start=start, end=i))
    return out


def safe_rva(pe: pefile.PE, off: int) -> Optional[int]:
    try:
        return pe.get_rva_from_offset(off)
    except Exception:
        return None


def section_for_rva(pe: pefile.PE, rva: int) -> Optional[str]:
    try:
        for s in pe.sections:
            va = s.VirtualAddress
            vsz = max(s.Misc_VirtualSize, s.SizeOfRawData)
            if va <= rva < va + vsz:
                return s.Name.rstrip(b"\x00").decode("ascii", errors="ignore") or None
    except Exception:
        pass
    return None


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Diff original vs patched PE and report changed file ranges with RVA/VA mapping.")
    ap.add_argument("--orig", default="input/BluetoothService.exe", help="Original container PE path")
    ap.add_argument("--patched", default="output/main_module_patched.exe", help="Patched PE path")
    ap.add_argument("--out-prefix", default="output/patched_diff", help="Output prefix (writes .txt and .json)")
    ap.add_argument("--max-ranges", type=int, default=2000, help="Stop after this many ranges (safety)")
    args = ap.parse_args(argv)

    orig_p = Path(args.orig)
    patched_p = Path(args.patched)
    out_prefix = Path(args.out_prefix)
    out_prefix.parent.mkdir(parents=True, exist_ok=True)

    ob = orig_p.read_bytes()
    pb = patched_p.read_bytes()

    ranges = group_changed_ranges(ob, pb)
    if len(ranges) > args.max_ranges:
        raise SystemExit(f"too many ranges ({len(ranges)}) > --max-ranges ({args.max_ranges}); refusing")

    pe = pefile.PE(str(patched_p), fast_load=False)
    imgbase = pe.OPTIONAL_HEADER.ImageBase

    total_changed = sum(r.size for r in ranges)

    # Write JSON
    json_path = out_prefix.with_suffix(".json")
    json_ranges = []
    for r in ranges:
        rva = safe_rva(pe, r.start)
        sec = section_for_rva(pe, rva) if rva is not None else None
        json_ranges.append(
            {
                "file_off_start": r.start,
                "file_off_end": r.end,
                "size": r.size,
                "rva": rva,
                "va": (imgbase + rva) if rva is not None else None,
                "section": sec,
            }
        )
    json_path.write_text(json.dumps(
        {
            "orig": str(orig_p),
            "patched": str(patched_p),
            "orig_sha256": sha256_bytes(ob),
            "patched_sha256": sha256_bytes(pb),
            "num_ranges": len(ranges),
            "total_changed_bytes": total_changed,
            "ranges": json_ranges,
        },
        indent=2,
    ) + "\n")

    # Write TXT
    txt_path = out_prefix.with_suffix(".txt")
    lines: list[str] = []
    lines.append(f"orig:    {orig_p} sha256={sha256_bytes(ob)} size={len(ob)}")
    lines.append(f"patched: {patched_p} sha256={sha256_bytes(pb)} size={len(pb)}")
    lines.append(f"ranges:  {len(ranges)} total_changed_bytes={total_changed}")
    lines.append("")
    lines.append("index  off_start  off_end    size    rva       va        section")
    for idx, r in enumerate(ranges):
        rva = safe_rva(pe, r.start)
        sec = section_for_rva(pe, rva) if rva is not None else ""
        if rva is None:
            lines.append(f"{idx:5d}  0x{r.start:08X} 0x{r.end:08X} 0x{r.size:06X}  {'?':<8} {'?':<10} {sec}")
        else:
            va = imgbase + rva
            lines.append(f"{idx:5d}  0x{r.start:08X} 0x{r.end:08X} 0x{r.size:06X}  0x{rva:06X} 0x{va:08X} {sec}")
    txt_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"[+] Wrote {txt_path} and {json_path}")
    print(f"[+] num_ranges={len(ranges)} total_changed_bytes=0x{total_changed:X}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

