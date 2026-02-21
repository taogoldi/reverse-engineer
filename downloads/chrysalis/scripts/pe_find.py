#!/usr/bin/env python3
"""
Small helper to find constants/strings in a PE file and map file offsets -> RVA/VA.

This is useful for quickly navigating in a disassembler (Ghidra/IDA) when you
only have an on-disk offset.
"""

from __future__ import annotations

import argparse
import struct
from pathlib import Path
from typing import Optional

import pefile


def find_all(hay: bytes, needle: bytes) -> list[int]:
    out: list[int] = []
    start = 0
    while True:
        i = hay.find(needle, start)
        if i == -1:
            return out
        out.append(i)
        start = i + 1


def off_to_rva(pe: pefile.PE, off: int) -> Optional[int]:
    try:
        return pe.get_rva_from_offset(off)
    except Exception:
        return None


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Find values in a PE and map offsets to RVA/VA.")
    ap.add_argument("pe", help="Path to PE file")
    ap.add_argument("--u32", action="append", default=[], help="Find a 32-bit little-endian value (hex or dec).")
    ap.add_argument("--u16", action="append", default=[], help="Find a 16-bit little-endian value (hex or dec).")
    ap.add_argument("--bytes", dest="hexbytes", action="append", default=[], help="Find raw bytes as hex, e.g. DEADBEEF")
    ap.add_argument("--ascii", action="append", default=[], help="Find ASCII string")
    args = ap.parse_args(argv)

    p = Path(args.pe)
    b = p.read_bytes()
    pe = pefile.PE(str(p), fast_load=False)
    imgbase = pe.OPTIONAL_HEADER.ImageBase

    def report(kind: str, needle_desc: str, offs: list[int]) -> None:
        print(f"[+] {kind} {needle_desc}: {len(offs)} hit(s)")
        for off in offs[:50]:
            rva = off_to_rva(pe, off)
            if rva is None:
                print(f"    off=0x{off:X} rva=? va=?")
            else:
                print(f"    off=0x{off:X} rva=0x{rva:X} va=0x{(imgbase + rva):X}")
        if len(offs) > 50:
            print("    ... (truncated)")

    for s in args.u32:
        v = int(s, 0) & 0xFFFFFFFF
        needle = struct.pack("<I", v)
        offs = find_all(b, needle)
        report("u32", f"0x{v:X}", offs)

    for s in args.u16:
        v = int(s, 0) & 0xFFFF
        needle = struct.pack("<H", v)
        offs = find_all(b, needle)
        report("u16", f"0x{v:X}", offs)

    for s in args.hexbytes:
        hs = s.strip().replace(" ", "")
        if len(hs) % 2 != 0:
            raise SystemExit(f"bad --bytes hex length: {s!r}")
        needle = bytes.fromhex(hs)
        offs = find_all(b, needle)
        report("bytes", hs.upper(), offs)

    for s in args.ascii:
        needle = s.encode("ascii", errors="ignore")
        offs = find_all(b, needle)
        report("ascii", repr(s), offs)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

