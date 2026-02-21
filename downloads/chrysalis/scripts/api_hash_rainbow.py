#!/usr/bin/env python3
"""
Build a rainbow table for the Chrysalis/log.dll loader API hashing scheme.

This script is intended to be run on Windows against DLLs such as:
  C:\\Windows\\System32\\*.dll

Why your old rainbow table didn't match `log.dll` immediates
-----------------------------------------------------------
In the Rapid7 Chrysalis chain, `log.dll` does NOT use a fixed salt like
`hash(kernel32.dll)` for its loader API resolver.

Instead, `log.dll` derives a per-host "seed" by hashing the first 0x100 bytes of
the host EXE (GetModuleHandleA(NULL)). In Rapid7's sample, that host EXE is
BluetoothService.exe (a renamed Bitdefender tool used for DLL sideloading).

Disassembly (init @ 0x10001016) shows:
  - read base = GetModuleHandleA(NULL)
  - hash bytes [base:base+0x100] with FNV-1a
  - apply a Murmur-style finalizer
  - store as global seed

Then the resolver (0x100014E0) hashes export names and compares:
    api_hash(export_name) == seed + target_constant

Therefore the constants embedded in `log.dll` are effectively:
    target_constant = api_hash(export_name) - seed   (mod 2^32)

This script computes *that* `target_constant` by default (output-mode=constant).

Hashing details (as observed in this sample)
--------------------------------------------
FNV-1a:
  basis = 0x811C9DC5
  prime = 0x01000193

Finalizer (observed constant 0x85EBCA6B):
    x = h ^ (h >> 15)
    x = x * 0x85EBCA6B
    x = x ^ (x >> 13)

Outputs
-------
- JSONL: one record per export
- nested JSON: { "dllname.dll": { "0xDEADBEEF": "ExportName", ... }, ... }
  Collisions are stored as a list.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Iterator, Optional

import pefile

FNV1A_BASIS_32 = 0x811C9DC5
FNV1A_PRIME_32 = 0x01000193


def u32(x: int) -> int:
    return x & 0xFFFFFFFF


def fnv1a32(data: bytes, basis: int = FNV1A_BASIS_32, prime: int = FNV1A_PRIME_32) -> int:
    h = u32(basis)
    for b in data:
        h ^= b
        h = u32(h * prime)
    return u32(h)


def chrysalis_loader_finalizer32(h: int) -> int:
    """
    Finalizer observed in log.dll's resolver (0x100014E0):
      eax = h
      eax >>= 0xF
      eax ^= h
      eax *= 0x85EBCA6B
      esi = eax
      esi >>= 0xD
      esi ^= eax
    """
    h = u32(h)
    x = u32(h ^ (h >> 15))
    x = u32(x * 0x85EBCA6B)
    x = u32(x ^ (x >> 13))
    return u32(x)


def api_hash_export_name(export_name: str) -> int:
    return chrysalis_loader_finalizer32(fnv1a32(export_name.encode("ascii", errors="ignore")))


def seed_from_host_image(image_bytes: bytes, *, seed_len: int = 0x100) -> int:
    """
    Seed derivation used by log.dll init:
      seed = finalizer(fnv1a(host_bytes[:0x100]))

    The host bytes are from the main module (GetModuleHandleA(NULL)),
    i.e. the sideloading EXE in the Rapid7 chain.
    """
    return chrysalis_loader_finalizer32(fnv1a32(image_bytes[:seed_len]))


def iter_export_names(dll_path: Path) -> Iterator[str]:
    try:
        pe = pefile.PE(str(dll_path), fast_load=True)
    except Exception:
        return

    try:
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]]
        )
    except Exception:
        return

    if not hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        return

    for sym in pe.DIRECTORY_ENTRY_EXPORT.symbols:  # type: ignore
        if sym.name is None:
            continue
        try:
            name = sym.name.decode("ascii", errors="ignore")
        except Exception:
            continue
        if name:
            yield name


def iter_dlls(root: Path, recursive: bool) -> Iterator[Path]:
    if root.is_file():
        yield root
        return
    it = root.rglob("*.dll") if recursive else root.glob("*.dll")
    for p in it:
        if p.is_file():
            yield p


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        description="Generate a hash->export rainbow table for the Chrysalis/log.dll loader hashing."
    )
    ap.add_argument(
        "--dll-dir",
        default=r"C:\Windows\System32" if os.name == "nt" else ".",
        help="Directory containing DLLs (default: C:\\Windows\\System32 on Windows). "
        "You can also pass a single DLL file path.",
    )
    ap.add_argument("--recursive", action="store_true", help="Recurse into subdirectories.")
    ap.add_argument(
        "--out",
        default="api_hash_rainbow.jsonl",
        help="Output path (default: api_hash_rainbow.jsonl).",
    )
    ap.add_argument(
        "--format",
        choices=["jsonl", "nested"],
        default="jsonl",
        help="Output format. 'jsonl' writes one record per export. "
        "'nested' writes a single JSON mapping {dll:{hash:export}}.",
    )

    ap.add_argument(
        "--seed",
        default=None,
        help="Seed value used by the loader (hex like 0x1234 or decimal). "
        "If omitted, and --seed-from-image is provided, the seed will be derived from that image. "
        "If neither is provided, seed=0 (won't match log.dll constants).",
    )
    ap.add_argument(
        "--seed-from-image",
        default=None,
        help="Derive seed from the first 0x100 bytes of this EXE/DLL (host image). "
        "In Rapid7's sample, use BluetoothService.exe.",
    )
    ap.add_argument(
        "--seed-len",
        default="0x100",
        help="Bytes used to derive the seed from --seed-from-image (default: 0x100).",
    )

    ap.add_argument(
        "--output-mode",
        choices=["constant", "raw"],
        default="constant",
        help="'constant' emits values that match log.dll immediates (api_hash - seed). "
        "'raw' emits api_hash(export_name) without subtracting the seed.",
    )

    ap.add_argument(
        "--validate",
        action="append",
        default=[],
        metavar="NAME=HASH",
        help="Optional: validate settings by checking a known pair, e.g. "
        "--validate VirtualProtect=0x47C204CA (constants mode) or "
        "--validate VirtualProtect=0x590FDFFD (raw mode).",
    )

    args = ap.parse_args(argv)

    seed = 0
    if args.seed is not None:
        seed = int(args.seed, 0) & 0xFFFFFFFF
    elif args.seed_from_image:
        seed_len = int(args.seed_len, 0)
        seed = seed_from_host_image(Path(args.seed_from_image).read_bytes(), seed_len=seed_len)
        print(f"[*] Derived seed from {args.seed_from_image}[:0x{seed_len:X}] = 0x{seed:08X}")

    out_path = Path(args.out)
    root = Path(args.dll_dir)

    def compute_value(exp: str) -> int:
        raw = api_hash_export_name(exp)
        if args.output_mode == "raw":
            return raw
        return u32(raw - seed)

    if args.validate:
        for item in args.validate:
            if "=" not in item:
                print(f"[!] Bad --validate '{item}' (expected NAME=HASH)")
                continue
            name, want_s = item.split("=", 1)
            want = int(want_s, 0) & 0xFFFFFFFF
            got = compute_value(name)
            print(
                f"[*] validate {name}: got=0x{got:08X} want=0x{want:08X} "
                f"{'OK' if got == want else 'MISMATCH'}"
            )

    count_syms = 0
    count_dlls = 0

    out_path.parent.mkdir(parents=True, exist_ok=True)

    if args.format == "jsonl":
        with out_path.open("w", encoding="utf-8") as f:
            for dll in iter_dlls(root, args.recursive):
                count_dlls += 1
                dll_name = dll.name
                for exp in iter_export_names(dll):
                    hv = compute_value(exp)
                    rec = {
                        "hash": f"0x{hv:08X}",
                        "dll": dll_name,
                        "export": exp,
                        "seed": f"0x{seed:08X}",
                        "mode": args.output_mode,
                    }
                    f.write(json.dumps(rec) + "\n")
                    count_syms += 1
    else:
        table: dict[str, dict[str, str | list[str]]] = {}
        for dll in iter_dlls(root, args.recursive):
            count_dlls += 1
            dll_name = dll.name
            inner = table.setdefault(dll_name, {})
            for exp in iter_export_names(dll):
                hv = compute_value(exp)
                hk = f"0x{hv:08X}"
                prev = inner.get(hk)
                if prev is None:
                    inner[hk] = exp
                else:
                    if isinstance(prev, list):
                        prev.append(exp)
                    else:
                        inner[hk] = [prev, exp]
                count_syms += 1
        out_path.write_text(json.dumps(table, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print(f"[+] seed=0x{seed:08X} mode={args.output_mode}")
    print(f"[+] Wrote {count_syms} exports from {count_dlls} DLL(s) -> {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

