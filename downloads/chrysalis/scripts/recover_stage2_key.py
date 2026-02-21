#!/usr/bin/env python3
"""
Recover the 8-byte XOR/add/sub key used by the stage1 loader to decrypt the "main module"
regions described in the 25-dword arg struct.

Why this works:
- The transform uses k = key[i & 7] with i starting at 0 for each region.
- That means each key byte only affects bytes at positions with the same (i mod 8) within
  each region, so we can do coordinate ascent over the 8 lanes.

This stays fully offline (no Unicorn).
"""

from __future__ import annotations

import argparse
import hashlib
import math
from collections import Counter
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_32


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def entropy(b: bytes) -> float:
    if not b:
        return 0.0
    c = Counter(b)
    n = len(b)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def parse_arg_struct(arg_str: str) -> list[int]:
    parts = [p.strip() for p in arg_str.replace("\n", " ").replace(",", " ").split(" ") if p.strip()]
    vals: list[int] = []
    for p in parts:
        if p.lower().startswith("0x"):
            vals.append(int(p, 16))
        else:
            vals.append(int(p, 10))
    if len(vals) != 25:
        raise ValueError(f"Expected 25 dwords, got {len(vals)}")
    return vals


def transform_byte(x: int, k: int) -> int:
    # Rapid7 pseudocode: x = x + k; x = x ^ k; x = x - k
    x = (x + k) & 0xFF
    x ^= k
    x = (x - k) & 0xFF
    return x


def decrypt_regions(stage1: bytes, pos_list: list[int], size_list: list[int], key: bytes) -> bytes:
    out_size = max(p + s for p, s in zip(pos_list, size_list))
    buf = bytearray(out_size)

    # Backing store: stage1 is a 2MB "full dump" so offsets align with these pos values.
    for p, s in zip(pos_list, size_list):
        end = p + s
        if end <= len(stage1):
            buf[p:end] = stage1[p:end]
        else:
            if p < len(stage1):
                buf[p:len(stage1)] = stage1[p:len(stage1)]

    for p, s in zip(pos_list, size_list):
        for i in range(s):
            k = key[i & 7]
            buf[p + i] = transform_byte(buf[p + i], k)

    return bytes(buf)


def score_decrypted(buf: bytes, text_rva: int, text_len: int) -> float:
    """
    Heuristic score: prefer buffers that disassemble cleanly in .text and contain some
    printable strings. This doesn't need to be perfect; it just needs to be monotonic-ish.
    """
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = False

    text = buf[text_rva : min(len(buf), text_rva + text_len)]
    if not text:
        return -1e9

    # Disassembly coverage.
    total = 0
    insn = 0
    bad_mnems = {
        "int",
        "into",
        "iret",
        "iretd",
        "in",
        "out",
        "hlt",
        "cli",
        "sti",
        "retf",
        "bound",
        "das",
        "aaa",
        "aas",
        "aam",
        "aad",
        "salc",
        "ljmp",
        "lds",
        "les",
    }
    bad = 0
    for i in md.disasm(text, 0x400000 + text_rva):
        insn += 1
        total += i.size
        if i.mnemonic in bad_mnems:
            bad += 1
        if total >= len(text):
            break

    coverage = total / max(1, len(text))
    bad_rate = bad / max(1, insn)

    # Printable strings proxy: proportion of bytes in full buffer that are ASCII-ish.
    # (Keep it cheap; do not run full strings extraction.)
    sample = buf[: min(len(buf), 0x40000)]
    printable = sum(1 for b in sample if 0x20 <= b <= 0x7E)
    pr = printable / max(1, len(sample))

    # Penalize very high entropy (often indicates we're still encrypted/compressed).
    ent = entropy(sample)

    return (coverage * 200.0) + (pr * 50.0) - (bad_rate * 200.0) - (ent * 2.0)


def main() -> int:
    ap = argparse.ArgumentParser(description="Recover the 8-byte stage2 decrypt key (offline)")
    ap.add_argument("--stage1", required=True, help="Path to stage1 full dump (output/shellcode_full.bin)")
    ap.add_argument("--arg-struct", required=True, help="25 dwords (space/comma separated)")
    ap.add_argument("--text-rva", type=lambda s: int(s, 0), default=0x1000, help="RVA to score disassembly at (default 0x1000)")
    ap.add_argument("--text-len", type=lambda s: int(s, 0), default=0x8000, help="Length to disassemble for scoring (default 0x8000)")
    ap.add_argument("--passes", type=int, default=2, help="Coordinate-ascent passes (default 2)")
    ap.add_argument("--out", default="output/stage2_recovered.bin", help="Output decrypted buffer path")
    args = ap.parse_args()

    stage1 = Path(args.stage1).read_bytes()
    words = parse_arg_struct(args.arg_struct)

    pos_list = words[2:7]
    size_list = words[9:14]

    # Start from the Rapid7 key as a prior, but we'll still optimize each byte.
    key = bytearray(b"gQ2JR&9;")

    print(f"[+] stage1={args.stage1} len=0x{len(stage1):X}")
    print(f"[+] pos_list={[hex(x) for x in pos_list]}")
    print(f"[+] size_list={[hex(x) for x in size_list]} total=0x{sum(size_list):X}")

    best_score = None
    for p in range(args.passes):
        print(f"[+] pass {p+1}/{args.passes}")
        for lane in range(8):
            lane_best = None  # (score, k)
            # Try all 256 for this lane, keeping others fixed.
            for k in range(256):
                cand = bytearray(key)
                cand[lane] = k
                buf = decrypt_regions(stage1, pos_list, size_list, bytes(cand))
                s = score_decrypted(buf, args.text_rva, args.text_len)
                if lane_best is None or s > lane_best[0]:
                    lane_best = (s, k)
            assert lane_best is not None
            key[lane] = lane_best[1]
            best_score = lane_best[0]
            ch = key[lane]
            printable = chr(ch) if 0x20 <= ch <= 0x7E else "."
            print(f"    lane {lane}: k=0x{ch:02X} ({printable}) score={lane_best[0]:.2f}")

    final = decrypt_regions(stage1, pos_list, size_list, bytes(key))
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(final)
    print(f"[+] key={bytes(key)!r} sha256={sha256_bytes(bytes(key))}")
    print(f"[+] wrote {len(final)} bytes to {out_path} sha256={sha256_bytes(final)} ent={entropy(final[: min(len(final), 0x40000)]):.3f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

