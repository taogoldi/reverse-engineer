#!/usr/bin/env python3
"""
Decrypt Chrysalis configuration from the encrypted "BluetoothService" blob.

Per Rapid7 (The Chrysalis Backdoor: A Deep Dive into Lotus Blossom’s toolkit):
  - Encrypted configuration is stored in the BluetoothService file at offset 0x30808
  - Size is 0x980 bytes
  - Algorithm: RC4
  - Key: qwhvb^435h&*7

In this repo, the BluetoothService blob is typically: input/encrypted_shellcode.bin
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path


def rc4_crypt(data: bytes, key: bytes) -> bytes:
    if not key:
        raise ValueError("RC4 key must be non-empty")

    # KSA
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 0xFF
        s[i], s[j] = s[j], s[i]

    # PRGA
    out = bytearray(len(data))
    i = 0
    j = 0
    for n, b in enumerate(data):
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        k = s[(s[i] + s[j]) & 0xFF]
        out[n] = b ^ k
    return bytes(out)


def extract_printable_strings(buf: bytes, min_len: int = 4) -> list[str]:
    # ASCII-ish strings; avoids pulling tons of junk.
    pat = rb"[ -~]{%d,}" % int(min_len)
    return [m.group(0).decode("ascii", errors="replace") for m in re.finditer(pat, buf)]


def main() -> int:
    ap = argparse.ArgumentParser(description="Decrypt Chrysalis config from BluetoothService blob (RC4)")
    ap.add_argument("--in", dest="in_path", default="input/encrypted_shellcode.bin", help="Input BluetoothService blob path")
    ap.add_argument("--off", type=lambda s: int(s, 0), default=0x30808, help="Config offset (default 0x30808)")
    ap.add_argument("--size", type=lambda s: int(s, 0), default=0x980, help="Config size (default 0x980)")
    ap.add_argument("--key", default="qwhvb^435h&*7", help="RC4 key (default from Rapid7)")
    ap.add_argument("--out", default="output/config_decrypted.bin", help="Write decrypted bytes here")
    args = ap.parse_args()

    inp = Path(args.in_path)
    raw = inp.read_bytes()
    if args.off < 0 or args.size <= 0 or args.off + args.size > len(raw):
        raise SystemExit(f"Config range out of bounds: off=0x{args.off:X} size=0x{args.size:X} file=0x{len(raw):X}")

    enc = raw[args.off : args.off + args.size]
    dec = rc4_crypt(enc, args.key.encode("ascii", errors="ignore"))

    outp = Path(args.out)
    outp.parent.mkdir(parents=True, exist_ok=True)
    outp.write_bytes(dec)

    print(f"[+] Input: {inp} (len=0x{len(raw):X})")
    print(f"[+] Decrypted config: off=0x{args.off:X} size=0x{args.size:X} -> {outp}")
    print(f"[+] Key: {args.key!r}")
    print("[+] Printable strings (min_len=4):")
    for s in extract_printable_strings(dec, min_len=4)[:200]:
        print(f"    {s}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

