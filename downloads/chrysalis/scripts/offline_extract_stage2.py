#!/usr/bin/env python3
"""
Offline attempt to reconstruct/decrypt the Chrysalis "main module" (stage2) from stage1.

Based on the Rapid7 pseudocode you pasted:

    x = encrypted[pos]
    x = x + k
    x = x ^ k
    x = x - k
    decrypted[pos] = x

...performed 5 times over 5 (BufferPosition, size) regions.

We don't rely on Unicorn here. Instead we:
1) Reconstruct an "encrypted module buffer" using a chosen strategy.
2) Apply the exact decrypt loop on the 5 regions in-place.
3) Save the result and scan for PE headers.
"""

import argparse
import hashlib
import math
import struct
from collections import Counter
from pathlib import Path
from typing import Iterable


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


def looks_like_pe(buf: bytes, off: int) -> bool:
    if off < 0 or off + 0x100 > len(buf):
        return False
    if buf[off : off + 2] != b"MZ":
        return False
    e_lfanew = struct.unpack_from("<I", buf, off + 0x3C)[0]
    if e_lfanew > 0x2000:
        return False
    pe_off = off + e_lfanew
    if pe_off + 4 > len(buf):
        return False
    return buf[pe_off : pe_off + 4] == b"PE\x00\x00"


def find_pe_offsets(buf: bytes, max_hits: int = 20) -> list[int]:
    hits: list[int] = []
    start = 0
    while len(hits) < max_hits:
        off = buf.find(b"MZ", start)
        if off == -1:
            break
        if looks_like_pe(buf, off):
            hits.append(off)
        start = off + 1
    return hits


def decrypt_region_in_place(buf: bytearray, pos: int, size: int, key: bytes):
    for i in range(size):
        k = key[i & 7]
        x = buf[pos + i]
        x = (x + k) & 0xFF
        x = x ^ k
        x = (x - k) & 0xFF
        buf[pos + i] = x


def decrypt_byte(x: int, k: int) -> int:
    x = (x + k) & 0xFF
    x = x ^ k
    x = (x - k) & 0xFF
    return x


def parse_pe_sections(raw: bytes) -> tuple[int, int, int, list[dict]]:
    """
    Return (image_base, size_of_headers, size_of_image, sections[]).
    Each section dict has: va, vsz, raw, rsz.
    Minimal PE32 parser, enough for RVA<->RAW mapping.
    """
    if raw[:2] != b"MZ" or len(raw) < 0x200:
        raise ValueError("Not a PE (missing MZ)")
    pe_off = struct.unpack_from("<I", raw, 0x3C)[0]
    if pe_off + 4 + 20 > len(raw) or raw[pe_off : pe_off + 4] != b"PE\x00\x00":
        raise ValueError("Not a PE (missing PE signature)")
    coff_off = pe_off + 4
    _, nsects, _, _, _, opt_size, _ = struct.unpack_from("<HHIIIHH", raw, coff_off)
    opt_off = coff_off + 20
    if opt_off + opt_size > len(raw):
        raise ValueError("Truncated PE optional header")
    magic = struct.unpack_from("<H", raw, opt_off)[0]
    if magic != 0x10B:
        raise ValueError(f"Unsupported PE magic {hex(magic)} (expected PE32 0x10B)")
    image_base = struct.unpack_from("<I", raw, opt_off + 28)[0]
    size_of_image = struct.unpack_from("<I", raw, opt_off + 56)[0]
    size_of_headers = struct.unpack_from("<I", raw, opt_off + 60)[0]

    sect_off = opt_off + opt_size
    sections: list[dict] = []
    for i in range(nsects):
        off = sect_off + i * 40
        if off + 40 > len(raw):
            break
        vsz, va, rsz, rptr = struct.unpack_from("<IIII", raw, off + 8)
        sections.append({"va": va, "vsz": vsz, "raw": rptr, "rsz": rsz})
    sections.sort(key=lambda s: s["va"])
    return image_base, size_of_headers, size_of_image, sections


def rva_to_raw(rva: int, size_of_headers: int, sections: list[dict]) -> int | None:
    # Headers are typically 1:1 for RVA==RAW within SizeOfHeaders.
    if 0 <= rva < size_of_headers:
        return rva
    for s in sections:
        va = s["va"]
        rsz = s["rsz"]
        rptr = s["raw"]
        # Use SizeOfRawData bounds for on-disk mapping.
        if va <= rva < va + rsz:
            return rptr + (rva - va)
    return None


def main() -> int:
    ap = argparse.ArgumentParser(description="Offline stage2 extractor/decryptor from stage1 dump")
    ap.add_argument("--stage1", default="output/shellcode.bin", help="Path to stage1 dump (shellcode.bin)")
    ap.add_argument(
        "--image",
        default=None,
        help=(
            "Optional: path to a PE image buffer to patch/decrypt in-place (e.g. input/BluetoothService.exe). "
            "If set, decrypts the regions as RVAs and outputs a patched on-disk PE, and --strategy is ignored."
        ),
    )
    ap.add_argument(
        "--container-pe",
        default=None,
        help=(
            "Optional: PE file used as an in-memory container at ImageBase (e.g. input/BluetoothService.exe). "
            "If set, we (1) build its memory image, (2) overwrite the 5 regions with encrypted bytes from stage1 "
            "using --strategy, (3) decrypt in place, and (4) write the resulting *memory image* to --out."
        ),
    )
    ap.add_argument(
        "--arg-struct",
        required=True,
        help="25 dwords from emulator log, as hex/dec list (space or comma separated)",
    )
    ap.add_argument("--key", default="gQ2JR&9;", help="Key string")
    ap.add_argument("--rounds", type=int, default=1, help="How many times to apply the transform per region (default 1)")
    ap.add_argument("--start", type=lambda s: int(s, 0), default=None, help="container-pe: start offset into stage1 for the concatenated encrypted blob")
    ap.add_argument("--auto-start", action="store_true", help="container-pe: brute-force start offset and pick best-scoring entrypoint disassembly")
    ap.add_argument(
        "--strategy",
        choices=["tail_concat", "sections_from_stage1", "sliding_concat"],
        default="tail_concat",
        help="How to reconstruct the encrypted module bytes before decrypting",
    )
    ap.add_argument("--slide-step", type=lambda s: int(s, 0), default=0x10, help="sliding_concat: step size (default 0x10)")
    ap.add_argument("--out", default="output/stage2_offline.bin", help="Output path")
    args = ap.parse_args()

    stage1 = Path(args.stage1).read_bytes()
    words = parse_arg_struct(args.arg_struct)
    key = args.key.encode("ascii", errors="ignore")
    if len(key) != 8:
        raise SystemExit("Expected 8-byte key (Rapid7 shows 8 bytes)")
    if args.rounds < 1 or args.rounds > 20:
        raise SystemExit("--rounds must be in [1, 20]")

    pos_list = words[2:7]      # 5
    size_list = words[9:14]    # 5
    if len(pos_list) != 5 or len(size_list) != 5:
        raise SystemExit("Bad arg struct: pos/size lists not 5 each")

    total_in = sum(size_list)
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    def do_decrypt_in_place(buf: bytearray) -> None:
        for p, s in zip(pos_list, size_list):
            end = p + s
            if end > len(buf):
                raise SystemExit(f"Region [0x{p:X},0x{end:X}) exceeds buffer size 0x{len(buf):X}")
            for _ in range(args.rounds):
                decrypt_region_in_place(buf, p, s, key)

    if args.image:
        img_path = Path(args.image)
        raw = img_path.read_bytes()
        try:
            image_base, size_of_headers, size_of_image, sections = parse_pe_sections(raw)
        except Exception as e:
            raise SystemExit(f"--image: failed to parse PE: {e}")

        out_raw = bytearray(raw)
        # Apply per-byte transform on the *file* bytes that correspond to the RVA ranges.
        for p, s in zip(pos_list, size_list):
            for i in range(s):
                rva = p + i
                raw_off = rva_to_raw(rva, size_of_headers, sections)
                if raw_off is None or raw_off >= len(out_raw):
                    raise SystemExit(f"--image: RVA 0x{rva:X} does not map to a RAW offset in {img_path}")
                k = key[i & 7]
                out_raw[raw_off] = decrypt_byte(out_raw[raw_off], k)

        out_bytes = bytes(out_raw)
        out_path.write_bytes(out_bytes)
        pe_hits = find_pe_offsets(out_bytes)
        print(f"[+] Patched image: {img_path} -> {out_path}")
        print(f"[+] Wrote {len(out_bytes)} bytes")
        print(f"[+] sha256={sha256_bytes(out_bytes)}")
        print(f"[+] entropy={entropy(out_bytes[: min(len(out_bytes), 0x200000)]):.3f}")
        print(f"[+] rounds={args.rounds} key={args.key!r}")
        print(f"[+] image_base=0x{image_base:X} size_of_headers=0x{size_of_headers:X} size_of_image=0x{size_of_image:X} sections={len(sections)}")
        print(f"[+] pos_list={[hex(x) for x in pos_list]}")
        print(f"[+] size_list={[hex(x) for x in size_list]} total_regions=0x{sum(size_list):X}")
        print(f"[+] pe_hits={pe_hits}")
        if pe_hits:
            print(f"[+] looks_like_pe@0={looks_like_pe(out_bytes,0)} looks_like_pe@0x1000={looks_like_pe(out_bytes,0x1000)}")
        return 0

    if args.container_pe:
        cont_path = Path(args.container_pe)
        cont_raw = cont_path.read_bytes()
        try:
            image_base, size_of_headers, size_of_image, sections = parse_pe_sections(cont_raw)
        except Exception as e:
            raise SystemExit(f"--container-pe: failed to parse PE: {e}")

        # Build a memory image (headers + section raw mapped at RVA).
        mem = bytearray(size_of_image)
        mem[: min(size_of_headers, len(cont_raw))] = cont_raw[: min(size_of_headers, len(cont_raw))]
        for s in sections:
            va, rptr, rsz = s["va"], s["raw"], s["rsz"]
            if rptr >= len(cont_raw):
                continue
            mem[va : va + rsz] = cont_raw[rptr : rptr + rsz].ljust(rsz, b"\x00")

        # Overwrite container RVAs with encrypted bytes derived from stage1.
        #
        # Note: the arg-struct provides 5 (pos,size) regions. We treat pos as an RVA into
        # the container memory image, and size as the byte count.
        total_in = sum(size_list)

        blob_start = args.start
        if args.auto_start:
            try:
                from capstone import Cs, CS_ARCH_X86, CS_MODE_32
            except Exception as e:
                raise SystemExit(f"--auto-start requires capstone: {e}")

            entry_rva = words[0]
            md = Cs(CS_ARCH_X86, CS_MODE_32)
            md.detail = False
            bad = {
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
            }

            def score_entry(mem_img: bytes) -> int:
                code = mem_img[entry_rva : entry_rva + 0x80]
                ins = list(md.disasm(code, image_base + entry_rva))
                if len(ins) < 6:
                    return -10_000
                score = 0
                if code[:3] == b"\x55\x8B\xEC":
                    score += 200
                if code[:2] == b"\x8B\xFF":
                    score += 50
                for i in ins[:12]:
                    if i.mnemonic in bad:
                        score -= 80
                    else:
                        score += 10
                    if i.op_str.count("0x") >= 1 and "0x" in i.op_str:
                        # Penalize huge constants as a cheap proxy for garbage decode.
                        try:
                            vals = []
                            for tok in i.op_str.replace("[", " ").replace("]", " ").replace(",", " ").split():
                                if tok.startswith("0x"):
                                    vals.append(int(tok, 16))
                            if vals and max(vals) > 0x2000000:
                                score -= 20
                        except Exception:
                            pass
                return score

            best = (-10_000_000, None)
            max_start = len(stage1) - total_in
            step = max(1, args.slide_step)
            for st in range(0, max_start + 1, step):
                mem2 = bytearray(mem)
                blob2 = stage1[st : st + total_in]
                cur2 = 0
                for p, s in zip(pos_list, size_list):
                    mem2[p : p + s] = blob2[cur2 : cur2 + s]
                    cur2 += s
                do_decrypt_in_place(mem2)
                sc = score_entry(mem2)
                if sc > best[0]:
                    best = (sc, st)
            if best[1] is None:
                raise SystemExit("--auto-start: failed to find any candidate")
            blob_start = best[1]
            print(f"[+] auto-start picked start=0x{blob_start:X} score={best[0]}")

        if args.strategy == "sections_from_stage1":
            # Directly treat stage1 as the encrypted backing store at those RVAs.
            # This is the simplest model (and matches the non-container mode).
            for p, s in zip(pos_list, size_list):
                end = p + s
                if end <= len(stage1):
                    mem[p:end] = stage1[p:end]
                else:
                    if p < len(stage1):
                        mem[p:len(stage1)] = stage1[p:len(stage1)]
                    # rest remains as whatever the container already had
        else:
            # Concatenated encrypted blob layout: carve a contiguous blob out of stage1 and
            # lay it into the 5 regions in order.
            if total_in > len(stage1):
                raise SystemExit(f"--container-pe: need 0x{total_in:X} bytes from stage1 but stage1 size is 0x{len(stage1):X}")

            if blob_start is not None:
                if blob_start < 0 or blob_start + total_in > len(stage1):
                    raise SystemExit(
                        f"--start out of range: start=0x{blob_start:X} total_in=0x{total_in:X} stage1=0x{len(stage1):X}"
                    )
                blob = stage1[blob_start : blob_start + total_in]
            else:
                if args.strategy == "tail_concat":
                    blob = stage1[len(stage1) - total_in :]
                elif args.strategy == "sliding_concat":
                    step = max(1, args.slide_step)
                    # Prefer blobs that maximize the number of MZ occurrences after decrypting into the container.
                    best = (-1, 0)
                    best_blob = None
                    for st in range(0, len(stage1) - total_in + 1, step):
                        cand_blob = stage1[st : st + total_in]
                        mem2 = bytearray(mem)
                        cur2 = 0
                        for p, s in zip(pos_list, size_list):
                            mem2[p : p + s] = cand_blob[cur2 : cur2 + s]
                            cur2 += s
                        do_decrypt_in_place(mem2)
                        mz = bytes(mem2).count(b"MZ")
                        if mz > best[0]:
                            best = (mz, st)
                            best_blob = cand_blob
                    if best_blob is None:
                        raise SystemExit("--container-pe sliding_concat: no candidates?")
                    blob_start = best[1]
                    print(f"[+] sliding_concat picked start=0x{blob_start:X} mz_count={best[0]}")
                    blob = best_blob
                else:
                    raise SystemExit(
                        "--container-pe: use --strategy sections_from_stage1|tail_concat|sliding_concat "
                        "(or provide --start/--auto-start for blob strategies)"
                    )

            cur = 0
            for p, s in zip(pos_list, size_list):
                mem[p : p + s] = blob[cur : cur + s]
                cur += s

        do_decrypt_in_place(mem)
        out_bytes = bytes(mem)
        out_path.write_bytes(out_bytes)

        print(f"[+] Container PE: {cont_path} (ImageBase=0x{image_base:X})")
        print(f"[+] Stage1: {args.stage1} (len=0x{len(stage1):X})")
        if blob_start is not None:
            print(f"[+] blob_start=0x{blob_start:X} total_in=0x{total_in:X}")
        print(f"[+] strategy={args.strategy} rounds={args.rounds} key={args.key!r}")
        print(f"[+] Wrote decrypted memory image: {out_path} ({len(out_bytes)} bytes)")
        print(f"[+] sha256={sha256_bytes(out_bytes)} entropy={entropy(out_bytes):.3f}")
        print(f"[+] pos_list={[hex(x) for x in pos_list]}")
        print(f"[+] size_list={[hex(x) for x in size_list]} total_in=0x{total_in:X}")
        print(f"[+] PE hits in memory image: {find_pe_offsets(out_bytes)}")
        return 0

    out_size = max(p + s for p, s in zip(pos_list, size_list))
    buf = bytearray(out_size)

    def fill_from_concat(blob: bytes) -> None:
        cur = 0
        for p, s in zip(pos_list, size_list):
            buf[p : p + s] = blob[cur : cur + s]
            cur += s

    best_slide = None  # (score, start)
    best_bytes = None

    if args.strategy == "tail_concat":
        if total_in > len(stage1):
            raise SystemExit(f"tail_concat: need 0x{total_in:X} bytes but stage1 size is 0x{len(stage1):X}")
        blob = stage1[len(stage1) - total_in :]
        fill_from_concat(blob)
        do_decrypt_in_place(buf)
        out_bytes = bytes(buf)
    elif args.strategy == "sliding_concat":
        if total_in > len(stage1):
            raise SystemExit(f"sliding_concat: need 0x{total_in:X} bytes but stage1 size is 0x{len(stage1):X}")
        step = max(1, args.slide_step)
        # Try different alignments of the concatenated encrypted blob within stage1.
        for start in range(0, len(stage1) - total_in + 1, step):
            buf[:] = b"\x00" * len(buf)
            blob = stage1[start : start + total_in]
            fill_from_concat(blob)
            do_decrypt_in_place(buf)
            cand = bytes(buf)
            pe_hits = find_pe_offsets(cand, max_hits=3)
            mz = cand.count(b"MZ")
            # Prefer any real PE hit. Otherwise prefer more 'MZ' (weak signal).
            score = (1000 if pe_hits else 0) + min(mz, 10)
            if best_slide is None or score > best_slide[0]:
                best_slide = (score, start, pe_hits, mz)
                best_bytes = cand
        if best_bytes is None:
            raise SystemExit("sliding_concat: no candidates?")
        out_bytes = best_bytes
    else:
        # Directly treat stage1 as the encrypted backing store at those offsets.
        for p, s in zip(pos_list, size_list):
            end = p + s
            if end <= len(stage1):
                buf[p:end] = stage1[p:end]
            else:
                # Partial fill if stage1 doesn't contain the full section.
                if p < len(stage1):
                    buf[p:len(stage1)] = stage1[p:len(stage1)]
                # rest stays zero

        do_decrypt_in_place(buf)
        out_bytes = bytes(buf)
    out_path.write_bytes(out_bytes)

    pe_hits = find_pe_offsets(out_bytes)
    print(f"[+] Wrote {len(out_bytes)} bytes to {out_path}")
    print(f"[+] sha256={sha256_bytes(out_bytes)}")
    print(f"[+] entropy={entropy(out_bytes[: min(len(out_bytes), 0x200000)]):.3f}")
    print(f"[+] strategy={args.strategy}")
    print(f"[+] rounds={args.rounds} key={args.key!r}")
    if best_slide is not None:
        print(f"[+] sliding_concat best: score={best_slide[0]} start=0x{best_slide[1]:X} pe_hits={best_slide[2]} mz_count={best_slide[3]}")
    print(f"[+] pos_list={[hex(x) for x in pos_list]}")
    print(f"[+] size_list={[hex(x) for x in size_list]} total_in=0x{total_in:X}")
    print(f"[+] pe_hits={pe_hits}")
    if pe_hits:
        print(f"[+] looks_like_pe@0={looks_like_pe(out_bytes,0)} looks_like_pe@0x1000={looks_like_pe(out_bytes,0x1000)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
