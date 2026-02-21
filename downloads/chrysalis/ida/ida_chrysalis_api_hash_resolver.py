#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Standalone IDAPython helper for Chrysalis/log.dll loader hash resolution.

Step 1 (CLI/headless):
  Windows: idat64.exe -A -Sida_chrysalis_api_hash_resolver.py <target_binary>
  macOS/Linux: idat64 -A -Sida_chrysalis_api_hash_resolver.py <target_binary>

What it does:
1) Builds a rainbow table from DLL exports (PE32 + PE32+ supported).
2) Uses the Chrysalis loader hash algorithm:
     constant = api_hash(export_name) - seed  (mod 2^32)
3) Resolves constants passed to the resolver callsites and annotates IDA.

Typical sample settings (Rapid7 chain):
  seed       = 0x114DDB33
  resolver   = 0x100014E0
  dll dirs   = C:\\Windows\\SysWOW64;C:\\Windows\\System32
"""

from __future__ import annotations

import json
import os
import re
import struct
import sys
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Set, Tuple

IN_IDA = True
try:
    import ida_kernwin  # type: ignore[import-not-found]
    import idaapi  # type: ignore[import-not-found]
    import idautils  # type: ignore[import-not-found]
    import idc  # type: ignore[import-not-found]
except Exception:
    IN_IDA = False
    ida_kernwin = None  # type: ignore[assignment]
    idaapi = None  # type: ignore[assignment]
    idautils = None  # type: ignore[assignment]
    idc = None  # type: ignore[assignment]


def require_ida() -> bool:
    if IN_IDA:
        return True
    sys.stderr.write("[!] Run this script inside IDA (GUI or idat -A -S).\n")
    return False


FNV1A_BASIS_32 = 0x811C9DC5
FNV1A_PRIME_32 = 0x01000193
FINAL_MUL = 0x85EBCA6B


def u32(x: int) -> int:
    return x & 0xFFFFFFFF


def fnv1a32(data: bytes) -> int:
    h = FNV1A_BASIS_32
    for b in data:
        h ^= b
        h = u32(h * FNV1A_PRIME_32)
    return u32(h)


def loader_finalizer(h: int) -> int:
    x = u32(h ^ (h >> 15))
    x = u32(x * FINAL_MUL)
    x = u32(x ^ (x >> 13))
    return u32(x)


def loader_api_hash(name: str, case_mode: str = "asis") -> int:
    if case_mode == "lower":
        name = name.lower()
    elif case_mode == "upper":
        name = name.upper()
    raw = name.encode("ascii", errors="ignore")
    return loader_finalizer(fnv1a32(raw))


def loader_constant(name: str, seed: int, case_mode: str = "asis") -> int:
    return u32(loader_api_hash(name, case_mode=case_mode) - u32(seed))


def _u16(b: bytes, off: int) -> int:
    return struct.unpack_from("<H", b, off)[0]


def _u32(b: bytes, off: int) -> int:
    return struct.unpack_from("<I", b, off)[0]


def _pe_layout(pe: bytes) -> Optional[Tuple[int, int, int, int]]:
    """
    Returns tuple:
      (num_sections, sections_off, export_rva, export_size)
    """
    if len(pe) < 0x100 or pe[:2] != b"MZ":
        return None
    e_lfanew = _u32(pe, 0x3C)
    if e_lfanew + 0x100 > len(pe):
        return None
    if pe[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        return None

    coff = e_lfanew + 4
    num_sections = _u16(pe, coff + 2)
    opt_size = _u16(pe, coff + 16)
    opt = coff + 20
    if opt + opt_size > len(pe):
        return None

    magic = _u16(pe, opt)
    if magic == 0x10B:
        dd_off = 0x60
    elif magic == 0x20B:
        dd_off = 0x70
    else:
        return None

    export_rva = _u32(pe, opt + dd_off)
    export_sz = _u32(pe, opt + dd_off + 4)
    sections_off = opt + opt_size
    return (num_sections, sections_off, export_rva, export_sz)


def _rva_to_off(pe: bytes, rva: int) -> Optional[int]:
    layout = _pe_layout(pe)
    if not layout:
        return None
    num_sections, sections_off, _, _ = layout

    for i in range(num_sections):
        s = sections_off + i * 40
        if s + 40 > len(pe):
            return None
        virt_size = _u32(pe, s + 8)
        virt_addr = _u32(pe, s + 12)
        raw_size = _u32(pe, s + 16)
        raw_ptr = _u32(pe, s + 20)
        size = max(virt_size, raw_size)
        if virt_addr <= rva < virt_addr + size:
            off = raw_ptr + (rva - virt_addr)
            return off if 0 <= off < len(pe) else None
    return None


def _read_cstr(pe: bytes, off: int, max_len: int = 512) -> Optional[str]:
    if off < 0 or off >= len(pe):
        return None
    end = pe.find(b"\x00", off, min(len(pe), off + max_len))
    if end < 0:
        return None
    try:
        return pe[off:end].decode("ascii", errors="ignore")
    except Exception:
        return None


def iter_export_names(path: str) -> Iterable[str]:
    try:
        pe = open(path, "rb").read()
    except Exception:
        return

    layout = _pe_layout(pe)
    if not layout:
        return
    _, _, exp_rva, exp_sz = layout
    if exp_rva == 0 or exp_sz == 0:
        return

    exp_off = _rva_to_off(pe, exp_rva)
    if exp_off is None or exp_off + 40 > len(pe):
        return

    num_names = _u32(pe, exp_off + 0x18)
    names_rva = _u32(pe, exp_off + 0x20)
    if num_names == 0 or names_rva == 0:
        return

    names_off = _rva_to_off(pe, names_rva)
    if names_off is None:
        return

    seen: Set[str] = set()
    for i in range(num_names):
        ent = names_off + i * 4
        if ent + 4 > len(pe):
            break
        nrva = _u32(pe, ent)
        noff = _rva_to_off(pe, nrva)
        if noff is None:
            continue
        name = _read_cstr(pe, noff)
        if not name or name in seen:
            continue
        seen.add(name)
        yield name


@dataclass(frozen=True)
class Match:
    dll: str
    exp: str


class Rainbow:
    def __init__(self) -> None:
        self.by_hash: Dict[int, Set[Match]] = {}

    def add(self, hv: int, dll: str, exp: str) -> None:
        self.by_hash.setdefault(u32(hv), set()).add(Match(dll, exp))

    def lookup(self, hv: int) -> List[Match]:
        return sorted(self.by_hash.get(u32(hv), set()), key=lambda m: (m.dll.lower(), m.exp.lower()))

    def to_nested(self) -> Dict[str, Dict[str, object]]:
        out: Dict[str, Dict[str, object]] = {}
        for hv, matches in self.by_hash.items():
            key = f"0x{hv:08X}"
            for m in sorted(matches, key=lambda x: (x.dll.lower(), x.exp.lower())):
                d = out.setdefault(m.dll, {})
                if key not in d:
                    d[key] = m.exp
                else:
                    cur = d[key]
                    if isinstance(cur, list):
                        if m.exp not in cur:
                            cur.append(m.exp)
                    elif cur != m.exp:
                        d[key] = [cur, m.exp]
        return out


def build_rainbow(dll_dirs: List[str], recursive: bool, seed: int, case_mode: str) -> Rainbow:
    rb = Rainbow()
    exts = {".dll", ".ocx", ".cpl", ".drv"}
    for root in dll_dirs:
        if not os.path.isdir(root):
            ida_kernwin.msg(f"[!] Missing dir: {root}\n")
            continue
        if recursive:
            walker = os.walk(root)
        else:
            walker = [(root, [], os.listdir(root))]

        for dpath, _, files in walker:
            for fn in files:
                if os.path.splitext(fn)[1].lower() not in exts:
                    continue
                full = os.path.join(dpath, fn)
                dll = os.path.basename(full)
                try:
                    for exp in iter_export_names(full):
                        rb.add(loader_constant(exp, seed, case_mode=case_mode), dll, exp)
                except Exception:
                    continue
    return rb


def _find_push_imm_before(call_ea: int, max_back: int = 12) -> Optional[Tuple[int, int]]:
    seg_start = idc.get_segm_start(call_ea) # type: ignore
    ea = call_ea
    for _ in range(max_back):
        ea = idc.prev_head(ea, seg_start)
        if ea == idc.BADADDR:
            break
        if idc.print_insn_mnem(ea).lower() != "push":
            continue
        if idc.get_operand_type(ea, 0) == idc.o_imm:
            return ea, u32(idc.get_operand_value(ea, 0))
    return None


def _sanitize_symbol(s: str) -> str:
    s = re.sub(r"[^0-9A-Za-z_]", "_", s)
    s = re.sub(r"_+", "_", s).strip("_")
    if not s:
        s = "UNK"
    if s[0].isdigit():
        s = "_" + s
    return s


def _get_or_create_enum(enum_name: str) -> Optional[int]:
    eid = idc.get_enum(enum_name)
    if eid in (idc.BADADDR, -1):
        eid = idc.add_enum(idc.BADADDR, enum_name, 0)
    if eid in (idc.BADADDR, -1):
        return None
    return eid


def _ensure_member_for_hash(enum_id: int, hv: int, primary: Match, all_matches: List[Match]) -> Optional[str]:
    # One enum member per hash value for stable operand rendering.
    base = f"APIHASH_{hv:08X}__{_sanitize_symbol(primary.dll)}__{_sanitize_symbol(primary.exp)}"
    name = base[:240]

    existing = idc.get_enum_member_by_name(name)
    if existing != idc.BADADDR:
        return name

    rc = idc.add_enum_member(enum_id, name, hv, -1)
    if rc != 0:
        # Fallback to a short unique symbol.
        name = f"APIHASH_{hv:08X}"
        if idc.get_enum_member_by_name(name) == idc.BADADDR:
            rc2 = idc.add_enum_member(enum_id, name, hv, -1)
            if rc2 != 0:
                return None

    # Store collision/context info on the member where possible.
    member_id = idc.get_enum_member_by_name(name)
    if member_id != idc.BADADDR:
        detail = ", ".join([f"{m.dll}!{m.exp}" for m in all_matches[:8]])
        if len(all_matches) > 8:
            detail += f" (+{len(all_matches)-8} more)"
        try:
            idc.set_enum_member_cmt(member_id, detail, 0)
        except Exception:
            pass
    return name


def annotate_callsites(
    rb: Rainbow,
    resolver_ea: int,
    image_base: int,
    apply_enum: bool = False,
    enum_name: str = "CHRYSALIS_API_HASH",
) -> Tuple[int, int, int]:
    enum_id = None
    if apply_enum:
        enum_id = _get_or_create_enum(enum_name)
        if enum_id is None:
            ida_kernwin.msg(f"[!] Failed to create/get enum '{enum_name}'. Continuing with comments only.\n")
            apply_enum = False

    resolved = 0
    total = 0
    enum_applied = 0
    for x in idautils.XrefsTo(resolver_ea, 0):
        call_ea = x.frm
        if idc.print_insn_mnem(call_ea).lower() not in ("call",):
            continue
        total += 1
        prev = _find_push_imm_before(call_ea)
        if not prev:
            continue
        push_ea, hv = prev
        matches = rb.lookup(hv)
        if not matches:
            continue
        resolved += 1
        if len(matches) == 1:
            txt = f"APIHASH 0x{hv:08X} -> {matches[0].dll}!{matches[0].exp}"
        else:
            joined = ", ".join([f"{m.dll}!{m.exp}" for m in matches[:6]])
            if len(matches) > 6:
                joined += f" (+{len(matches)-6} more)"
            txt = f"APIHASH 0x{hv:08X} -> {joined}"
        idc.set_cmt(call_ea, txt, 0)
        idc.set_cmt(push_ea, txt, 0)

        if apply_enum and enum_id not in (None, idc.BADADDR):
            member_name = _ensure_member_for_hash(enum_id, hv, matches[0], matches)
            if member_name:
                # Force operand rendering to enum symbol in disassembly; this often propagates to decompiler.
                if idc.op_enum(push_ea, 0, enum_id, 0):
                    enum_applied += 1

        rva = call_ea - image_base
        ida_kernwin.msg(f"[+] 0x{call_ea:08X} (rva 0x{rva:08X}) 0x{hv:08X} {txt}\n")
    return resolved, total, enum_applied


def main() -> None:
    if not require_ida():
        return
    ida_kernwin.msg("[*] Chrysalis API hash resolver (loader scheme)\n")

    seed_s = ida_kernwin.ask_str("0x114DDB33", 0, "Seed value (hex/dec). Rapid7 sample: 0x114DDB33")
    if not seed_s:
        ida_kernwin.msg("[!] Cancelled.\n")
        return
    try:
        seed = u32(int(seed_s.strip(), 0))
    except Exception:
        ida_kernwin.msg(f"[!] Invalid seed value: {seed_s}\n")
        return

    # Self-test so failure is obvious.
    test = loader_constant("VirtualProtect", seed, case_mode="asis")
    ida_kernwin.msg(f"[*] Self-test: VirtualProtect constant = 0x{test:08X}\n")

    resolver_ea = ida_kernwin.ask_addr(0x100014E0, "Resolver EA (call target), e.g. 0x100014E0")
    if resolver_ea is None:
        ida_kernwin.msg("[!] Cancelled.\n")
        return

    dirs = ida_kernwin.ask_str(r"C:\Windows\SysWOW64;C:\Windows\System32", 0, "DLL dirs (semicolon-separated)")
    if not dirs:
        ida_kernwin.msg("[!] No dirs provided.\n")
        return
    dll_dirs = [x.strip() for x in dirs.split(";") if x.strip()]
    recursive = ida_kernwin.ask_yn(1, "Recursive directory walk?") == 1
    case_mode = (ida_kernwin.ask_str("asis", 0, "Case mode: asis|lower|upper") or "asis").strip().lower()
    if case_mode not in ("asis", "lower", "upper"):
        case_mode = "asis"

    image_base = idaapi.get_imagebase()
    ida_kernwin.msg(
        f"[*] image_base=0x{image_base:08X} resolver_ea=0x{resolver_ea:08X} seed=0x{seed:08X}\n"
    )
    ida_kernwin.msg(f"[*] Building rainbow from: {dll_dirs} recursive={recursive} case={case_mode}\n")

    ida_kernwin.show_wait_box("Building hash rainbow...")
    try:
        rb = build_rainbow(dll_dirs, recursive, seed, case_mode)
    finally:
        ida_kernwin.hide_wait_box()

    ida_kernwin.msg(f"[*] Rainbow built: {len(rb.by_hash)} unique constants\n")
    canary = rb.lookup(0x47C204CA)
    ida_kernwin.msg(f"[*] Canary 0x47C204CA present: {'yes' if canary else 'no'}\n")
    if canary:
        ida_kernwin.msg("[*] Canary matches: " + ", ".join([f"{m.dll}!{m.exp}" for m in canary[:5]]) + "\n")
    else:
        ida_kernwin.msg(
            "[!] Missing canary hash. Check: seed, case mode ('asis'), and that you're running this updated script.\n"
        )

    out = ida_kernwin.ask_file(True, "*.json", "Optional: write rainbow JSON (Cancel to skip)")
    if out:
        try:
            with open(out, "w", encoding="utf-8") as f:
                json.dump(rb.to_nested(), f, indent=2, sort_keys=True)
            ida_kernwin.msg(f"[+] Wrote: {out}\n")
        except Exception as e:
            ida_kernwin.msg(f"[!] Failed writing JSON: {e}\n")

    apply_enum = ida_kernwin.ask_yn(1, "Create/apply enum symbols to push immediates?") == 1
    enum_name = "CHRYSALIS_API_HASH"
    if apply_enum:
        enum_name = ida_kernwin.ask_str(enum_name, 0, "Enum name for hash symbols") or enum_name

    ida_kernwin.msg("[*] Resolving xrefs and annotating...\n")
    resolved, total, enum_applied = annotate_callsites(
        rb,
        resolver_ea,
        image_base,
        apply_enum=apply_enum,
        enum_name=enum_name,
    )
    ida_kernwin.msg(
        f"[+] Annotated {resolved} callsites out of {total} resolver xrefs; enum-applied={enum_applied}\n"
    )


if __name__ == "__main__":
    main()
