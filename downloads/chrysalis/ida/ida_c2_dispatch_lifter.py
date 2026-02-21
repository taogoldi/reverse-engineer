#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IDAPython helper to lift C2 command-tag usage from Chrysalis main module.

Step 1 (CLI/headless):
  Windows: idat64.exe -A -Sida_c2_dispatch_lifter.py <target_binary>
  macOS/Linux: idat64 -A -Sida_c2_dispatch_lifter.py <target_binary>

Use on:
  - output/main_module_patched.exe
  - output/main_module_mem.bin

What it does:
1) Finds all instruction operands with C2 command constants (4T..4d family).
2) Annotates those instructions and applies enum rendering.
3) Ranks likely dispatcher functions by unique tag coverage.
4) Optionally exports CSV table for reporting.
"""

from __future__ import annotations

import csv
import sys
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

IN_IDA = True
try:
    import ida_funcs  # type: ignore[import-not-found]
    import ida_kernwin  # type: ignore[import-not-found]
    import idaapi  # type: ignore[import-not-found]
    import idautils  # type: ignore[import-not-found]
    import idc  # type: ignore[import-not-found]
except Exception:
    IN_IDA = False
    ida_funcs = None  # type: ignore[assignment]
    ida_kernwin = None  # type: ignore[assignment]
    idaapi = None  # type: ignore[assignment]
    idautils = None  # type: ignore[assignment]
    idc = None  # type: ignore[assignment]


def require_ida() -> bool:
    if IN_IDA:
        return True
    sys.stderr.write("[!] Run this script inside IDA (GUI or idat -A -S).\n")
    return False


CMD_TAGS: Dict[int, str] = {
    0x3454: "CMD_4T_SPAWN_INTERACTIVE_SHELL",
    0x3455: "CMD_4U_SEND_OK",
    0x3456: "CMD_4V_CREATE_PROCESS",
    0x3457: "CMD_4W_WRITE_FILE",
    0x3458: "CMD_4X_WRITE_CHUNK",
    0x3459: "CMD_4Y_READ_AND_SEND",
    0x345A: "CMD_4Z_BREAK",
    0x345C: "CMD_4_BACKSLASH_UNINSTALL_CLEANUP",
    0x345D: "CMD_4_RIGHTBRACKET_SLEEP",
    0x345F: "CMD_4_UNDERSCORE_ENUM_LOGICAL_DRIVES",
    0x3460: "CMD_4_BACKTICK_ENUM_FILES",
    0x3461: "CMD_4A_DELETE_FILE",
    0x3462: "CMD_4B_CREATE_DIRECTORY",
    0x3463: "CMD_4C_GET_FILE_FROM_C2",
    0x3464: "CMD_4D_SEND_FILE_TO_C2",
}


@dataclass
class TagHit:
    ea: int
    op_idx: int
    value: int
    tag: str
    func_start: int
    func_name: str
    mnem: str
    disasm: str


def _iter_heads() -> Iterable[int]:
    for seg in idautils.Segments():
        start = idc.get_segm_start(seg)
        end = idc.get_segm_end(seg)
        ea = start
        while ea != idc.BADADDR and ea < end:
            yield ea
            ea = idc.next_head(ea, end)


def _func_info(ea: int) -> Tuple[int, str]:
    f = ida_funcs.get_func(ea)
    if not f:
        return (idc.BADADDR, "")
    s = f.start_ea
    return (s, idc.get_func_name(s) or f"sub_{s:X}")


def _get_or_create_enum(enum_name: str) -> Optional[int]:
    eid = idc.get_enum(enum_name)
    if eid in (idc.BADADDR, -1):
        eid = idc.add_enum(idc.BADADDR, enum_name, 0)
    if eid in (idc.BADADDR, -1):
        return None
    return eid


def _ensure_enum(enum_name: str) -> Optional[int]:
    eid = _get_or_create_enum(enum_name)
    if eid is None:
        return None
    for val, name in CMD_TAGS.items():
        if idc.get_enum_member_by_name(name) != idc.BADADDR:
            continue
        idc.add_enum_member(eid, name, val, -1)
    return eid


def collect_hits() -> List[TagHit]:
    out: List[TagHit] = []
    for ea in _iter_heads():
        mnem = idc.print_insn_mnem(ea)
        if not mnem:
            continue
        for op_idx in range(3):
            if idc.get_operand_type(ea, op_idx) != idc.o_imm:
                continue
            imm = idc.get_operand_value(ea, op_idx) & 0xFFFFFFFF
            if imm not in CMD_TAGS:
                continue
            fs, fn = _func_info(ea)
            out.append(
                TagHit(
                    ea=ea,
                    op_idx=op_idx,
                    value=imm,
                    tag=CMD_TAGS[imm],
                    func_start=fs,
                    func_name=fn,
                    mnem=mnem,
                    disasm=idc.generate_disasm_line(ea, 0) or "",
                )
            )
    return out


def annotate_hits(hits: Sequence[TagHit], enum_name: str = "CHRYSALIS_CMD_TAG") -> None:
    eid = _ensure_enum(enum_name)
    for h in hits:
        idc.set_cmt(h.ea, f"C2 command tag 0x{h.value:04X} ({h.tag})", 0)
        idc.set_color(h.ea, idc.CIC_ITEM, 0xFFF0E0)
        if eid not in (None, idc.BADADDR):
            idc.op_enum(h.ea, h.op_idx, eid, 0)


def rank_dispatchers(hits: Sequence[TagHit]) -> List[Tuple[int, str, int, int]]:
    by_func_tags: Dict[int, Set[int]] = {}
    by_func_count: Dict[int, int] = {}
    names: Dict[int, str] = {}
    for h in hits:
        if h.func_start == idc.BADADDR:
            continue
        by_func_tags.setdefault(h.func_start, set()).add(h.value)
        by_func_count[h.func_start] = by_func_count.get(h.func_start, 0) + 1
        names[h.func_start] = h.func_name
    ranked = [
        (ea, names.get(ea, f"sub_{ea:X}"), len(tags), by_func_count.get(ea, 0))
        for ea, tags in by_func_tags.items()
    ]
    ranked.sort(key=lambda t: (t[2], t[3]), reverse=True)
    return ranked


def export_csv(path: str, hits: Sequence[TagHit]) -> None:
    base = idaapi.get_imagebase()
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(
            ["ea", "rva", "func_start", "func_name", "op_idx", "hash", "tag", "mnem", "disasm"]
        )
        for h in sorted(hits, key=lambda x: (x.func_start, x.ea, x.value)):
            w.writerow(
                [
                    f"0x{h.ea:08X}",
                    f"0x{(h.ea - base):08X}",
                    "" if h.func_start == idc.BADADDR else f"0x{h.func_start:08X}",
                    h.func_name,
                    h.op_idx,
                    f"0x{h.value:08X}",
                    h.tag,
                    h.mnem,
                    h.disasm,
                ]
            )


def main() -> None:
    if not require_ida():
        return
    base = idaapi.get_imagebase()
    ida_kernwin.msg(f"[*] Chrysalis C2 dispatch lifter image_base=0x{base:08X}\n")

    hits = collect_hits()
    annotate_hits(hits)
    ida_kernwin.msg(f"[+] tag_hits={len(hits)}\n")

    ranked = rank_dispatchers(hits)
    ida_kernwin.msg("[+] top dispatcher candidates by unique tag coverage:\n")
    for ea, fn, uniq, total in ranked[:20]:
        ida_kernwin.msg(
            f"    func=0x{ea:08X} {fn} unique_tags={uniq} total_tag_refs={total}\n"
        )
        idc.set_func_cmt(ea, f"C2_DISPATCH_CANDIDATE uniq={uniq} refs={total}", 0)

    if ida_kernwin.ask_yn(1, "Export C2 dispatch tag table CSV?") == 1:
        out = ida_kernwin.ask_file(True, "*.csv", "Save dispatch CSV report")
        if out:
            export_csv(out, hits)
            ida_kernwin.msg(f"[+] wrote CSV: {out}\n")


if __name__ == "__main__":
    main()
