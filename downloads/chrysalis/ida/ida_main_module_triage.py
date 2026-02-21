#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IDAPython helper for Chrysalis main-module triage.

Step 1 (CLI/headless):
  Windows: idat64.exe -A -Sida_main_module_triage.py <target_binary>
  macOS/Linux: idat64 -A -Sida_main_module_triage.py <target_binary>

Use this on:
  - output/main_module_patched.exe
  - output/main_module_mem.bin (loaded as PE image in IDA)

Features:
1) Creates/applies enum symbols for C2 command tags (4T..4d family).
2) Annotates instructions that reference these tag constants.
3) Optionally imports patched-range JSON (from diff_patched_pe.py) and marks
   those ranges with comments/colors for faster navigation.
"""

from __future__ import annotations

import json
import sys
from typing import Dict, Iterable, List, Optional, Tuple

IN_IDA = True
try:
    import idaapi  # type: ignore[import-not-found]
    import ida_bytes  # type: ignore[import-not-found]
    import ida_kernwin  # type: ignore[import-not-found]
    import idautils  # type: ignore[import-not-found]
    import idc  # type: ignore[import-not-found]
except Exception:
    IN_IDA = False
    idaapi = None  # type: ignore[assignment]
    ida_bytes = None  # type: ignore[assignment]
    ida_kernwin = None  # type: ignore[assignment]
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


def _iter_heads() -> Iterable[int]:
    for seg_ea in idautils.Segments():
        start = idc.get_segm_start(seg_ea)
        end = idc.get_segm_end(seg_ea)
        ea = start
        while ea != idc.BADADDR and ea < end:
            yield ea
            ea = idc.next_head(ea, end)


def _get_or_create_enum(enum_name: str) -> Optional[int]:
    eid = idc.get_enum(enum_name)
    if eid in (idc.BADADDR, -1):
        eid = idc.add_enum(idc.BADADDR, enum_name, 0)
    if eid in (idc.BADADDR, -1):
        return None
    return eid


def _ensure_cmd_enum(enum_name: str) -> Optional[int]:
    eid = _get_or_create_enum(enum_name)
    if eid is None:
        return None
    for val, name in CMD_TAGS.items():
        if idc.get_enum_member_by_name(name) != idc.BADADDR:
            continue
        idc.add_enum_member(eid, name, val, -1)
    return eid


def annotate_command_tags(enum_name: str = "CHRYSALIS_CMD_TAG", apply_enum: bool = True) -> int:
    eid = _ensure_cmd_enum(enum_name) if apply_enum else None
    hits = 0
    for ea in _iter_heads():
        mnem = idc.print_insn_mnem(ea)
        if not mnem:
            continue
        found = []
        for op_idx in range(2):
            if idc.get_operand_type(ea, op_idx) != idc.o_imm:
                continue
            imm = idc.get_operand_value(ea, op_idx) & 0xFFFFFFFF
            if imm in CMD_TAGS:
                found.append((op_idx, imm))
        if not found:
            continue

        parts = [f"tag 0x{imm:04X} ({CMD_TAGS[imm]})" for _, imm in found]
        msg = "C2 command tag: " + ", ".join(parts)
        idc.set_cmt(ea, msg, 0)
        hits += 1

        if apply_enum and eid not in (None, idc.BADADDR):
            for op_idx, imm in found:
                idc.op_enum(ea, op_idx, eid, 0)
    return hits


def _rva_to_ea(rva: int) -> int:
    return idaapi.get_imagebase() + rva


def _set_item_color_safe(ea: int, color: int) -> None:
    flags = idc.get_full_flags(ea)
    if flags != 0:
        idc.set_color(ea, idc.CIC_ITEM, color)


def mark_changed_ranges(diff_json_path: str, color: int = 0xE0FFF0) -> int:
    """
    Supports multiple JSON shapes from diff tools.
    Expected fields per range (any one set):
      - {"rva":..., "size":...}
      - {"rva_start":..., "rva_size":...}
      - {"rva_start":..., "rva_end":...}
    """
    try:
        data = json.load(open(diff_json_path, "r", encoding="utf-8"))
    except Exception as e:
        ida_kernwin.msg(f"[!] Failed to load diff JSON: {e}\n")
        return 0

    if isinstance(data, dict):
        # Common patterns
        ranges = data.get("ranges") or data.get("changes") or data.get("diffs") or []
    elif isinstance(data, list):
        ranges = data
    else:
        ranges = []

    marked = 0
    for i, r in enumerate(ranges):
        if not isinstance(r, dict):
            continue

        rva_start = None
        size = None
        if "rva" in r and "size" in r:
            rva_start = int(r["rva"])
            size = int(r["size"])
        elif "rva_start" in r and "rva_size" in r:
            rva_start = int(r["rva_start"])
            size = int(r["rva_size"])
        elif "rva_start" in r and "rva_end" in r:
            rva_start = int(r["rva_start"])
            size = int(r["rva_end"]) - int(r["rva_start"])

        if rva_start is None or size is None or size <= 0:
            continue

        start_ea = _rva_to_ea(rva_start)
        end_ea = start_ea + size
        idc.set_cmt(start_ea, f"PATCHED_RANGE #{i} rva=0x{rva_start:X} size=0x{size:X}", 0)
        ea = start_ea
        while ea != idc.BADADDR and ea < end_ea:
            _set_item_color_safe(ea, color)
            ea = idc.next_head(ea, end_ea)
        marked += 1

    return marked


def main() -> None:
    if not require_ida():
        return
    ida_kernwin.msg("[*] Chrysalis main-module triage helper\n")
    base = idaapi.get_imagebase()
    ep = idc.get_inf_attr(idc.INF_START_IP)
    ida_kernwin.msg(f"[*] image_base=0x{base:08X} entry=0x{ep:08X} (rva 0x{ep-base:08X})\n")

    apply_enum = ida_kernwin.ask_yn(1, "Create/apply enum for C2 command tags?") == 1
    enum_name = "CHRYSALIS_CMD_TAG"
    if apply_enum:
        enum_name = ida_kernwin.ask_str(enum_name, 0, "Enum name") or enum_name
    tag_hits = annotate_command_tags(enum_name=enum_name, apply_enum=apply_enum)
    ida_kernwin.msg(f"[+] Command-tag annotations: {tag_hits}\n")

    do_diff = ida_kernwin.ask_yn(0, "Import patched diff JSON and mark changed ranges?") == 1
    if do_diff:
        path = ida_kernwin.ask_file(False, "*.json", "Select patched diff JSON")
        if path:
            marked = mark_changed_ranges(path)
            ida_kernwin.msg(f"[+] Marked changed ranges: {marked}\n")


if __name__ == "__main__":
    main()
