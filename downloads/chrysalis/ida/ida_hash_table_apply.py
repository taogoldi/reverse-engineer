#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Generic IDAPython hash-table applicator for 32-bit immediate constants.

Step 1 (CLI/headless):
  Windows: idat64.exe -A -Sida_hash_table_apply.py <target_binary>
  macOS/Linux: idat64 -A -Sida_hash_table_apply.py <target_binary>

Primary use:
  Apply a prebuilt rainbow JSON (e.g. api_hash_rainbow_nested.json) to
  disassembly/decompiler by replacing raw hash constants with enum symbols and
  comments showing likely DLL!export mappings.

Input JSON shape supported:
{
  "KERNEL32.dll": {
    "0x47C204CA": "VirtualProtect",
    "0x12345678": ["ExportA", "ExportB"]
  },
  ...
}
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

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


@dataclass(frozen=True)
class Match:
    dll: str
    exp: str


def _iter_heads() -> Iterable[int]:
    for seg in idautils.Segments():
        start = idc.get_segm_start(seg)
        end = idc.get_segm_end(seg)
        ea = start
        while ea != idc.BADADDR and ea < end:
            yield ea
            ea = idc.next_head(ea, end)


def _normalize_member_name(name: str) -> str:
    out = []
    for ch in name:
        if ch.isalnum() or ch == "_":
            out.append(ch)
        else:
            out.append("_")
    s = "".join(out)
    while "__" in s:
        s = s.replace("__", "_")
    return s.strip("_") or "HASH"


def _get_or_create_enum(enum_name: str) -> Optional[int]:
    eid = idc.get_enum(enum_name)
    if eid in (idc.BADADDR, -1):
        eid = idc.add_enum(idc.BADADDR, enum_name, 0)
    if eid in (idc.BADADDR, -1):
        return None
    return eid


def load_nested_json(path: str) -> Dict[int, List[Match]]:
    data = json.load(open(path, "r", encoding="utf-8"))
    out: Dict[int, List[Match]] = {}
    if not isinstance(data, dict):
        return out

    for dll, hv_map in data.items():
        if not isinstance(hv_map, dict):
            continue
        for hv_s, exp_v in hv_map.items():
            try:
                hv = int(str(hv_s), 0) & 0xFFFFFFFF
            except Exception:
                continue
            if isinstance(exp_v, str):
                exps = [exp_v]
            elif isinstance(exp_v, list):
                exps = [str(x) for x in exp_v]
            else:
                continue
            cur = out.setdefault(hv, [])
            seen = {(m.dll, m.exp) for m in cur}
            for e in exps:
                t = (str(dll), e)
                if t in seen:
                    continue
                cur.append(Match(*t))
                seen.add(t)
    return out


def apply_hash_map(
    hash_map: Dict[int, List[Match]],
    enum_name: str = "CHRYSALIS_HASH_CONST",
    max_comment_exports: int = 4,
) -> Tuple[int, int]:
    eid = _get_or_create_enum(enum_name)
    enum_applied = 0
    hits = 0
    enum_added: Dict[int, bool] = {}

    for ea in _iter_heads():
        for op_idx in range(3):
            if idc.get_operand_type(ea, op_idx) != idc.o_imm:
                continue
            imm = idc.get_operand_value(ea, op_idx) & 0xFFFFFFFF
            matches = hash_map.get(imm)
            if not matches:
                continue

            hits += 1
            sorted_m = sorted(matches, key=lambda m: (m.dll.lower(), m.exp.lower()))
            show = sorted_m[:max_comment_exports]
            body = ", ".join([f"{m.dll}!{m.exp}" for m in show])
            if len(sorted_m) > len(show):
                body += f", ...(+{len(sorted_m)-len(show)} more)"
            idc.set_cmt(ea, f"HASH 0x{imm:08X} -> {body}", 0)
            idc.set_color(ea, idc.CIC_ITEM, 0xF0F8FF)

            if eid not in (None, idc.BADADDR):
                m0 = sorted_m[0]
                member_name = _normalize_member_name(
                    f"H_{imm:08X}_{m0.dll}_{m0.exp}"
                )
                # Keep one enum member per hash value; ignore duplicate-member errors.
                if imm not in enum_added:
                    idc.add_enum_member(eid, member_name[:250], imm, -1)
                    enum_added[imm] = True
                idc.op_enum(ea, op_idx, eid, 0)
                enum_applied += 1

    return hits, enum_applied


def main() -> None:
    if not require_ida():
        return
    base = idaapi.get_imagebase()
    ida_kernwin.msg(f"[*] hash table apply helper image_base=0x{base:08X}\n")

    jpath = ida_kernwin.ask_file(False, "*.json", "Select nested hash JSON")
    if not jpath:
        ida_kernwin.msg("[!] canceled\n")
        return

    enum_name = ida_kernwin.ask_str("CHRYSALIS_HASH_CONST", 0, "Enum name")
    if not enum_name:
        enum_name = "CHRYSALIS_HASH_CONST"

    max_show = ida_kernwin.ask_long(4, "Max exports to show in comment")
    if not max_show or max_show < 1:
        max_show = 4

    hash_map = load_nested_json(jpath)
    ida_kernwin.msg(
        f"[*] loaded hash constants: {len(hash_map)} from {jpath}\n"
    )
    hits, enum_applied = apply_hash_map(
        hash_map,
        enum_name=enum_name,
        max_comment_exports=max_show,
    )
    ida_kernwin.msg(
        f"[+] annotated_immediates={hits} enum_applied={enum_applied}\n"
    )


if __name__ == "__main__":
    main()
