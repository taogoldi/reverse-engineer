#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IDAPython helper to locate likely config extraction/decryption paths in
Chrysalis main-module artifacts.

Step 1 (CLI/headless):
  Windows: idat64.exe -A -Sida_config_path_mapper.py <target_binary>
  macOS/Linux: idat64 -A -Sida_config_path_mapper.py <target_binary>

Use on:
  - output/main_module_patched.exe
  - output/main_module_mem.bin (loaded in IDA as PE image)

What it does:
1) Finds immediate constants commonly tied to config handling:
   - 0x980  (config size in Rapid7 sample)
   - 0x30808 (config offset in encrypted blob)
2) Scans data segments for those marker DWORDs and lifts xrefs back into code.
3) Finds strings that may indicate config/C2 parsing.
4) Annotates instructions and marks likely functions for triage.
5) Optionally exports a CSV report.
"""

from __future__ import annotations

import csv
import sys
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

IN_IDA = True
try:
    import ida_funcs  # type: ignore[import-not-found]
    import ida_kernwin  # type: ignore[import-not-found]
    import ida_nalt  # type: ignore[import-not-found]
    import idaapi  # type: ignore[import-not-found]
    import idautils  # type: ignore[import-not-found]
    import idc  # type: ignore[import-not-found]
except Exception:
    IN_IDA = False
    ida_funcs = None  # type: ignore[assignment]
    ida_kernwin = None  # type: ignore[assignment]
    ida_nalt = None  # type: ignore[assignment]
    idaapi = None  # type: ignore[assignment]
    idautils = None  # type: ignore[assignment]
    idc = None  # type: ignore[assignment]

if IN_IDA:
    try:
        import ida_segment  # type: ignore
    except Exception:  # pragma: no cover - IDA module availability is version-dependent
        ida_segment = None
else:
    ida_segment = None


def require_ida() -> bool:
    if IN_IDA:
        return True
    sys.stderr.write("[!] Run this script inside IDA (GUI or idat -A -S).\n")
    return False


IMM_MARKERS = {
    0x980: "CONFIG_SIZE_0x980",
    0x30808: "CONFIG_OFF_0x30808",
}

STRING_MARKERS = [
    "api.skycloudcenter.com",
    "/a/chat/s/",
    "BluetoothService",
    "qwhvb^435h&*7",
]

# APIs commonly involved in this family's config load/decrypt path.
CONFIG_API_MARKERS = [
    "CreateFileW",
    "ReadFile",
    "SetFilePointerEx",
    "GetFileSize",
    "GetFileAttributesW",
    "CloseHandle",
    "LocalAlloc",
    "LocalFree",
]


# IDA API compatibility: permission constants moved across modules/versions.
SEGPERM_EXEC = getattr(ida_segment, "SEGPERM_EXEC", getattr(idaapi, "SEGPERM_EXEC", 1))


@dataclass
class Hit:
    kind: str
    ea: int
    marker: str
    text: str
    func_start: int
    func_name: str


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
    n = idc.get_func_name(s) or f"sub_{s:X}"
    return (s, n)


def _annotate(ea: int, msg: str, color: int = 0xE8FFF0) -> None:
    idc.set_cmt(ea, msg, 0)
    idc.set_color(ea, idc.CIC_ITEM, color)


def _find_imm_hits() -> List[Hit]:
    out: List[Hit] = []
    for ea in _iter_heads():
        mnem = idc.print_insn_mnem(ea)
        if not mnem:
            continue
        for op_idx in range(3):
            if idc.get_operand_type(ea, op_idx) != idc.o_imm:
                continue
            imm = idc.get_operand_value(ea, op_idx) & 0xFFFFFFFF
            if imm not in IMM_MARKERS:
                continue
            fs, fn = _func_info(ea)
            marker = IMM_MARKERS[imm]
            text = f"{marker} at op{op_idx} (0x{imm:X})"
            out.append(Hit("imm", ea, marker, text, fs, fn))
    return out


def _parse_extra_markers(raw: str) -> Dict[int, str]:
    out: Dict[int, str] = {}
    txt = (raw or "").strip()
    if not txt:
        return out
    for chunk in txt.split(","):
        c = chunk.strip()
        if not c:
            continue
        try:
            v = int(c, 0) & 0xFFFFFFFF
        except Exception:
            continue
        out[v] = f"CUSTOM_0x{v:X}"
    return out


def _scan_data_markers(marker_map: Dict[int, str], include_exec: bool) -> List[Hit]:
    out: List[Hit] = []
    marker_set = set(marker_map.keys())
    seen_data = set()
    seen_xref = set()
    scanned_any = False

    for seg in idautils.Segments():
        start = idc.get_segm_start(seg)
        end = idc.get_segm_end(seg)
        perm = idc.get_segm_attr(seg, idc.SEGATTR_PERM)
        if not include_exec and (perm & SEGPERM_EXEC):
            continue
        if end - start < 4:
            continue
        scanned_any = True

        ea = start
        lim = end - 4
        while ea <= lim:
            v = idc.get_wide_dword(ea) & 0xFFFFFFFF
            if v in marker_set:
                key = (ea, v)
                if key not in seen_data:
                    seen_data.add(key)
                    out.append(
                        Hit(
                            "data",
                            ea,
                            marker_map[v],
                            f"{marker_map[v]} in data (0x{v:X})",
                            idc.BADADDR,
                            "",
                        )
                    )
                for xr in idautils.XrefsTo(ea, 0):
                    frm = int(xr.frm)
                    xk = (frm, ea, v)
                    if xk in seen_xref:
                        continue
                    seen_xref.add(xk)
                    fs, fn = _func_info(frm)
                    out.append(
                        Hit(
                            "data_xref",
                            frm,
                            marker_map[v],
                            f"xref to data marker {marker_map[v]} @0x{ea:X}",
                            fs,
                            fn,
                        )
                    )
            ea += 1
    if not scanned_any:
        return []
    return out


def _find_data_marker_hits(marker_map: Dict[int, str]) -> List[Hit]:
    # First pass: prefer non-executable segments to reduce noise.
    out = _scan_data_markers(marker_map, include_exec=False)
    if out:
        return out
    # Fallback: some IDBs mark all segments executable.
    ida_kernwin.msg("[*] No marker hits in non-exec segments, retrying with all segments...\n")
    return _scan_data_markers(marker_map, include_exec=True)


def _find_string_hits() -> List[Hit]:
    out: List[Hit] = []
    needles = [s.lower() for s in STRING_MARKERS]
    siter = idautils.Strings()
    siter.setup(strtypes=[ida_nalt.STRTYPE_C, ida_nalt.STRTYPE_C_16], minlen=4)

    for s in siter:
        sval = str(s)
        low = sval.lower()
        match = None
        for n in needles:
            if n in low:
                match = n
                break
        if not match:
            continue
        sea = int(s.ea)
        for xr in idautils.XrefsTo(sea, 0):
            ea = xr.frm
            fs, fn = _func_info(ea)
            text = f"string '{sval[:96]}' xref"
            out.append(Hit("str", ea, f"STR_{match}", text, fs, fn))
    return out


def _iter_imports() -> Iterable[Tuple[int, str, str]]:
    qty = ida_nalt.get_import_module_qty()
    for i in range(qty):
        mod = ida_nalt.get_import_module_name(i) or f"mod_{i}"
        entries: List[Tuple[int, str, int]] = []

        def _cb(ea: int, name: Optional[str], ord_: int) -> bool:
            entries.append((ea, name or f"ord_{ord_}", ord_))
            return True

        ida_nalt.enum_import_names(i, _cb)
        for ea, name, _ord in entries:
            yield (ea, mod, name)


def _find_api_xref_hits() -> List[Hit]:
    out: List[Hit] = []
    needles = {n.lower() for n in CONFIG_API_MARKERS}
    seen = set()
    for imp_ea, mod, name in _iter_imports():
        if name.lower() not in needles:
            continue
        for xr in idautils.XrefsTo(imp_ea, 0):
            frm = int(xr.frm)
            key = (frm, imp_ea)
            if key in seen:
                continue
            seen.add(key)
            fs, fn = _func_info(frm)
            out.append(
                Hit(
                    "api_xref",
                    frm,
                    f"API_{name}",
                    f"xref import {mod}!{name} @0x{imp_ea:X}",
                    fs,
                    fn,
                )
            )
    return out


def _rank_functions(hits: Sequence[Hit]) -> List[Tuple[int, str, int]]:
    score: Dict[int, int] = {}
    name: Dict[int, str] = {}
    for h in hits:
        if h.func_start == idc.BADADDR:
            continue
        if h.kind == "imm":
            w = 3
        elif h.kind == "data_xref":
            w = 2
        elif h.kind == "api_xref":
            w = 2
        else:
            w = 1
        score[h.func_start] = score.get(h.func_start, 0) + w
        name[h.func_start] = h.func_name
    ranked = [(ea, name.get(ea, f"sub_{ea:X}"), sc) for ea, sc in score.items()]
    ranked.sort(key=lambda t: t[2], reverse=True)
    return ranked


def _write_csv(path: str, hits: Sequence[Hit]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["kind", "ea", "rva", "marker", "text", "func_start", "func_name"])
        base = idaapi.get_imagebase()
        for h in hits:
            rva = h.ea - base
            w.writerow(
                [
                    h.kind,
                    f"0x{h.ea:08X}",
                    f"0x{rva:08X}",
                    h.marker,
                    h.text,
                    "" if h.func_start == idc.BADADDR else f"0x{h.func_start:08X}",
                    h.func_name,
                ]
            )


def main() -> None:
    if not require_ida():
        return
    base = idaapi.get_imagebase()
    ida_kernwin.msg(f"[*] Chrysalis config path mapper image_base=0x{base:08X}\n")
    extra_raw = ida_kernwin.ask_str(
        "",
        0,
        "Extra marker DWORDs (comma-separated, optional), ex: 0x2C5D0,0x116A7",
    )
    marker_map = dict(IMM_MARKERS)
    marker_map.update(_parse_extra_markers(extra_raw or ""))

    hits = (
        _find_imm_hits()
        + _find_data_marker_hits(marker_map)
        + _find_string_hits()
        + _find_api_xref_hits()
    )
    hits.sort(key=lambda h: h.ea)

    for h in hits:
        color = 0xE8FFF0
        if h.kind == "data_xref":
            color = 0xFFF8E8
        elif h.kind == "api_xref":
            color = 0xE8F4FF
        _annotate(h.ea, f"CONFIG_PATH {h.kind}: {h.text}", color=color)

    ranked = _rank_functions(hits)
    ida_kernwin.msg(f"[+] total_hits={len(hits)} candidate_functions={len(ranked)}\n")
    for ea, fn, sc in ranked[:20]:
        ida_kernwin.msg(f"    score={sc:>3} func=0x{ea:08X} {fn}\n")
        idc.set_func_cmt(ea, f"CONFIG_PATH_CANDIDATE score={sc}", 0)

    if ida_kernwin.ask_yn(1, "Export config-path hits CSV?") == 1:
        out = ida_kernwin.ask_file(True, "*.csv", "Save config path CSV report")
        if out:
            _write_csv(out, hits)
            ida_kernwin.msg(f"[+] wrote CSV: {out}\n")


if __name__ == "__main__":
    main()
