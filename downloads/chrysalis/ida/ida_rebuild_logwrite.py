#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IDAPython: rebuild/normalize the `LogWrite` decompilation view for Chrysalis log.dll.

Step 1 (CLI/headless):
  Windows: idat64.exe -A -Sida_rebuild_logwrite.py <target_binary>
  macOS/Linux: idat64 -A -Sida_rebuild_logwrite.py <target_binary>

Targets:
  - LogWrite at VA 0x10001B20 (default)
  - Resolver at VA 0x100014E0 (default)
  - Decrypt routine at VA 0x10001640 (default)

What this script does:
1) Ensures function names and function prototypes are applied.
2) Adds local C types (PFN_VirtualProtect, LOGWRITE_STAGE1_ARGS, etc.).
3) Renames key Hex-Rays locals (`v3` -> `stage1Args`, etc.).
4) Applies local variable types in Hex-Rays so pseudocode is readable.
5) Adds a call-site comment with the canonical WinAPI `VirtualProtect` signature.
6) Normalizes `mw_decrypt` as no-arg in this sample (callsite has no pushes).
7) Adds a dedicated reconstruction pass for `mw_decrypt`:
   - helper-function names,
   - key-block comments,
   - best-effort local variable renaming.

Run inside IDA with Hex-Rays available.
"""

from __future__ import annotations

import sys

IN_IDA = True
try:
    import ida_funcs  # type: ignore[import-not-found]
    import ida_hexrays  # type: ignore[import-not-found]
    import ida_kernwin  # type: ignore[import-not-found]
    import idaapi  # type: ignore[import-not-found]
    import ida_typeinf  # type: ignore[import-not-found]
    import idautils  # type: ignore[import-not-found]
    import idc  # type: ignore[import-not-found]
except Exception:
    IN_IDA = False
    ida_funcs = None  # type: ignore[assignment]
    ida_hexrays = None  # type: ignore[assignment]
    ida_kernwin = None  # type: ignore[assignment]
    idaapi = None  # type: ignore[assignment]
    ida_typeinf = None  # type: ignore[assignment]
    idautils = None  # type: ignore[assignment]
    idc = None  # type: ignore[assignment]

def require_ida() -> bool:
    if IN_IDA:
        return True
    sys.stderr.write("[!] Run this script inside IDA (GUI or idat -A -S).\n")
    return False


# Default VAs from your sample.
LOGWRITE_VA = 0x10001B20
RESOLVER_VA = 0x100014E0
DECRYPT_VA = 0x10001640
LOADLIB_VA = 0x100014C0
GETPROC_VA = 0x100014D0
VEC_APPEND_BYTE_VA = 0x10001ED0
KEYBUF_INIT_VA = 0x10002010
TRANSFORM_STAGE_VA = 0x10001270
ALLOC_GUARDED_VA = 0x10001D10


LOCAL_TYPES = r"""
typedef unsigned long  DWORD;
typedef int            BOOL;
typedef unsigned int   SIZE_T;
typedef void          *LPVOID;
typedef DWORD         *PDWORD;

typedef BOOL (__stdcall *PFN_VirtualProtect)(
  LPVOID lpAddress,
  SIZE_T dwSize,
  DWORD  flNewProtect,
  PDWORD lpflOldProtect
);

typedef int (__cdecl *PFN_Stage1Entry)(DWORD *args);

typedef struct _LOGWRITE_STAGE1_ARGS {
  DWORD magic;            // [0]
  DWORD region_count;     // [1]
  DWORD rva0;             // [2]
  DWORD rva1;             // [3]
  DWORD rva2;             // [4]
  DWORD rva3;             // [5]
  DWORD rva4;             // [6]
  DWORD rva5_unused;      // [7]
  DWORD rva6_unused;      // [8]
  DWORD size0;            // [9]
  DWORD size1;            // [10]
  DWORD size2;            // [11]
  DWORD size3;            // [12]
  DWORD size4;            // [13]
  DWORD size5_unused;     // [14]
  DWORD size6_unused;     // [15]
  DWORD image_base;       // [16]
  DWORD reserved0;        // [17]
  DWORD stage1_len;       // [18]
  DWORD config_rva;       // [19]
  DWORD shellcode_ptr;    // [20]
  DWORD pLoadLibraryA;    // [21]
  DWORD pGetProcAddress;  // [22]
  DWORD scratch;          // [23]
  DWORD reserved1;        // [24]
} LOGWRITE_STAGE1_ARGS;
"""


def _ea_from_user(default_va: int, prompt: str) -> int:
    base = idaapi.get_imagebase()
    raw = ida_kernwin.ask_str(f"0x{default_va:X}", 0, prompt)
    if not raw:
        v = default_va
    else:
        try:
            v = int(raw, 0)
        except Exception:
            v = default_va
    if v < base:
        # Treat user input as RVA.
        return base + v
    return v


def _ensure_func(ea: int) -> bool:
    f = ida_funcs.get_func(ea)
    if f:
        return True
    return bool(ida_funcs.add_func(ea))


def _set_name(ea: int, name: str) -> bool:
    if ea == idc.BADADDR:
        return False
    return bool(idc.set_name(ea, name, idc.SN_NOWARN))


def _set_type(ea: int, decl: str) -> bool:
    if ea == idc.BADADDR:
        return False
    return bool(idc.SetType(ea, decl))


def _parse_local_types() -> None:
    idc.parse_decls(LOCAL_TYPES, idc.PT_SILENT)


def _decompile(ea: int):
    try:
        return ida_hexrays.decompile(ea)
    except Exception:
        return None


def _rename_lvar(func_ea: int, old_name: str, new_name: str) -> bool:
    cfunc = _decompile(func_ea)
    if not cfunc:
        return False

    # Preferred path on newer IDA builds.
    try:
        if cfunc.rename_lvar(old_name, new_name, True):
            return True
    except Exception:
        pass

    # Fallback: direct user-lvar edit.
    try:
        for lv in cfunc.get_lvars():
            if lv.name != old_name:
                continue
            lsi = ida_hexrays.lvar_saved_info_t()
            lsi.ll = lv
            lsi.name = new_name
            if ida_hexrays.modify_user_lvar_info(func_ea, ida_hexrays.MLI_NAME, lsi):
                return True
    except Exception:
        return False
    return False


def _set_lvar_type(func_ea: int, lvar_name: str, type_decl: str) -> bool:
    cfunc = _decompile(func_ea)
    if not cfunc:
        return False

    tif = ida_typeinf.tinfo_t()
    # Parse as declaration statement, e.g. "PFN_VirtualProtect pVirtualProtect;"
    if not ida_typeinf.parse_decl(tif, None, type_decl, ida_typeinf.PT_SIL):
        return False

    try:
        for lv in cfunc.get_lvars():
            if lv.name != lvar_name:
                continue
            lsi = ida_hexrays.lvar_saved_info_t()
            lsi.ll = lv
            lsi.type = tif
            return bool(ida_hexrays.modify_user_lvar_info(func_ea, ida_hexrays.MLI_TYPE, lsi))
    except Exception:
        return False
    return False


def _annotate_virtualprotect_signature(logwrite_ea: int) -> int:
    """
    Add a canonical signature comment near the call that uses immediate 0x200000.
    """
    sig = (
        "BOOL VirtualProtect(LPVOID lpAddress, SIZE_T dwSize, "
        "DWORD flNewProtect, PDWORD lpflOldProtect);"
    )
    hits = 0
    f = ida_funcs.get_func(logwrite_ea)
    if not f:
        return 0
    for ea in idautils.FuncItems(f.start_ea):
        if idc.get_operand_type(ea, 0) == idc.o_imm and (idc.get_operand_value(ea, 0) & 0xFFFFFFFF) == 0x200000:
            idc.set_cmt(ea, "VirtualProtect size arg (0x200000)", 0)
            prev = idc.prev_head(ea, f.start_ea)
            # Walk backward a bit to find likely call.
            for _ in range(8):
                if prev == idc.BADADDR or prev < f.start_ea:
                    break
                if idc.print_insn_mnem(prev).lower() == "call":
                    idc.set_cmt(prev, sig, 0)
                    hits += 1
                    break
                prev = idc.prev_head(prev, f.start_ea)
    return hits


def _va_by_delta(current_base_ea: int, default_base_ea: int, default_va: int) -> int:
    """
    Translate a known VA from the reference sample by relative delta from the
    selected function base. This keeps comments valid even if user fed RVA.
    """
    return current_base_ea + (default_va - default_base_ea)


def _annotate_decrypt_blocks(decrypt_ea: int) -> int:
    """
    Add concise comments at key algorithm blocks in mw_decrypt.
    """
    cmt = {
        0x100016A2: "init dynamic seed vector from dword_10016354 (4 bytes)",
        0x10001763: "build 0x20-byte key material buffer",
        0x10001774: "key[i] = seed_bytes[i % seed_len] ^ (0x55 * i)",
        0x10001793: "rolling mix: key[i] = (key[i] + key[i-1]) ^ 0xAA",
        0x100017A9: "copy encrypted Shellcode[Size] into temporary string buffer",
        0x10001856: "core transform/decrypt stage (sub_10001270)",
        0x10001880: "memmove decrypted bytes back into Shellcode buffer",
        0x10001996: "free temporary dynamic seed/key buffers",
    }
    hits = 0
    for ref_va, text in cmt.items():
        ea = _va_by_delta(decrypt_ea, DECRYPT_VA, ref_va)
        if idc.get_full_flags(ea) != 0:
            idc.set_cmt(ea, text, 0)
            hits += 1
    return hits


def _rebuild_mw_decrypt(decrypt_ea: int) -> tuple[int, int, int]:
    """
    Best-effort decompiler cleanup for mw_decrypt:
    - helper names
    - function comment
    - lvar rename/type hints
    - key-block assembly comments
    """
    # Helper subroutines used by mw_decrypt; names chosen by behavior.
    helper_names = [
        (_va_by_delta(decrypt_ea, DECRYPT_VA, VEC_APPEND_BYTE_VA), "mw_seedvec_append_byte"),
        (_va_by_delta(decrypt_ea, DECRYPT_VA, KEYBUF_INIT_VA), "mw_keybuf_init"),
        (_va_by_delta(decrypt_ea, DECRYPT_VA, TRANSFORM_STAGE_VA), "mw_stage1_transform"),
        (_va_by_delta(decrypt_ea, DECRYPT_VA, ALLOC_GUARDED_VA), "mw_guarded_alloc"),
    ]
    named = 0
    for ea, nm in helper_names:
        if _set_name(ea, nm):
            named += 1

    idc.set_func_cmt(
        decrypt_ea,
        (
            "Custom stage1 decrypt routine. No explicit stack args at callsite; "
            "uses a custom frame/SEH prologue and caller context. "
            "Derives key material from dword_10016354, builds 0x20-byte schedule, "
            "runs transform helper, then writes plaintext back into Shellcode."
        ),
        0,
    )

    # Best-effort local variable renames. Hex-Rays names may vary by version.
    rename_map = [
        ("v23", "seed_word"),
        ("v25", "seed_byte"),
        ("v26", "key_state"),
        ("v27", "key_bytes"),
        ("v28", "key_cur"),
        ("v29", "key_end"),
        ("v30", "shellcode_str"),
        ("v31", "shellcode_len"),
        ("n15", "shellcode_cap"),
        ("v33", "decrypted_span"),
        ("v34", "decrypted_end"),
        ("v35", "work_span"),
        ("v36", "work_end"),
        ("v37", "seed_vec"),
        ("v38", "seed_vec_end"),
        ("v42", "try_state"),
        ("v43", "saved_ebp"),
        ("v44", "saved_retaddr"),
    ]
    renamed = 0
    for old, new in rename_map:
        if _rename_lvar(decrypt_ea, old, new):
            renamed += 1

    type_map = [
        ("seed_word", "unsigned int seed_word;"),
        ("seed_byte", "unsigned char seed_byte;"),
        ("key_bytes", "unsigned char *key_bytes;"),
        ("shellcode_len", "int shellcode_len;"),
        ("shellcode_cap", "unsigned int shellcode_cap;"),
    ]
    typed = 0
    for name, decl in type_map:
        if _set_lvar_type(decrypt_ea, name, decl):
            typed += 1

    block_cmts = _annotate_decrypt_blocks(decrypt_ea)
    return named, renamed, typed + block_cmts


def main() -> None:
    if not require_ida():
        return
    if not ida_hexrays.init_hexrays_plugin():
        ida_kernwin.msg("[!] Hex-Rays is required for local-variable rebuild.\n")
        return

    logwrite_ea = _ea_from_user(LOGWRITE_VA, "LogWrite VA (or RVA)")
    resolver_ea = _ea_from_user(RESOLVER_VA, "mw_apihashing VA (or RVA)")
    decrypt_ea = _ea_from_user(DECRYPT_VA, "mw_decrypt VA (or RVA)")

    ida_kernwin.msg(
        f"[*] Rebuild LogWrite: logwrite=0x{logwrite_ea:08X} "
        f"resolver=0x{resolver_ea:08X} decrypt=0x{decrypt_ea:08X}\n"
    )

    _parse_local_types()

    _ensure_func(logwrite_ea)
    _ensure_func(resolver_ea)
    _ensure_func(decrypt_ea)

    # Function/global naming.
    _set_name(logwrite_ea, "LogWrite")
    _set_name(resolver_ea, "mw_apihashing")
    _set_name(decrypt_ea, "mw_decrypt")
    _set_name(LOADLIB_VA, "_LoadLibraryA")
    _set_name(GETPROC_VA, "_GetProcAddress")

    # Function prototypes.
    _set_type(logwrite_ea, "int __cdecl LogWrite(void);")
    _set_type(
        resolver_ea,
        "void * __cdecl mw_apihashing(unsigned int module_or_seed, unsigned int api_hash);",
    )
    # In this sample, caller performs `call mw_decrypt` with no explicit stack args.
    # Model it as no-arg to avoid undefined pseudo-arguments in Hex-Rays.
    _set_type(decrypt_ea, "void __cdecl mw_decrypt(void);")
    _set_type(LOADLIB_VA, "void * __stdcall _LoadLibraryA(const char *lpLibFileName);")
    _set_type(GETPROC_VA, "void * __stdcall _GetProcAddress(void *hModule, const char *lpProcName);")

    # Local-variable renaming pass (best effort).
    rename_map = [
        ("VirtualProtect", "pVirtualProtect"),
        ("lpflOldProtect", "oldProtect"),
        ("v3", "stage1Args"),
        ("v4", "stage1Args"),
    ]
    renamed = 0
    for old, new in rename_map:
        if _rename_lvar(logwrite_ea, old, new):
            renamed += 1

    # Local-variable typing pass (best effort).
    type_map = [
        ("pVirtualProtect", "PFN_VirtualProtect pVirtualProtect;"),
        ("oldProtect", "DWORD oldProtect;"),
        ("stage1Args", "LOGWRITE_STAGE1_ARGS stage1Args;"),
    ]
    typed = 0
    for name, decl in type_map:
        if _set_lvar_type(logwrite_ea, name, decl):
            typed += 1

    helper_named, dec_renamed, dec_typed_or_cmts = _rebuild_mw_decrypt(decrypt_ea)

    # VirtualProtect call signature comment.
    sig_hits = _annotate_virtualprotect_signature(logwrite_ea)

    # Clarify decrypt-call calling convention at call site(s) inside LogWrite.
    dec_cmt_hits = 0
    f = ida_funcs.get_func(logwrite_ea)
    if f:
        for ea in idautils.FuncItems(f.start_ea):
            if idc.print_insn_mnem(ea).lower() != "call":
                continue
            op0 = idc.get_operand_value(ea, 0)
            if (op0 & 0xFFFFFFFF) == (decrypt_ea & 0xFFFFFFFF):
                idc.set_cmt(
                    ea,
                    "mw_decrypt() uses internal/caller context; no explicit stack args at this callsite",
                    0,
                )
                dec_cmt_hits += 1

    ida_kernwin.msg(f"[+] Local renames applied: {renamed}\n")
    ida_kernwin.msg(f"[+] Local types applied:   {typed}\n")
    ida_kernwin.msg(f"[+] VP signature comments: {sig_hits}\n")
    ida_kernwin.msg(f"[+] Decrypt call comments: {dec_cmt_hits}\n")
    ida_kernwin.msg(f"[+] Decrypt helper names:  {helper_named}\n")
    ida_kernwin.msg(f"[+] Decrypt lvar renames:  {dec_renamed}\n")
    ida_kernwin.msg(f"[+] Decrypt types/comments:{dec_typed_or_cmts}\n")
    try:
        ida_hexrays.clear_cached_cfuncs()
    except Exception:
        pass
    ida_kernwin.msg("[+] Done. Refresh pseudocode (F5) in LogWrite.\n")


if __name__ == "__main__":
    main()
