import sys
import os
import argparse
import struct
import hashlib
import pefile
from unicorn import Uc, UcError, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE, UC_HOOK_MEM_INVALID, UC_HOOK_MEM_WRITE, UC_MEM_FETCH_UNMAPPED, UC_MEM_READ_UNMAPPED, UC_MEM_WRITE_UNMAPPED # pyright: ignore[reportPrivateImportUsage]
from unicorn.x86_const import *
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from capstone.x86 import X86_OP_MEM

# Bump this when sharing logs so we can confirm what code actually ran.
SCRIPT_VERSION = "2026-02-06u"

# ----------------------------
# Config you care about
# ----------------------------
BREAK_RVA = 0x1C11            # your .text:10001C11 (IDA base 0x10000000)
DUMP_MAX = 0x400000           # max bytes to attempt dumping
DUMP_MIN = 0x1000             # minimum to keep if heuristics fail
OUTFILE  = "shellcode.bin"
OUTFILE_FULL = "shellcode_full.bin"   # larger dump from stage1 base (see STAGE1_FULL_DUMP_LEN)
STAGE2_OUTFILE = "stage2_payload.bin"
STAGE2_LIVE_OUTFILE = "stage2_live_dump.bin"
STAGE2_MEMIMG_OUTFILE = "stage2_mem_image.bin"
STAGE2_MEMIMG_BASE = 0x00400000
STAGE2_SPAN_OUTFILE = "stage2_written_span.bin"
STAGE2_TRACE = "stage2_trace.log"
MAX_INSN = 5_000_000          # instruction cap to avoid infinite loops
STAGE2_MAX_INSN = 2_000_000   # per-candidate cap (bruteforce stage2 mode)
STAGE2_DUMP_SIZE = 0x40000    # 256KB default dump for shellcode
FORCE_BREAK = False           # set True to jump to breakpoint from anti-analysis region
RUN_INIT_ONLY = False         # set True to only run init and capture seed

# Stage1 (the decrypted buffer) often includes exception-driven / anti-emulation junk instructions
# (e.g., IN/OUT, INT, RETF, segment register ops, stack pivot). We can't emulate Windows SEH here,
# so we optionally skip a small set of these while executing inside stage1.
STAGE1_SKIP_MAX = 10_000
# Cap stage1 execution in --mode full so we don't run forever.
STAGE1_MAX_INSN = 20_000_000
# Many samples VirtualProtect() a full 0x200000 region for the stage1 buffer and keep data past
# the initially-reported "out_len". Dumping the full region helps offline extraction of stage2.
STAGE1_FULL_DUMP_LEN = 0x200000

# ----------------------------
# log.dll globals (RVA offsets)
# ----------------------------
G_SEED_RVA = 0x16354
G_LEN_RVA  = 0x16358
G_K32_RVA  = 0x1635C
G_BUF_RVA  = 0x16360

# ----------------------------
# Helpers
# ----------------------------
def align_down(x, a): return x & ~(a - 1)
def align_up(x, a): return (x + (a - 1)) & ~(a - 1)

def resolve_input_path(path: str, input_dir: str) -> str:
    """
    Convenience: if the user passes just a filename and it doesn't exist in CWD,
    automatically resolve it from input_dir.
    """
    if not path:
        return path
    if os.path.exists(path):
        return path
    # Only auto-resolve "bare" paths (no directory component)
    if os.path.basename(path) == path:
        cand = os.path.join(input_dir, path)
        if os.path.exists(cand):
            return cand
    return path

def resolve_output_path(path: str, output_dir: str) -> str:
    """
    If path is a bare filename, write it under output_dir.
    If it already contains a directory component or is absolute, keep it as-is.
    """
    if not path:
        return path
    if path.lower() == "none":
        return path
    if os.path.isabs(path) or os.path.dirname(path):
        return path
    return os.path.join(output_dir, path)

def read_cstr(mu: Uc, addr: int, max_len: int = 0x200) -> bytes:
    if not addr:
        return b""
    out = bytearray()
    for i in range(max_len):
        try:
            b = mu.mem_read(addr + i, 1)
        except Exception:
            break
        if b == b"\x00":
            break
        out += b
    return bytes(out)

def read_wstr(mu: Uc, addr: int, max_chars: int = 0x200) -> str:
    if not addr:
        return ""
    bs = bytearray()
    for i in range(max_chars):
        try:
            c = mu.mem_read(addr + i * 2, 2)
        except Exception:
            break
        if c == b"\x00\x00":
            break
        bs += c
    try:
        return bs.decode("utf-16le", errors="ignore")
    except Exception:
        return ""

def is_probably_end(blob: bytes) -> int:
    """
    Heuristic trimming:
    - If we see a long run of 0x00 or 0xCC after some data, trim there.
    - Otherwise keep full blob.
    """
    if len(blob) <= DUMP_MIN:
        return len(blob)

    # Look for 32 consecutive nulls or int3s after at least DUMP_MIN
    patterns = [b"\x00" * 32, b"\xCC" * 32]
    for pat in patterns:
        idx = blob.find(pat, DUMP_MIN)
        if idx != -1:
            return idx
    return len(blob)

def parse_imm_from_op_str(op_str: str):
    s = (op_str or "").strip()
    try:
        if s.startswith("0x") or s.startswith("-0x"):
            return int(s, 16)
        return int(s, 10)
    except Exception:
        return None

def op_str_has_seg_reg(op_str: str) -> bool:
    s = (op_str or "").lower().replace(" ", "")
    # Match things like: "ds,edi" or "es:[edi],dx" or "movds,ax" (capstone formats vary)
    for seg in ("ds", "es", "ss", "cs", "fs", "gs"):
        if s.startswith(seg + ","):
            return True
        if (seg + ":[") in s:
            return True
    return False

def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def write_stage1_base_file(path: str, base_va: int, length: int, sha256_hex: str):
    try:
        with open(path + ".base.txt", "w") as f:
            f.write(f"base_va=0x{base_va:08X}\n")
            f.write(f"length=0x{length:X}\n")
            f.write(f"sha256={sha256_hex}\n")
    except Exception:
        pass

def write_base_file(path: str, base_va: int, length: int, extra: dict | None = None):
    try:
        with open(path + ".base.txt", "w") as f:
            f.write(f"base_va=0x{base_va:08X}\n")
            f.write(f"length=0x{length:X}\n")
            if extra:
                for k, v in extra.items():
                    f.write(f"{k}={v}\n")
    except Exception:
        pass

# ----------------------------
# Output tee (stdout log)
# ----------------------------
class TeeStdout:
    def __init__(self, *streams):
        self.streams = streams

    def write(self, data):
        for s in self.streams:
            try:
                s.write(data)
            except Exception:
                pass

    def flush(self):
        for s in self.streams:
            try:
                s.flush()
            except Exception:
                pass

# ----------------------------
# Minimal WinAPI stubs
# ----------------------------
class WinStubs:
    def __init__(self, mu: Uc):
        self.mu = mu
        self.alloc_base = 0x30000000
        self.alloc_page = 0x1000
        self.allocations = {}  # addr -> size
        self.process_heap = 0x70000000
        self.handle_base = 0x70000000
        self.files = {}  # handle -> {"data": bytes, "pos": int}
        self.default_data = b""
        self.default_pos = 0
        self.payload_data = b""
        self.tls_next = 1
        self.tls = {}  # idx -> value

    def virtual_alloc(self, lpAddress, dwSize, flAllocationType, flProtect):
        size = align_up(dwSize, self.alloc_page)
        if size == 0:
            size = self.alloc_page
        # If the caller requests a specific address, try to honor it. Stage payloads often
        # expect to build a PE at 0x00400000.
        if lpAddress:
            req = align_down(lpAddress, self.alloc_page)
            # If it's already mapped, treat as success.
            try:
                _ = self.mu.mem_read(req, 1)
                self.allocations.setdefault(req, size)
                print(f"[*] VirtualAlloc reuse-mapped 0x{req:08X}-0x{req+size:08X} size=0x{size:X}")
                return req
            except Exception:
                pass
            try:
                for page in range(req, req + size, self.alloc_page):
                    self.mu.mem_map(page, self.alloc_page)
                self.allocations[req] = size
                print(f"[*] VirtualAlloc mapped 0x{req:08X}-0x{req+size:08X} size=0x{size:X} (requested)")
                return req
            except Exception:
                # Fall back to heap-style allocations below.
                pass

        addr = align_up(self.alloc_base, self.alloc_page)
        self.alloc_base = addr + size

        # map RWX for simplicity in emulation
        # Force-map page by page to ensure it's readable/executable later.
        for page in range(addr, addr + size, self.alloc_page):
            try:
                self.mu.mem_map(page, self.alloc_page)
            except Exception:
                pass
        print(f"[*] VirtualAlloc mapped 0x{addr:08X}-0x{addr+size:08X} size=0x{size:X}")
        self.allocations[addr] = size
        return addr

    def heap_alloc(self, hHeap, dwFlags, dwBytes):
        addr = self.virtual_alloc(0, dwBytes, 0, 0)
        # HEAP_ZERO_MEMORY = 0x00000008
        if dwFlags & 0x8:
            try:
                self.mu.mem_write(addr, b"\x00" * min(align_up(dwBytes, 1), 0x1000000))
            except Exception:
                pass
        return addr

    def heap_size(self, hHeap, dwFlags, lpMem):
        for base, sz in self.allocations.items():
            if base == lpMem:
                return sz
        return 0

    def heap_realloc(self, hHeap, dwFlags, lpMem, dwBytes):
        if not lpMem:
            return self.heap_alloc(hHeap, dwFlags, dwBytes)
        old_sz = self.heap_size(hHeap, dwFlags, lpMem)
        new_addr = self.heap_alloc(hHeap, dwFlags, dwBytes)
        if old_sz:
            try:
                data = bytes(self.mu.mem_read(lpMem, min(old_sz, dwBytes)))
                self.mu.mem_write(new_addr, data)
            except Exception:
                pass
        # We don't unmap old pages (would require tracking exact page set); emulate success.
        return new_addr

    def virtual_protect(self, lpAddress, dwSize, flNewProtect, lpflOldProtect):
        # no-op for emulator
        return 1

    def load_library_a(self, lpLibFileName):
        # return a fake module handle
        return 0x50000000

    def get_proc_address(self, hModule, lpProcName):
        # return a fake function pointer (not used if your code calls IAT directly)
        return 0x50001000

    def memcpy(self, dst, src, n):
        data = self.mu.mem_read(src, n)
        self.mu.mem_write(dst, data)
        return dst

    def new_handle(self):
        h = self.handle_base
        self.handle_base += 4
        return h

    def open_file_bytes(self, data: bytes):
        h = self.new_handle()
        self.files[h] = {"data": data, "pos": 0}
        return h

    def read_file(self, h, n):
        f = self.files.get(h)
        if not f:
            return b""
        pos = f["pos"]
        chunk = f["data"][pos:pos + n]
        f["pos"] = pos + len(chunk)
        return chunk

    def read_default(self, n):
        pos = self.default_pos
        chunk = self.default_data[pos:pos + n]
        self.default_pos = pos + len(chunk)
        return chunk

    def tls_alloc(self) -> int:
        idx = self.tls_next
        self.tls_next += 1
        self.tls[idx] = 0
        return idx

    def tls_free(self, idx: int) -> int:
        self.tls.pop(idx, None)
        return 1

    def tls_get(self, idx: int) -> int:
        return int(self.tls.get(idx, 0)) & 0xFFFFFFFF

    def tls_set(self, idx: int, val: int) -> int:
        self.tls[idx] = val & 0xFFFFFFFF
        return 1


# ----------------------------
# PE mapping into Unicorn
# ----------------------------
def map_pe(mu: Uc, pe: pefile.PE):
    image_base = pe.OPTIONAL_HEADER.ImageBase # type: ignore
    size_image = pe.OPTIONAL_HEADER.SizeOfImage # type: ignore
    page = 0x1000

    mu.mem_map(align_down(image_base, page), align_up(size_image, page))

    # Map headers
    headers = pe.get_memory_mapped_image()[: pe.OPTIONAL_HEADER.SizeOfHeaders] # type: ignore
    mu.mem_write(image_base, headers)

    # Map sections
    for s in pe.sections:
        va = image_base + s.VirtualAddress
        raw = s.get_data()
        mu.mem_write(va, raw)

    return image_base, size_image


def find_export_rva(pe: pefile.PE, name: str) -> int:
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]])
    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols: # type: ignore
        if exp.name and exp.name.decode(errors="ignore") == name:
            return exp.address  # RVA
    raise RuntimeError(f"Export not found: {name}")

# ----------------------------
# Emulation harness
# ----------------------------
def emulate_and_dump(dll_path: str, payload_path: str, mode: str, stop_at: str, output_dir: str):
    os.makedirs(output_dir, exist_ok=True)
    out_shellcode_path = os.path.join(output_dir, OUTFILE)
    out_shellcode_full_path = os.path.join(output_dir, OUTFILE_FULL)
    out_stage2_path = os.path.join(output_dir, STAGE2_OUTFILE)
    out_stage2_live_path = os.path.join(output_dir, STAGE2_LIVE_OUTFILE)
    out_stage2_memimg_path = os.path.join(output_dir, STAGE2_MEMIMG_OUTFILE)
    out_stage2_span_path = os.path.join(output_dir, STAGE2_SPAN_OUTFILE)
    out_stage2_trace_path = os.path.join(output_dir, STAGE2_TRACE)

    print(f"[*] emulate_logwrite_dump_shellcode.py {SCRIPT_VERSION} mode={mode} stop_at={stop_at}")
    pe = pefile.PE(dll_path, fast_load=False)
    if pe.FILE_HEADER.Machine != pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_I386"]: # type: ignore
        raise RuntimeError("This script is for 32-bit x86 DLLs only.")

    mu = Uc(UC_ARCH_X86, UC_MODE_32)
    stubs = WinStubs(mu)

    # Map NULL page and install a minimal fake DOS+PE header to avoid unmapped reads like [0x3C].
    mu.mem_map(0x00000000, 0x1000)
    mu.mem_write(0x00000000, b"MZ")
    mu.mem_write(0x0000003C, struct.pack("<I", 0x80))
    mu.mem_write(0x00000080, b"PE\x00\x00")

    image_base, size_image = map_pe(mu, pe)
    with open(dll_path, "rb") as f:
        dll_bytes = f.read()
    # Load encrypted payload for direct decrypt.
    try:
        with open(payload_path, "rb") as f:
            enc_payload = f.read()
    except Exception:
        enc_payload = None
    # Patch the anti-analysis block to a quick RET.
    try:
        mu.mem_write(image_base + 0xE180, b"\xC3")
    except Exception:
        pass
    stubs.default_data = dll_bytes
    # Patch security check to a RET to avoid raising exceptions during emulation.
    try:
        mu.mem_write(image_base + 0x220E, b"\xC3")
    except Exception:
        pass
    # Scratch buffer region used by stubs (e.g., ReadFile4 -> 0x200000).
    try:
        mu.mem_map(0x00200000, 0x00200000)
    except Exception:
        pass

    # Build IAT stubs to avoid jumping into import name table RVAs.
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
    STUB_BASE = 0x20000000
    STUB_SIZE = 0x10000
    mu.mem_map(STUB_BASE, STUB_SIZE)
    stub_map = {}
    stub_next = STUB_BASE
    name_to_stub = {}

    def add_stub(imp_name):
        nonlocal stub_next
        addr = stub_next
        stub_next += 0x10
        stub_map[addr] = imp_name
        # Prefer first mapping for name->stub.
        name_to_stub.setdefault(imp_name, addr)
        return addr

    for entry in pe.DIRECTORY_ENTRY_IMPORT: # type: ignore
        for imp in entry.imports:
            if not imp.name:
                continue
            name = imp.name.decode(errors="ignore")
            stub_addr = add_stub(name)
            mu.mem_write(imp.address, struct.pack("<I", stub_addr))

    # Hash constants passed to 0x100014E0 (resolver) in this sample.
    # NOTE: These constants are *not* raw api_hash(export_name).
    # The resolver compares:
    #   api_hash(export_name) == seed + constant
    # Where seed is derived from the first 0x100 bytes of the host EXE
    # (BluetoothService.exe in the Rapid7 chain). For this sample, that yields
    # seed=0x114DDB33, which makes e.g. VirtualProtect => 0x47C204CA.
    hash_to_api = {
        0xE2F5E21B: "GetModuleFileNameA",
        0x54BFC47B: "CreateFileW",
        0x053FAAA4: "ReadFile",
        0xD6410922: "CloseHandle",
        0x47C204CA: "VirtualProtect",
    }

    dyn_stub_addrs = {}
    def resolve_hash(hash_val):
        name = hash_to_api.get(hash_val)
        if not name:
            return 0
        if name not in dyn_stub_addrs:
            dyn_stub_addrs[name] = add_stub(name)
        return dyn_stub_addrs[name]

    logwrite_rva = find_export_rva(pe, "LogWrite")
    logwrite_va  = image_base + logwrite_rva
    break_va     = image_base + BREAK_RVA
    init_va      = image_base + 0x1000
    decrypt_va   = image_base + 0x1640
    seed_value   = 0x216707EA  # hash/finalizer of "kernel32.dll"

    g_seed = image_base + G_SEED_RVA
    g_len  = image_base + G_LEN_RVA
    g_k32  = image_base + G_K32_RVA
    g_buf  = image_base + G_BUF_RVA

    # Stack
    STACK_BASE = 0x0FF00000
    STACK_SIZE = 0x00100000
    mu.mem_map(STACK_BASE, STACK_SIZE)
    esp = STACK_BASE + STACK_SIZE - 0x1000
    mu.reg_write(UC_X86_REG_ESP, esp)

    # Fake args (stdcall-ish): LogWrite(arg1,arg2,arg3,arg4)
    # If it crashes due to arg expectations, you can tweak these.
    def push32(val):
        nonlocal esp
        esp -= 4
        mu.mem_write(esp, struct.pack("<I", val & 0xFFFFFFFF))
        mu.reg_write(UC_X86_REG_ESP, esp)

    # Return address (when target returns, we stop)
    RET_ADDR = 0x41414141

    def reset_stack(args=None):
        nonlocal esp
        esp = STACK_BASE + STACK_SIZE - 0x1000
        mu.reg_write(UC_X86_REG_ESP, esp)
        push32(RET_ADDR)
        if args:
            for val in args:
                push32(val)

    # If the DLL uses IAT calls, Unicorn will just execute into unmapped memory unless we patch.
    # We’ll instead hook invalid memory execution and treat some common patterns as "API calls".
    #
    # Practical approach: hook on invalid fetch; if EIP points into IAT/data, you can translate it.
    # For many samples, simpler is: hook on CODE and break at your target; often enough.

    dumped = {"done": False}
    returned = {"done": False}
    insn_count = {"n": 0}
    forced = {"done": False}
    last_write = {"addr": None, "size": 0}
    stage2 = {"found": False, "addr": None}
    init_done = {"done": False}
    stage2_active = {"on": False, "kind": "none"}  # kind: none|stage1|candidate
    stage2_candidates = []
    stage2_trace = {"fh": None}
    stage2_region = {"base": 0, "size": 0}
    stage2_invalid = {"n": 0}
    stage2_writes = {"n": 0, "last_insn": 0}
    stage2_pe_write = {"addr": None, "size": None}
    stage2_page_writes = {"counts": {}, "best_page": None}
    stage2_best_shellcode = {"addr": None, "score": None}
    stage1_entry = {"va": None, "len": None}
    stage1_ran = {"done": False}
    stage1_skip = {"n": 0}
    stage1_exc_skips = {"n": 0}
    stage1_fault = {"pending": False, "eip": 0, "next_eip": 0, "access": 0, "addr": 0, "disasm": ""}

    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True

    def decode_insn(address):
        try:
            code = bytes(mu.mem_read(address, 16))
        except Exception:
            return None
        for insn in md.disasm(code, address, count=1):
            return insn
        return None

    def patch_low_base_for_disp(insn, target_disp: int, new_base: int) -> bool:
        """
        If the current instruction has a memory operand with disp==target_disp and base reg value is 0,
        rewrite that base reg to new_base. Returns True if patched.
        """
        try:
            for op in insn.operands:
                if op.type != X86_OP_MEM:
                    continue
                if op.mem.disp != target_disp:
                    continue
                base_reg = op.mem.base
                if not base_reg:
                    continue
                try:
                    base_val = mu.reg_read(base_reg)
                except Exception:
                    continue
                if base_val != 0:
                    continue
                mu.reg_write(base_reg, new_base)
                return True
        except Exception:
            return False
        return False

    def map_range(addr, size):
        if size <= 0:
            return
        start = align_down(addr, 0x1000)
        end = align_up(addr + size, 0x1000)
        for page in range(start, end, 0x1000):
            try:
                mu.mem_map(page, 0x1000)
            except Exception:
                pass

    def map_fake_kernel32():
        # Minimal fake kernel32 with export table for stage2 API resolution.
        K32_BASE = 0x50000000
        K32_SIZE = 0x10000
        map_range(K32_BASE, K32_SIZE)
        # DOS header + PE header stub
        mu.mem_write(K32_BASE + 0x0, b"MZ")
        mu.mem_write(K32_BASE + 0x3C, struct.pack("<I", 0x80))
        mu.mem_write(K32_BASE + 0x80, b"PE\x00\x00")
        # Export directory layout
        export_rva = 0x2000
        funcs_rva = 0x2100
        names_rva = 0x2200
        ords_rva = 0x2300
        strings_rva = 0x2400

        api_names = [
            "LoadLibraryA",
            "GetProcAddress",
            "VirtualAlloc",
            "VirtualProtect",
            "VirtualFree",
            "GetModuleHandleA",
            "GetTickCount",
            "GetSystemTimeAsFileTime",
            "QueryPerformanceCounter",
        ]
        # Write strings
        name_rvas = []
        off = strings_rva
        for n in api_names:
            mu.mem_write(K32_BASE + off, n.encode() + b"\x00")
            name_rvas.append(off)
            off += len(n) + 1

        # Function RVAs (point to stubs)
        func_rvas = []
        stub_base = 0x3000
        for i, n in enumerate(api_names):
            func_rvas.append(stub_base + i * 0x10)

        # Write AddressOfFunctions
        for i, rva in enumerate(func_rvas):
            mu.mem_write(K32_BASE + funcs_rva + i * 4, struct.pack("<I", rva))
        # Write AddressOfNames
        for i, rva in enumerate(name_rvas):
            mu.mem_write(K32_BASE + names_rva + i * 4, struct.pack("<I", rva))
        # Write AddressOfNameOrdinals
        for i in range(len(api_names)):
            mu.mem_write(K32_BASE + ords_rva + i * 2, struct.pack("<H", i))

        # IMAGE_EXPORT_DIRECTORY
        # Characteristics, TimeDateStamp, MajorVersion, MinorVersion, Name, Base,
        # NumberOfFunctions, NumberOfNames, AddressOfFunctions, AddressOfNames, AddressOfNameOrdinals
        export_dir = struct.pack(
            "<IIHHIIIIIII",
            0, 0, 0, 0,
            0x2500, 1,
            len(api_names), len(api_names),
            funcs_rva, names_rva, ords_rva
        )
        mu.mem_write(K32_BASE + export_rva, export_dir)
        # Export name "kernel32.dll"
        mu.mem_write(K32_BASE + 0x2500, b"kernel32.dll\x00")

        # Record stubs so on_code can emulate
        for i, n in enumerate(api_names):
            stub_map[K32_BASE + func_rvas[i]] = n
        return K32_BASE

    def map_fake_ntdll():
        NTD_BASE = 0x60000000
        NTD_SIZE = 0x10000
        map_range(NTD_BASE, NTD_SIZE)
        mu.mem_write(NTD_BASE + 0x0, b"MZ")
        mu.mem_write(NTD_BASE + 0x3C, struct.pack("<I", 0x80))
        mu.mem_write(NTD_BASE + 0x80, b"PE\x00\x00")
        export_rva = 0x2000
        funcs_rva = 0x2100
        names_rva = 0x2200
        ords_rva = 0x2300
        strings_rva = 0x2400
        api_names = [
            "NtAllocateVirtualMemory",
            "NtProtectVirtualMemory",
            "NtQueryInformationProcess",
            "NtDelayExecution",
        ]
        name_rvas = []
        off = strings_rva
        for n in api_names:
            mu.mem_write(NTD_BASE + off, n.encode() + b"\x00")
            name_rvas.append(off)
            off += len(n) + 1
        func_rvas = []
        stub_base = 0x3000
        for i in range(len(api_names)):
            func_rvas.append(stub_base + i * 0x10)
        for i, rva in enumerate(func_rvas):
            mu.mem_write(NTD_BASE + funcs_rva + i * 4, struct.pack("<I", rva))
        for i, rva in enumerate(name_rvas):
            mu.mem_write(NTD_BASE + names_rva + i * 4, struct.pack("<I", rva))
        for i in range(len(api_names)):
            mu.mem_write(NTD_BASE + ords_rva + i * 2, struct.pack("<H", i))
        export_dir = struct.pack(
            "<IIHHIIIIIII",
            0, 0, 0, 0,
            0x2500, 1,
            len(api_names), len(api_names),
            funcs_rva, names_rva, ords_rva
        )
        mu.mem_write(NTD_BASE + export_rva, export_dir)
        mu.mem_write(NTD_BASE + 0x2500, b"ntdll.dll\x00")
        for i, n in enumerate(api_names):
            stub_map[NTD_BASE + func_rvas[i]] = n
        return NTD_BASE

    def init_fake_peb():
        """
        Provide a minimal TEB/PEB so shellcode using fs:[0x30] (PEB pointer)
        and fs:[0x00] (SEH chain head) doesn't immediately deref NULL / low pages.

        NOTE: Unicorn supports setting FS base via UC_X86_REG_FS_BASE.
        """
        PEB = 0x00070000
        LDR = 0x00071000
        LDR_ENTRY = 0x00072000

        # Map our tiny PEB structures.
        map_range(PEB, 0x3000)

        # NOTE: On this host, Unicorn crashes when mapping address 0 and when writing
        # UC_X86_REG_FS_BASE. We therefore cannot provide a real `fs:[...]` mapping.
        #
        # The current pipeline uses --mode logwrite to dump stage1 and relies on stubs for
        # resolver behavior; stage1 execution is best-effort and may still fail on true PEB-walk
        # logic. We keep a minimal PEB/LDR in normal memory for callers that obtain PEB by other
        # means (e.g. passed pointers / module lists), but we do NOT write to linear 0x0/0x30.

        # PEB->Ldr
        mu.mem_write(PEB + 0x0C, struct.pack("<I", LDR))

        # Ldr->InLoadOrderModuleList (self-linked)
        mu.mem_write(LDR + 0x0C, struct.pack("<I", LDR_ENTRY))
        mu.mem_write(LDR + 0x10, struct.pack("<I", LDR_ENTRY))

        # LDR_ENTRY: Flink/Blink
        mu.mem_write(LDR_ENTRY + 0x00, struct.pack("<I", LDR_ENTRY))
        mu.mem_write(LDR_ENTRY + 0x04, struct.pack("<I", LDR_ENTRY))

        # BaseAddress at +0x18 (kernel32 base) - enough for simple walkers.
        mu.mem_write(LDR_ENTRY + 0x18, struct.pack("<I", k32_base))

    def score_buffer(buf: bytes):
        if not buf:
            return (0, 0.0)
        nz = sum(1 for b in buf if b != 0)
        # rough entropy on first 4KB to keep it cheap
        sample = buf[:4096]
        from collections import Counter
        import math
        counts = Counter(sample)
        ent = 0.0
        for c in counts.values():
            p = c / len(sample)
            ent -= p * math.log2(p)
        return (nz, ent)

    def score_shellcode(buf: bytes):
        if not buf:
            return (0.0, 0.0, 0)
        nz, ent = score_buffer(buf)
        # Instruction density (how much disasm succeeds)
        total = 0
        insn_count = 0
        max_len = min(len(buf), 0x4000)
        for insn in md.disasm(buf[:max_len], 0):
            insn_count += 1
            total += insn.size
            if total >= max_len:
                break
        density = total / max_len if max_len else 0.0
        # Score: prefer lower entropy + higher density + more non-zero bytes
        score = (-ent * 10.0) + (density * 100.0) + (nz / 4096.0)
        return (score, ent, insn_count)

    def hash_name(s: bytes) -> int:
        edx = 0x811C9DC5
        for b in s:
            eax = b ^ edx
            edx = (eax * 0x1000193) & 0xFFFFFFFF
        eax = edx
        eax = ((eax >> 0xF) ^ edx) & 0xFFFFFFFF
        ecx = (eax * 0x85EBCA6B) & 0xFFFFFFFF
        eax = ((ecx >> 0xD) ^ ecx) & 0xFFFFFFFF
        return eax

    def resolve_hash_to_stub(h: int) -> int:
        # Map hash->API and return stub address if known.
        for addr, name in stub_map.items():
            try:
                if hash_name(name.encode()) == h:
                    return addr
            except Exception:
                pass
        return 0

    def in_stage2_region(addr):
        base = stage2_region["base"]
        size = stage2_region["size"]
        return base and base <= addr < base + size

    def in_allocations(addr):
        for base, sz in stubs.allocations.items():
            if base <= addr < base + sz:
                return True
        return False

    def in_stub_regions(addr):
        # IAT stubs + fake kernel32/ntdll ranges
        if 0x20000000 <= addr < 0x20010000:
            return True
        if 0x00200000 <= addr < 0x00400000:
            return True
        # Common PE mapping base
        if 0x00400000 <= addr < 0x02000000:
            return True
        if 0x50000000 <= addr < 0x50010000:
            return True
        if 0x60000000 <= addr < 0x60010000:
            return True
        return False

    def in_image(addr):
        return image_base <= addr < image_base + size_image

    def in_expected_exec(addr):
        return (
            in_stage2_region(addr)
            or in_allocations(addr)
            or in_stub_regions(addr)
            or in_image(addr)
        )

    def in_stage1(addr: int) -> bool:
        if stage1_entry["va"] is None or stage1_entry["len"] is None:
            return False
        return stage1_entry["va"] <= addr < stage1_entry["va"] + stage1_entry["len"]

    def _score_stage1_entry(raw: bytes, off: int) -> float | None:
        """
        Score a candidate stage1 entry offset by decoding a small window.
        Prefer dense, non-privileged instruction streams.
        """
        if off < 0 or off >= len(raw):
            return None
        window = raw[off : off + 0x80]
        if len(window) < 0x10:
            return None
        insn_count = 0
        total = 0
        bad = 0
        # Quick prologue bonuses
        bonus = 0
        if window[:3] == b"\x55\x8B\xEC":  # push ebp; mov ebp, esp
            bonus += 50
        if window[:2] == b"\x8B\xFF":  # mov edi, edi (msvc hotpatch)
            bonus += 10
        # call $+5; pop reg (position-independent)
        if len(window) >= 6 and window[0] == 0xE8 and window[1:5] == b"\x00\x00\x00\x00" and 0x58 <= window[5] <= 0x5F:
            bonus += 20

        for insn in md.disasm(window, 0x10000000 + off):
            insn_count += 1
            total += insn.size
            m = (insn.mnemonic or "").lower()
            if m.startswith("f") or m in ("in", "insb", "insw", "insd", "out", "outsb", "outsw", "outsd", "int", "into", "iret", "iretd", "hlt", "cli", "sti", "retf", "bound"):
                bad += 1
            if insn_count >= 12 or total >= 0x40:
                break
        if insn_count < 4:
            return None
        density = total / 0x40
        return density * 100 + insn_count * 3 + bonus - bad * 30

    def pick_stage1_entry_offset(raw: bytes) -> int:
        """
        Stage1 buffers in this family often start with junk bytes (privileged/FPU/SEH driven).
        Find a better entrypoint within the first 0x40000 bytes.
        """
        max_scan = min(len(raw), 0x40000)
        if max_scan < 0x40:
            return 0
        seed = set([0])
        for i in range(max_scan - 8):
            if raw[i:i+3] == b"\x55\x8B\xEC":
                seed.add(i)
            if raw[i:i+2] == b"\x8B\xFF":
                seed.add(i)
            if raw[i] == 0xFC and i + 6 < max_scan and raw[i+1] == 0xE8:
                seed.add(i)
            if raw[i] == 0xE8 and raw[i+1:i+5] == b"\x00\x00\x00\x00" and 0x58 <= raw[i+5] <= 0x5F:
                seed.add(i)
        for i in range(0, max_scan, 0x10):
            seed.add(i)

        best = (float("-inf"), 0)
        for off in seed:
            sc = _score_stage1_entry(raw[:max_scan], off)
            if sc is None:
                continue
            # Prefer non-zero offsets if scores tie.
            if sc > best[0] or (sc == best[0] and best[1] == 0 and off != 0):
                best = (sc, off)
        return best[1]

    def stage1_skip_insn(mu, address: int, insn) -> bool:
        if not stage1_ran["done"] or not in_stage1(address) or insn is None:
            return False

        if stage1_skip["n"] >= STAGE1_SKIP_MAX:
            return False

        mnem = (insn.mnemonic or "").lower()
        op_str = insn.op_str or ""

        # Suspicious stack pivot used as anti-emulation: "mov esp, imm32" to a high address.
        if mnem == "mov":
            ops = op_str.replace(" ", "")
            if ops.startswith("esp,"):
                imm = parse_imm_from_op_str(ops.split(",", 1)[1])
                if imm is not None and imm >= 0x80000000:
                    # Don't skip the pivot outright: later instructions may expect the new stack
                    # layout. Instead, proactively map a small stack window so subsequent pops
                    # don't fault.
                    try:
                        old_esp = mu.reg_read(UC_X86_REG_ESP)
                        win_start = align_down(imm - 0x2000, 0x1000)
                        map_range(win_start, 0x8000)
                        # Heuristic: copy a small window of the current stack into the new one
                        # so pop/popal sequences don't immediately go off the rails.
                        try:
                            shadow = bytes(mu.mem_read(old_esp, 0x400))
                            mu.mem_write(imm, shadow)
                            seeded = " + seeded"
                        except Exception:
                            seeded = ""
                        print(
                            f"[!] Stage1 stack pivot detected at 0x{address:08X}: {insn.mnemonic} {insn.op_str} "
                            f"(mapped 0x{win_start:08X}-0x{win_start+0x8000:08X}{seeded})"
                        )
                    except Exception:
                        pass
                    return False

            # Segment register moves frequently raise GPF and rely on SEH for control-flow.
            if op_str_has_seg_reg(op_str):
                stage1_skip["n"] += 1
                mu.reg_write(UC_X86_REG_EIP, address + insn.size)
                if stage1_skip["n"] <= 30 or (stage1_skip["n"] % 500 == 0):
                    print(f"[!] Stage1 skip#{stage1_skip['n']} @0x{address:08X}: {insn.mnemonic} {insn.op_str}")
                return True

        # Privileged / exception-producing instructions in user-mode.
        # NOTE: Do NOT blanket-skip x87 FPU instructions ("f*"). Many real shellcodes use
        # FNSTENV/FSTENV tricks to obtain EIP, and skipping them breaks control-flow.
        if mnem in {
            "retf", "retfw",
            "iret", "iretd", "iretq",
            "int", "into", "ud2",
            "in", "insb", "insw", "insd",
            "out", "outsb", "outsw", "outsd",
            "cli", "sti", "hlt",
            # Rare in real decoders; often appears as junk.
            "bound",
        }:
            stage1_skip["n"] += 1
            mu.reg_write(UC_X86_REG_EIP, address + insn.size)
            if stage1_skip["n"] <= 30 or (stage1_skip["n"] % 500 == 0):
                print(f"[!] Stage1 skip#{stage1_skip['n']} @0x{address:08X}: {insn.mnemonic} {insn.op_str}")
            return True

        return False

    def on_code(mu, address, size, user_data):
        insn_count["n"] += 1
        if not stage2_active["on"] and insn_count["n"] >= MAX_INSN:
            print(f"[!] Reached instruction cap ({MAX_INSN}); stopping at 0x{address:08X}")
            mu.emu_stop()
            return

        # Intercept the sample's API resolver at 0x100014E0 and return stubs directly.
        # This avoids needing a fully-correct kernel32 image + export walking + string helpers.
        if address == image_base + 0x14E0:
            try:
                esp = mu.reg_read(UC_X86_REG_ESP)
                ret = struct.unpack("<I", mu.mem_read(esp, 4))[0]
                mod_base = struct.unpack("<I", mu.mem_read(esp + 4, 4))[0]
                h = struct.unpack("<I", mu.mem_read(esp + 8, 4))[0]
                stub_addr = resolve_hash(h)
                api = hash_to_api.get(h, "UNKNOWN")
                print(f"[*] RESOLVE 0x{h:08X} ({api}) mod=0x{mod_base:08X} -> 0x{stub_addr:08X} RET=0x{ret:08X}")
                mu.reg_write(UC_X86_REG_EAX, stub_addr)
                mu.reg_write(UC_X86_REG_EIP, ret)
                mu.reg_write(UC_X86_REG_ESP, esp + 12)
                return
            except Exception:
                # Fall through and let the real resolver run if our interception fails.
                pass

        # Precise fix for the early failure you saw: code trying to read the DOS header field
        # e_lfanew at offset 0x3C from a NULL base register.
        if address == image_base + 0x14F3:
            insn = decode_insn(address)
            if insn:
                if patch_low_base_for_disp(insn, 0x3C, image_base):
                    print("[!] Patched NULL base reg -> ImageBase for disp 0x3C at 0x100014F3")
                elif patch_low_base_for_disp(insn, 0x3C, LOW_MIRROR_BASE): # type: ignore
                    print("[!] Patched NULL base reg -> low-mirror for disp 0x3C at 0x100014F3")

        if stage2_active["on"]:
            if stage2_active.get("kind") == "stage1" and insn_count["n"] >= STAGE1_MAX_INSN:
                print(f"[!] Stage1 hit instruction cap ({STAGE1_MAX_INSN}); stopping at 0x{address:08X}")
                mu.emu_stop()
                return

            # Stage1 executes inside the decrypted buffer and often contains junk instructions
            # that rely on Windows SEH for control flow. Skip a small set pre-execution.
            insn = decode_insn(address)
            if stage1_skip_insn(mu, address, insn):
                return

            if stage2_active.get("kind") == "candidate":
                # Per-candidate instruction cap
                if insn_count["n"] >= STAGE2_MAX_INSN:
                    print(f"[!] Stage2 hit per-candidate cap ({STAGE2_MAX_INSN}); stopping candidate")
                    mu.emu_stop()
                    return
                # If no writes for a long stretch, this is likely a bad entrypoint.
                if (insn_count["n"] - stage2_writes["last_insn"]) > 200_000:
                    print("[!] Stage2 no-write streak exceeded 200k; stopping candidate")
                    mu.emu_stop()
                    return
            # Bail out quickly if execution runs into unmapped/zero-filled junk.
            # Only enforce "expected regions" for brute-force stage2 entrypoint candidates.
            if stage2_active.get("kind") == "candidate" and not in_expected_exec(address):
                print(f"[!] Stage2 jumped out of expected regions at 0x{address:08X}; stopping candidate")
                mu.emu_stop()
                return
            if insn and insn.mnemonic in ("iretd", "bound"):
                if stage1_skip_insn(mu, address, insn):
                    return
                print(f"[!] Stage2 hit unlikely instruction '{insn.mnemonic}' at 0x{address:08X}; stopping candidate")
                mu.emu_stop()
                return
            if insn and stage2_trace["fh"]:
                try:
                    regs = {
                        "eax": mu.reg_read(UC_X86_REG_EAX),
                        "ebx": mu.reg_read(UC_X86_REG_EBX),
                        "ecx": mu.reg_read(UC_X86_REG_ECX),
                        "edx": mu.reg_read(UC_X86_REG_EDX),
                        "esi": mu.reg_read(UC_X86_REG_ESI),
                        "edi": mu.reg_read(UC_X86_REG_EDI),
                        "ebp": mu.reg_read(UC_X86_REG_EBP),
                        "esp": mu.reg_read(UC_X86_REG_ESP),
                    }
                    stage2_trace["fh"].write(
                        f"0x{address:08X} {insn.mnemonic} {insn.op_str} "
                        f"EAX=0x{regs['eax']:08X} EBX=0x{regs['ebx']:08X} "
                        f"ECX=0x{regs['ecx']:08X} EDX=0x{regs['edx']:08X} "
                        f"ESI=0x{regs['esi']:08X} EDI=0x{regs['edi']:08X} "
                        f"EBP=0x{regs['ebp']:08X} ESP=0x{regs['esp']:08X}\n"
                    )
                except Exception:
                    pass
            try:
                b = bytes(mu.mem_read(address, 8))
                if stage2_active.get("kind") == "candidate" and b == b"\x00" * 8:
                    print(f"[!] Stage2 executing zero-filled bytes at 0x{address:08X}; stopping candidate")
                    mu.emu_stop()
                    return
            except Exception:
                pass

        # If we captured the stage1 entry pointer at the LogWrite breakpoint, enable stage2-style
        # monitoring when execution first transfers into that buffer.
        if stage1_entry["va"] is not None and not stage2_active["on"] and address == stage1_entry["va"]:
            stage2_active["on"] = True
            stage2_active["kind"] = "stage1"
            stage1_ran["done"] = True
            stage2_region["base"] = stage1_entry["va"]
            stage2_region["size"] = stage1_entry["len"] or 0
            stage2_writes["last_insn"] = 0
            stage2_invalid["n"] = 0
            stage2_writes["n"] = 0
            stage2_page_writes["counts"].clear()
            stage2_page_writes["best_page"] = None
            stage2_best_shellcode["addr"] = None
            stage2_best_shellcode["score"] = None
            insn_count["n"] = 0
            # Stage1 commonly unpacks a PE to 0x00400000. Also, some decoder stubs use early
            # memory ops on EDI; if EDI is 0 (common in our stubbed environment), steer it
            # toward the expected PE base to avoid NULL-page dependent traps.
            try:
                map_range(0x00400000, 0x400000)  # 4MB window is enough for this family
            except Exception:
                pass
            try:
                edi = mu.reg_read(UC_X86_REG_EDI)
                if edi == 0:
                    mu.reg_write(UC_X86_REG_EDI, 0x00400000)
                    print("[!] Stage1 fixup: set EDI=0x00400000")
            except Exception:
                pass
            # Stage1 buffers often contain junk bytes at offset 0. Redirect EIP to a better-looking
            # internal entrypoint, then proceed with normal execution/monitoring.
            try:
                base = int(stage1_entry["va"] or 0)
                blen = int(stage1_entry["len"] or 0)
                if base and blen >= 0x40:
                    scan_len = min(blen, 0x40000)
                    raw = bytes(mu.mem_read(base, scan_len))
                    pick_off = pick_stage1_entry_offset(raw)
                    if pick_off:
                        mu.reg_write(UC_X86_REG_EIP, base + pick_off)
                        print(f"[+] Stage1 entry redirect: 0x{base:08X} -> 0x{base + pick_off:08X} (off=0x{pick_off:X})")
            except Exception as e:
                print(f"[!] Stage1 entry redirect failed: {e}")
            try:
                regs = {
                    "eax": mu.reg_read(UC_X86_REG_EAX),
                    "ebx": mu.reg_read(UC_X86_REG_EBX),
                    "ecx": mu.reg_read(UC_X86_REG_ECX),
                    "edx": mu.reg_read(UC_X86_REG_EDX),
                    "esi": mu.reg_read(UC_X86_REG_ESI),
                    "edi": mu.reg_read(UC_X86_REG_EDI),
                    "ebp": mu.reg_read(UC_X86_REG_EBP),
                    "esp": mu.reg_read(UC_X86_REG_ESP),
                    "efl": mu.reg_read(UC_X86_REG_EFLAGS),
                }
                arg1 = struct.unpack("<I", mu.mem_read(regs["esp"] + 4, 4))[0]
                print(
                    f"[+] Entered stage1 payload at 0x{address:08X} (len=0x{(stage1_entry['len'] or 0):X}); monitoring writes "
                    f"EAX=0x{regs['eax']:08X} EBX=0x{regs['ebx']:08X} ECX=0x{regs['ecx']:08X} EDX=0x{regs['edx']:08X} "
                    f"ESI=0x{regs['esi']:08X} EDI=0x{regs['edi']:08X} EBP=0x{regs['ebp']:08X} ESP=0x{regs['esp']:08X} EFLAGS=0x{regs['efl']:08X} "
                    f"arg1@esp+4=0x{arg1:08X}"
                )
                print(f"[+] Stage1 raw base for disassembly: 0x{address:08X} (treat output/shellcode.bin as raw x86 at this base)")
                try:
                    # Dump the 25-dword argument struct passed to stage1 (matches Rapid7's LogWrite arg array).
                    raw = bytes(mu.mem_read(arg1, 25 * 4))
                    words = list(struct.unpack("<25I", raw))
                    print("[+] Stage1 arg struct (25 dwords):")
                    for i, v in enumerate(words):
                        print(f"    [{i:02}] 0x{v:08X}")
                    # Commonly-interesting pointers:
                    print(f"[+] Stage1 arg ptrs: shellcode_ptr=[20]=0x{words[20]:08X} LoadLibrary=[21]=0x{words[21]:08X} GetProcAddress=[22]=0x{words[22]:08X}")
                except Exception:
                    pass
                try:
                    b0 = bytes(mu.mem_read(address, 16))
                    print(f"[*] stage1 bytes: {b0.hex()}")
                except Exception:
                    pass
            except Exception:
                print(f"[+] Entered stage1 payload at 0x{address:08X} (len=0x{(stage1_entry['len'] or 0):X}); monitoring writes")

        # If execution reaches heap-allocated memory, treat it as shellcode entry.
        # In full/logwrite modes we *want* to execute the stage1 buffer, so don't stop there.
        for base, sz in stubs.allocations.items():
            if base <= address < base + sz:
                if stage2_active["on"] or stage1_entry["va"] == base:
                    break
                print(f"[+] Heap execution at 0x{address:08X}; dumping as shellcode")
                if last_write["addr"] is not None:
                    print(f"[+] Last heap write at 0x{last_write['addr']:08X} size={last_write['size']}")
                max_len = min(DUMP_MAX, (base + sz) - address)
                try:
                    blob = bytes(mu.mem_read(address, max_len))
                except Exception as e:
                    print(f"[!] Failed to read heap memory at 0x{address:08X}: {e}")
                    try:
                        map_range(address, max_len)
                        blob = bytes(mu.mem_read(address, max_len))
                    except Exception:
                        blob = b""
                if blob:
                    keep = is_probably_end(blob)
                    keep = max(keep, DUMP_MIN)
                    blob = blob[:keep]
                    with open(out_shellcode_path, "wb") as f:
                        f.write(blob)
                    sh = sha256_file(out_shellcode_path)
                    print(f"[+] Wrote {len(blob)} bytes to {out_shellcode_path} sha256={sh}")
                    write_stage1_base_file(out_shellcode_path, address, len(blob), sh)
                else:
                    # Fallback: dump from last write region if available.
                    if last_write["addr"] is not None:
                        try:
                            # bound to allocation size if possible
                            lw = last_write["addr"]
                            max_lw = DUMP_MAX
                            for b2, sz2 in stubs.allocations.items():
                                if b2 <= lw < b2 + sz2:
                                    max_lw = min(DUMP_MAX, (b2 + sz2) - lw)
                                    break
                            blob2 = bytes(mu.mem_read(lw, max_lw))
                            keep = is_probably_end(blob2)
                            keep = max(keep, DUMP_MIN)
                            blob2 = blob2[:keep]
                            with open(out_shellcode_path, "wb") as f:
                                f.write(blob2)
                            print(f"[+] Wrote {len(blob2)} bytes to {out_shellcode_path} from last-write region")
                        except Exception as e2:
                            print(f"[!] Fallback dump failed: {e2}")
                    else:
                        print("[!] No bytes dumped.")
                # Scan all heap allocations and dump the best-looking region.
                best = None
                best_addr = None
                for b2, sz2 in stubs.allocations.items():
                    try:
                        max_b = min(DUMP_MAX, sz2)
                        buf = bytes(mu.mem_read(b2, max_b))
                    except Exception:
                        continue
                    nz, ent = score_buffer(buf)
                    if best is None or (nz, ent) > best:
                        best = (nz, ent)
                        best_addr = b2
                        best_buf = buf
                if best_addr is not None and best is not None:
                    keep = is_probably_end(best_buf)
                    keep = max(keep, DUMP_MIN)
                    best_buf = best_buf[:keep]
                    with open(out_shellcode_path, "wb") as f:
                        f.write(best_buf)
                    print(f"[+] Best heap region 0x{best_addr:08X} nz={best[0]} ent={best[1]:.3f} -> wrote {len(best_buf)} bytes")
                dumped["done"] = True
                mu.emu_stop()
                return

        # Short-circuit the export resolver (0x100014E0) with a hash-based stub.
        if address == image_base + 0x14E0:
            try:
                esp = mu.reg_read(UC_X86_REG_ESP)
                ret = struct.unpack("<I", mu.mem_read(esp, 4))[0]
                hash_val = struct.unpack("<I", mu.mem_read(esp + 8, 4))[0]
                stub_addr = resolve_hash(hash_val)
                mu.reg_write(UC_X86_REG_EAX, stub_addr)
                mu.reg_write(UC_X86_REG_ESP, esp + 12)
                mu.reg_write(UC_X86_REG_EIP, ret)
                print(f"[*] Resolver hash 0x{hash_val:08X} -> 0x{stub_addr:08X}")
                return
            except Exception:
                pass

        # Stage2 hash resolver: if EAX holds a hash and we can resolve it, redirect.
        if stage2_active["on"]:
            try:
                eax = mu.reg_read(UC_X86_REG_EAX)
                stub = resolve_hash_to_stub(eax)
                if stub:
                    mu.reg_write(UC_X86_REG_EAX, stub)
            except Exception:
                pass

        # Cap large REP MOVSD copies to avoid walking off the image.
        if address == image_base + 0x4E50:
            try:
                esi = mu.reg_read(UC_X86_REG_ESI)
                ecx = mu.reg_read(UC_X86_REG_ECX)
                img_end = image_base + size_image
                if image_base <= esi < img_end:
                    remaining = img_end - esi
                    max_ecx = remaining // 4
                    if ecx > max_ecx:
                        mu.reg_write(UC_X86_REG_ECX, max_ecx)
                        print(f"[!] Capped ECX for rep movsd to {max_ecx}")
            except Exception:
                pass

        # Cap long hash loops over export names.
        if address == image_base + 0x1585:
            try:
                ebx = mu.reg_read(UC_X86_REG_EBX)
                if ebx > 0x1000:
                    mu.reg_write(UC_X86_REG_EBX, 0x1000)
                    print("[!] Capped EBX in hash loop to 0x1000")
            except Exception:
                pass

        # Avoid ECX-1 underflow in string loops.
        if address == image_base + 0x145B:
            try:
                ecx = mu.reg_read(UC_X86_REG_ECX)
                if ecx == 0:
                    mu.reg_write(UC_X86_REG_ECX, 1)
                    print("[!] Fixed ECX underflow at 0x1000145B")
            except Exception:
                pass

        # Skip suspicious arithmetic on invalid memory in the 0x1000E1xx range.
        if image_base + 0xE180 <= address <= image_base + 0xE300:
            try:
                esp = mu.reg_read(UC_X86_REG_ESP)
                ret = struct.unpack("<I", mu.mem_read(esp, 4))[0]
                mu.reg_write(UC_X86_REG_EIP, ret)
                mu.reg_write(UC_X86_REG_ESP, esp + 4)
                print("[!] Bypassed 0x1000E1xx block via RET")
                return
            except Exception:
                pass
            if FORCE_BREAK and not forced["done"]:
                try:
                    mu.reg_write(UC_X86_REG_EAX, 0x00200000)
                    mu.reg_write(UC_X86_REG_EIP, break_va)
                    forced["done"] = True
                    print("[!] Forced jump to breakpoint from 0x1000E1xx")
                    return
                except Exception:
                    pass
            insn = decode_insn(address)
            if insn:
                try:
                    for op in insn.operands:
                        if op.type == X86_OP_MEM and op.mem.base:
                            base_val = mu.reg_read(op.mem.base)
                            if base_val >= 0xC0000000 or base_val < 0x1000 or (base_val == 0 and abs(op.mem.disp) > 0x10000):
                                mu.reg_write(UC_X86_REG_EIP, address + insn.size)
                                print(f"[!] Skipped suspicious mem op at 0x{address:08X}")
                                return
                except Exception:
                    pass
            if address == image_base + 0xE1C0 and insn:
                mu.reg_write(UC_X86_REG_EIP, address + insn.size)
                print("[!] Skipped op at 0x1000E1C0")
                return

        # Skip security cookie / exception helpers that can raise in emulation.
        if address == image_base + 0x220E:
            try:
                esp = mu.reg_read(UC_X86_REG_ESP)
                ret = struct.unpack("<I", mu.mem_read(esp, 4))[0]
                mu.reg_write(UC_X86_REG_EIP, ret)
                mu.reg_write(UC_X86_REG_ESP, esp + 4)
                mu.reg_write(UC_X86_REG_EAX, 0)
                print("[!] Skipped security check at 0x1000220E")
                return
            except Exception:
                pass

        # Emulate IAT stubs.
        if address in stub_map:
            raw_name = stub_map[address]
            name = raw_name.split("\x00", 1)[0]
            esp = mu.reg_read(UC_X86_REG_ESP)
            ret = struct.unpack("<I", mu.mem_read(esp, 4))[0]
            argc = 0
            eax = 0
            arg_vals = []

            if name == "GetModuleHandleA":
                argc = 1
                lp = struct.unpack("<I", mu.mem_read(esp + 4, 4))[0]
                if not lp:
                    eax = image_base
                else:
                    s = read_cstr(mu, lp).lower()
                    if b"kernel32" in s:
                        eax = k32_base
                    elif b"ntdll" in s:
                        eax = ntd_base
                    else:
                        eax = 0
            elif name == "GetProcessHeap":
                argc = 0
                eax = stubs.process_heap
            elif name == "InitializeCriticalSectionAndSpinCount":
                argc = 2
                eax = 1
            elif name == "DeleteCriticalSection":
                argc = 1
                eax = 0
            elif name == "EnterCriticalSection":
                argc = 1
                eax = 0
            elif name == "LeaveCriticalSection":
                argc = 1
                eax = 0
            elif name == "HeapAlloc":
                argc = 3
                h_heap = struct.unpack("<I", mu.mem_read(esp + 4, 4))[0]
                flags = struct.unpack("<I", mu.mem_read(esp + 8, 4))[0]
                size_arg = struct.unpack("<I", mu.mem_read(esp + 12, 4))[0]
                eax = stubs.heap_alloc(h_heap, flags, size_arg)
            elif name == "HeapFree":
                argc = 3
                eax = 1
            elif name == "HeapReAlloc":
                argc = 4
                h_heap = struct.unpack("<I", mu.mem_read(esp + 4, 4))[0]
                flags = struct.unpack("<I", mu.mem_read(esp + 8, 4))[0]
                lp_mem = struct.unpack("<I", mu.mem_read(esp + 12, 4))[0]
                size_arg = struct.unpack("<I", mu.mem_read(esp + 16, 4))[0]
                eax = stubs.heap_realloc(h_heap, flags, lp_mem, size_arg)
            elif name == "HeapSize":
                argc = 3
                h_heap = struct.unpack("<I", mu.mem_read(esp + 4, 4))[0]
                flags = struct.unpack("<I", mu.mem_read(esp + 8, 4))[0]
                lp_mem = struct.unpack("<I", mu.mem_read(esp + 12, 4))[0]
                eax = stubs.heap_size(h_heap, flags, lp_mem)
            elif name == "GetLastError":
                argc = 0
                eax = 0
            elif name == "SetLastError":
                argc = 1
                eax = 0
            elif name == "EncodePointer":
                argc = 1
                eax = struct.unpack("<I", mu.mem_read(esp + 4, 4))[0]
            elif name == "DecodePointer":
                argc = 1
                eax = struct.unpack("<I", mu.mem_read(esp + 4, 4))[0]
            elif name == "TlsAlloc":
                argc = 0
                eax = stubs.tls_alloc()
            elif name == "TlsFree":
                argc = 1
                idx = struct.unpack("<I", mu.mem_read(esp + 4, 4))[0]
                eax = stubs.tls_free(idx)
            elif name == "TlsGetValue":
                argc = 1
                idx = struct.unpack("<I", mu.mem_read(esp + 4, 4))[0]
                eax = stubs.tls_get(idx)
            elif name == "TlsSetValue":
                argc = 2
                idx = struct.unpack("<I", mu.mem_read(esp + 4, 4))[0]
                val = struct.unpack("<I", mu.mem_read(esp + 8, 4))[0]
                eax = stubs.tls_set(idx, val)
            elif name == "IsDebuggerPresent":
                argc = 0
                eax = 0
            elif name == "IsProcessorFeaturePresent":
                argc = 1
                eax = 0
            elif name == "GetCurrentProcess":
                argc = 0
                eax = 0xFFFFFFFF
            elif name == "GetCurrentProcessId":
                argc = 0
                eax = 1337
            elif name == "GetCurrentThreadId":
                argc = 0
                eax = 31337
            elif name == "GetSystemTimeAsFileTime":
                argc = 1
                ft_ptr = struct.unpack("<I", mu.mem_read(esp + 4, 4))[0]
                if ft_ptr:
                    try:
                        map_range(ft_ptr, 8)
                        mu.mem_write(ft_ptr, b"\x00" * 8)
                    except Exception:
                        pass
                eax = 0
            elif name == "QueryPerformanceCounter":
                argc = 1
                qpc_ptr = struct.unpack("<I", mu.mem_read(esp + 4, 4))[0]
                if qpc_ptr:
                    try:
                        map_range(qpc_ptr, 8)
                        mu.mem_write(qpc_ptr, struct.pack("<Q", 1))
                    except Exception:
                        pass
                eax = 1
            elif name == "RaiseException":
                argc = 4
                eax = 0
            elif name == "LoadLibraryA":
                argc = 1
                lp = struct.unpack("<I", mu.mem_read(esp + 4, 4))[0]
                s = read_cstr(mu, lp).lower() if lp else b""
                if b"kernel32" in s:
                    eax = k32_base
                elif b"ntdll" in s:
                    eax = ntd_base
                else:
                    eax = 0x50000000
            elif name == "GetProcAddress":
                argc = 2
                lp_proc = struct.unpack("<I", mu.mem_read(esp + 8, 4))[0]
                # If lpProcName is an ordinal (HIWORD=0), we don't support it; return 0.
                if lp_proc and lp_proc < 0x10000:
                    eax = 0
                else:
                    proc = read_cstr(mu, lp_proc).decode(errors="ignore")
                    eax = name_to_stub.get(proc, 0)
            elif name == "VirtualAlloc":
                argc = 4
                lp_addr = struct.unpack("<I", mu.mem_read(esp + 4, 4))[0]
                size_arg = struct.unpack("<I", mu.mem_read(esp + 8, 4))[0]
                eax = stubs.virtual_alloc(lp_addr, size_arg, 0, 0)
            elif name == "VirtualProtect":
                argc = 4
                lp_old = struct.unpack("<I", mu.mem_read(esp + 16, 4))[0]
                if lp_old:
                    try:
                        map_range(lp_old, 4)
                        mu.mem_write(lp_old, struct.pack("<I", 0x40))
                    except Exception:
                        pass
                eax = 1
            elif name == "VirtualFree":
                argc = 3
                eax = 1
            elif name == "CreateFileW":
                argc = 7
                # This sample reads the encrypted payload from disk; feed it from --payload.
                # If the payload is missing, fall back to returning the DLL bytes.
                lp_filename = struct.unpack("<I", mu.mem_read(esp + 4, 4))[0]
                fn = read_wstr(mu, lp_filename).lower() if lp_filename else ""
                data = stubs.payload_data or dll_bytes
                if fn:
                    # Useful breadcrumb in logs
                    print(f"[*] CreateFileW filename='{fn}' -> {len(data)} bytes")
                eax = stubs.open_file_bytes(data)
            elif name == "GetModuleFileNameA":
                argc = 3
                lp_filename = struct.unpack("<I", mu.mem_read(esp + 8, 4))[0]
                n_size = struct.unpack("<I", mu.mem_read(esp + 12, 4))[0]
                fake = b"C:\\dummy\\file.bin\x00"
                if lp_filename and n_size:
                    mu.mem_write(lp_filename, fake[:n_size])
                eax = len(fake) - 1
            elif name == "ReadFile":
                argc = 5
                h_file = struct.unpack("<I", mu.mem_read(esp + 4, 4))[0]
                lp_buffer = struct.unpack("<I", mu.mem_read(esp + 8, 4))[0]
                n_read = struct.unpack("<I", mu.mem_read(esp + 12, 4))[0]
                lp_bytes = struct.unpack("<I", mu.mem_read(esp + 16, 4))[0]
                if lp_buffer and n_read:
                    map_range(lp_buffer, min(n_read, 0x2000))
                    chunk = stubs.read_file(h_file, min(n_read, 0x2000))
                    if chunk:
                        mu.mem_write(lp_buffer, chunk + b"\x00" * (min(n_read, 0x2000) - len(chunk)))
                    else:
                        mu.mem_write(lp_buffer, b"\x00" * min(n_read, 0x2000))
                if lp_bytes:
                    mu.mem_write(lp_bytes, struct.pack("<I", min(n_read, 0x2000)))
                eax = 1
            elif name == "ReadFile4":
                argc = 4
                lp_buffer = struct.unpack("<I", mu.mem_read(esp + 8, 4))[0]
                n_read = struct.unpack("<I", mu.mem_read(esp + 12, 4))[0]
                lp_bytes = struct.unpack("<I", mu.mem_read(esp + 16, 4))[0]
                if lp_buffer and n_read:
                    map_range(lp_buffer, min(n_read, 0x2000))
                    chunk = stubs.read_default(min(n_read, 0x2000))
                    if chunk:
                        mu.mem_write(lp_buffer, chunk + b"\x00" * (min(n_read, 0x2000) - len(chunk)))
                    else:
                        mu.mem_write(lp_buffer, b"\x00" * min(n_read, 0x2000))
                if lp_bytes:
                    mu.mem_write(lp_bytes, struct.pack("<I", min(n_read, 0x2000)))
                eax = 1
            elif name == "WriteFile":
                argc = 5
                eax = 1
            elif name == "ExitProcess":
                argc = 1
                eax = 0
                print("[*] ExitProcess called; stopping emulation")
                mu.emu_stop()
            elif name == "TerminateProcess":
                argc = 2
                eax = 1
                print("[*] TerminateProcess called; stopping emulation")
                mu.emu_stop()
            elif name == "NtAllocateVirtualMemory":
                argc = 6
                # args: ProcessHandle, BaseAddress*, ZeroBits, RegionSize*, AllocType, Protect
                base_ptr = struct.unpack("<I", mu.mem_read(esp + 8, 4))[0]
                size_ptr = struct.unpack("<I", mu.mem_read(esp + 16, 4))[0]
                size_val = struct.unpack("<I", mu.mem_read(size_ptr, 4))[0] if size_ptr else 0x1000
                addr = stubs.virtual_alloc(0, size_val, 0, 0)
                if base_ptr:
                    mu.mem_write(base_ptr, struct.pack("<I", addr))
                eax = 0
            elif name == "NtProtectVirtualMemory":
                argc = 5
                eax = 0
            elif name == "NtQueryInformationProcess":
                argc = 5
                eax = 0
            elif name == "NtDelayExecution":
                argc = 2
                eax = 0
            elif name == "CloseHandle":
                argc = 1
                eax = 1
            elif name == "GetProcAddress":
                argc = 2
                lp_proc = struct.unpack("<I", mu.mem_read(esp + 8, 4))[0]
                if lp_proc and lp_proc < 0x10000:
                    eax = 0
                else:
                    proc = read_cstr(mu, lp_proc).decode(errors="ignore")
                    eax = name_to_stub.get(proc, 0)
            elif name == "LoadLibraryA":
                argc = 1
                lp = struct.unpack("<I", mu.mem_read(esp + 4, 4))[0]
                s = read_cstr(mu, lp).lower() if lp else b""
                if b"kernel32" in s:
                    eax = k32_base
                elif b"ntdll" in s:
                    eax = ntd_base
                else:
                    eax = 0x50000000

            # Generic fallback: most CriticalSection routines are stdcall and take a single pointer arg.
            if argc == 0 and name.endswith("CriticalSection"):
                argc = 1
                eax = 0

            if argc:
                for i in range(argc):
                    arg_vals.append(struct.unpack("<I", mu.mem_read(esp + 4 + (i * 4), 4))[0])
            print(f"[*] STUB {name}({', '.join(hex(a) for a in arg_vals)}) -> EAX=0x{eax:08X} RET=0x{ret:08X}")
            mu.reg_write(UC_X86_REG_EAX, eax)
            esp += 4 + (argc * 4)
            mu.reg_write(UC_X86_REG_ESP, esp)
            mu.reg_write(UC_X86_REG_EIP, ret)
            return

        # Patch register base for the known faulting instruction.
        if address == image_base + 0x14F3:
            insn = decode_insn(address)
            if insn:
                for op in insn.operands:
                    if op.type == X86_OP_MEM and op.mem.disp == 0x3C:
                        base_reg = op.mem.base
                        if base_reg:
                            try:
                                base_val = mu.reg_read(base_reg)
                                if base_val == 0:
                                    mu.reg_write(base_reg, image_base)
                            except Exception:
                                pass

        # Stop when we hit the breakpoint instruction
        if address == break_va:
            if dumped["done"]:
                return
            eax = mu.reg_read(UC_X86_REG_EAX)
            print(f"[+] BREAK hit at VA 0x{address:08X}")
            print(f"[+] ImageBase: 0x{image_base:08X}")
            print(f"[+] EAX:       0x{eax:08X}")
            try:
                out_len = struct.unpack("<I", mu.mem_read(g_len, 4))[0]
            except Exception:
                out_len = 0
            if out_len:
                stage1_entry["va"] = eax
                stage1_entry["len"] = out_len
                print(f"[+] Stage1 buffer len: 0x{out_len:X}")

            # If EAX points into the PE image, compute RVA for rebasing
            if image_base <= eax < image_base + size_image:
                rva = eax - image_base
                print(f"[+] EAX looks like PE-pointer -> RVA 0x{rva:08X}")
            else:
                print("[!] EAX does not point inside the PE image (likely heap/VirtualAlloc).")

            # Try reading up to the stage1 length (bounded by DUMP_MAX) from EAX and trim with heuristics
            try:
                want = out_len if out_len else DUMP_MAX
                want = min(want, DUMP_MAX)
                blob = bytes(mu.mem_read(eax, want))
            except Exception as e:
                print(f"[!] Failed to read memory at EAX: {e}")
                blob = b""

            if blob:
                keep = is_probably_end(blob)
                keep = max(keep, DUMP_MIN)
                blob = blob[:keep]
                with open(out_shellcode_path, "wb") as f:
                    f.write(blob)
                sh = sha256_file(out_shellcode_path)
                print(f"[+] Wrote {len(blob)} bytes to {out_shellcode_path} sha256={sh}")
                write_stage1_base_file(out_shellcode_path, eax, len(blob), sh)

                # Also dump the full stage1 region (commonly 0x200000) for offline stage2 extraction.
                # This includes bytes beyond the initial stage1 length.
                try:
                    want_full = min(DUMP_MAX, STAGE1_FULL_DUMP_LEN)
                    full_blob = bytes(mu.mem_read(eax, want_full))
                    with open(out_shellcode_full_path, "wb") as f:
                        f.write(full_blob)
                    sh_full = sha256_file(out_shellcode_full_path)
                    print(f"[+] Wrote {len(full_blob)} bytes to {out_shellcode_full_path} sha256={sh_full}")
                    write_stage1_base_file(out_shellcode_full_path, eax, len(full_blob), sh_full)
                except Exception as e:
                    print(f"[!] Failed to dump full stage1 region: {e}")
            else:
                print("[!] No bytes dumped.")

            dumped["done"] = True
            # In --mode logwrite, the user explicitly wants to stop here.
            # In --mode full, continue so LogWrite can transfer control to the stage1 payload.
            if stop_at == "break" or mode == "logwrite":
                mu.emu_stop()
            return

        # Stop if the function returns to our fake return address
        if address == RET_ADDR:
            print("[*] Returned to fake RET; stopping.")
            returned["done"] = True
            mu.emu_stop()

    def on_mem_invalid(mu, access, address, size, value, user_data):
        # Attempt very light “API call” handling if the code jumps/calls into nowhere.
        # Many DLLs call kernel32!VirtualAlloc/etc via IAT -> address in kernel32 range.
        # In emulation, that won't exist. If you see it failing here, add a rule.
        eip = mu.reg_read(UC_X86_REG_EIP)
        try:
            regs = {
                "eax": mu.reg_read(UC_X86_REG_EAX),
                "ebx": mu.reg_read(UC_X86_REG_EBX),
                "ecx": mu.reg_read(UC_X86_REG_ECX),
                "edx": mu.reg_read(UC_X86_REG_EDX),
                "esi": mu.reg_read(UC_X86_REG_ESI),
                "edi": mu.reg_read(UC_X86_REG_EDI),
                "ebp": mu.reg_read(UC_X86_REG_EBP),
                "esp": mu.reg_read(UC_X86_REG_ESP),
                "efl": mu.reg_read(UC_X86_REG_EFLAGS),
            }
            print(
                f"[!] Invalid memory access at EIP=0x{eip:08X} addr=0x{address:08X} access={access} "
                f"EAX=0x{regs['eax']:08X} EBX=0x{regs['ebx']:08X} ECX=0x{regs['ecx']:08X} EDX=0x{regs['edx']:08X} "
                f"ESI=0x{regs['esi']:08X} EDI=0x{regs['edi']:08X} EBP=0x{regs['ebp']:08X} ESP=0x{regs['esp']:08X} EFLAGS=0x{regs['efl']:08X}"
            )
        except Exception:
            print(f"[!] Invalid memory access at EIP=0x{eip:08X} addr=0x{address:08X} access={access}")
        insn = decode_insn(eip)
        if insn:
            print(f"[!] Disasm: {insn.mnemonic} {insn.op_str}")
            for op in insn.operands:
                if op.type == X86_OP_MEM:
                    base_reg = op.mem.base
                    if base_reg:
                        try:
                            base_val = mu.reg_read(base_reg)
                            reg_name = insn.reg_name(base_reg)
                            print(f"[!] Base reg {reg_name} = 0x{base_val:08X}")
                        except Exception:
                            pass
            # Stage1 often uses exception-driven control flow by touching bogus high addresses.
            # We do NOT want to map huge "upper zero pages" (they devolve into 0x00-filled loops),
            # and we also can't reliably change EIP from inside the invalid-memory callback on
            # this host (it can trip Unicorn into UC_ERR_MAP).
            #
            # So: record the fault and stop. The outer emulation loop will advance EIP and resume.
            if stage2_active.get("kind") == "stage1":
                if access in (UC_MEM_READ_UNMAPPED, UC_MEM_WRITE_UNMAPPED) and address >= 0xC0000000 and not (0xA0000000 <= address < 0xB0000000):
                    stage1_fault["pending"] = True
                    stage1_fault["eip"] = eip
                    stage1_fault["next_eip"] = eip + insn.size
                    stage1_fault["access"] = access
                    stage1_fault["addr"] = address
                    stage1_fault["disasm"] = f"{insn.mnemonic} {insn.op_str}".strip()
                    return False
            if access == UC_MEM_READ_UNMAPPED and address == image_base + size_image:
                try:
                    mu.mem_map(address, 0x1000)
                    mu.mem_write(address, b"\x00" * 0x1000)
                    print(f"[!] Mapped zero page at image end 0x{address:08X}")
                    return True
                except Exception:
                    pass
            if access == UC_MEM_READ_UNMAPPED and address >= 0xFFFF0000:
                page = align_down(address, 0x1000)
                try:
                    mu.mem_map(page, 0x1000)
                    mu.mem_write(page, b"\x00" * 0x1000)
                    print(f"[!] Mapped high zero page at 0x{page:08X}")
                    return True
                except Exception:
                    pass
            if access == UC_MEM_READ_UNMAPPED and address >= 0xC0000000 and stage2_active.get("kind") != "stage1":
                page = align_down(address, 0x1000)
                try:
                    mu.mem_map(page, 0x1000)
                    mu.mem_write(page, b"\x00" * 0x1000)
                    print(f"[!] Mapped upper zero page at 0x{page:08X}")
                    return True
                except Exception:
                    pass
            if access == UC_MEM_READ_UNMAPPED and address >= image_base + size_image and address < image_base + size_image + 0x10000:
                page = align_down(address, 0x1000)
                try:
                    mu.mem_map(page, 0x1000)
                    mu.mem_write(page, b"\x00" * 0x1000)
                    print(f"[!] Mapped zero page at 0x{page:08X}")
                    return True
                except Exception:
                    pass
            if access == UC_MEM_READ_UNMAPPED and address < size_image:
                page = align_down(address, 0x1000)
                try:
                    mu.mem_map(page, 0x1000)
                    src = image_base + page
                    length = min(0x1000, size_image - page)
                    data = mu.mem_read(src, length)
                    mu.mem_write(page, data)
                    print(f"[!] Mapped RVA mirror page at 0x{page:08X}")
                    return True
                except Exception:
                    pass
                for op in insn.operands:
                    if op.type == X86_OP_MEM and op.mem.base:
                        try:
                            base_val = mu.reg_read(op.mem.base)
                            if base_val < size_image:
                                mu.reg_write(op.mem.base, base_val + image_base)
                                print(f"[!] Rebased mem base to 0x{base_val + image_base:08X}")
                                return True
                        except Exception:
                            pass
        # If we couldn't decode the instruction, we can't safely skip. Fail closed.
        if stage2_active.get("kind") == "stage1":
            if access in (UC_MEM_READ_UNMAPPED, UC_MEM_WRITE_UNMAPPED) and address >= 0xC0000000 and not (0xA0000000 <= address < 0xB0000000):
                return False
        if access == UC_MEM_FETCH_UNMAPPED and address == RET_ADDR:
            print("[*] Returned to fake RET (unmapped fetch); stopping.")
            return False
        if stage2_active["on"]:
            insn = decode_insn(eip)
            if stage2_active.get("kind") == "candidate" and insn and insn.mnemonic in ("ret", "retf", "iret", "iretd"):
                print(f"[*] Stage2 hit return '{insn.mnemonic}' at 0x{eip:08X}; stopping candidate")
                return False
        if stage2_active["on"]:
            if access == UC_MEM_FETCH_UNMAPPED:
                if stage2_active.get("kind") == "candidate":
                    stage2_invalid["n"] += 1
                    if stage2_invalid["n"] > 200:
                        print("[!] Too many stage2 invalid memory events; stopping candidate")
                        return False
                else:
                    # Stage1 tends to use exception-driven control flow. If we start *executing*
                    # out of mapped/expected regions, we usually drift into zero pages and spin
                    # on 'add byte ptr [eax], al'. Stop early and let the post-run dump capture
                    # whatever was unpacked to 0x00400000 so far.
                    if not in_expected_exec(address):
                        print(f"[!] Unmapped fetch in stage1 at 0x{address:08X}; stopping stage1 execution")
                        return False
            # During stage2, auto-map any missing page to allow unpacking.
            page = align_down(address, 0x1000)
            try:
                mu.mem_map(page, 0x1000)
                return True
            except Exception:
                pass
            # If stack access faulted, map around ESP.
            try:
                esp = mu.reg_read(UC_X86_REG_ESP)
                if abs(address - esp) < 0x20000:
                    page = align_down(address, 0x1000)
                    mu.mem_map(page, 0x1000)
                    return True
            except Exception:
                pass
            # Some stages use a high stack / bogus pointers in the 0xA0-0xAF range.
            if 0xA0000000 <= address < 0xB0000000:
                try:
                    page = align_down(address, 0x1000)
                    mu.mem_map(page, 0x1000)
                    return True
                except Exception:
                    pass
        elif access == UC_MEM_FETCH_UNMAPPED and address < size_image:
            rebased = image_base + address
            rebased_insn = decode_insn(rebased)
            if rebased_insn:
                print(f"[!] Disasm (rebased): {rebased_insn.mnemonic} {rebased_insn.op_str}")
            try:
                mu.reg_write(UC_X86_REG_EIP, rebased)
                print(f"[!] Rebased EIP to 0x{rebased:08X}")
                return True
            except Exception:
                pass
        elif access == UC_MEM_FETCH_UNMAPPED:
            # Last-resort: treat as an external call returning 0.
            try:
                esp = mu.reg_read(UC_X86_REG_ESP)
                ret = struct.unpack("<I", mu.mem_read(esp, 4))[0]
                mu.reg_write(UC_X86_REG_EAX, 0)
                mu.reg_write(UC_X86_REG_ESP, esp + 4)
                mu.reg_write(UC_X86_REG_EIP, ret)
                print(f"[!] Unmapped fetch -> returning to 0x{ret:08X} with EAX=0")
                return True
            except Exception:
                pass
        return False  # stop emu

    def on_mem_write(mu, access, address, size, value, user_data):
        # Track last heap write as candidate shellcode buffer.
        for base, sz in stubs.allocations.items():
            if base <= address < base + sz:
                last_write["addr"] = address
                last_write["size"] = size
                break
        if stage2_active["on"]:
            stage2_writes["n"] += 1
            stage2_writes["last_insn"] = insn_count["n"]
            # Track page write counts
            page = align_down(address, 0x1000)
            counts = stage2_page_writes["counts"]
            counts[page] = counts.get(page, 0) + 1
            if stage2_page_writes["best_page"] is None or counts[page] > counts.get(stage2_page_writes["best_page"], 0):
                stage2_page_writes["best_page"] = page
            # Track possible PE writes in the 0x00400000 region.
            if 0x00400000 <= address < 0x01400000:
                # If we haven't confirmed a PE yet, check for MZ/PE at base.
                if stage2_pe_write["addr"] is None:
                    try:
                        base = 0x00400000
                        hdr = bytes(mu.mem_read(base, 0x200))
                        if hdr[:2] == b"MZ":
                            e = struct.unpack_from("<I", hdr, 0x3c)[0]
                            if 0 <= e <= 0x200 - 4 and hdr[e:e+4] == b"PE\x00\x00":
                                size = struct.unpack_from("<I", hdr, e + 0x50)[0]
                                stage2_pe_write["addr"] = base # type: ignore
                                stage2_pe_write["size"] = size if size else None
                                stage2["found"] = True
                                stage2["addr"] = base
                    except Exception:
                        pass
        # Lightweight PE detection on write: check if we just wrote 'Z' after 'M'.
        try:
            if address > 0 and address < 0x80000000:
                b0 = bytes(mu.mem_read(address - 1, 2))
                if b0 == b"MZ":
                    stage2["found"] = True
                    stage2["addr"] = address - 1
        except Exception:
            pass
        # If we wrote a larger chunk, scan for MZ/PE and record candidates.
        if size >= 0x200:
            try:
                buf = bytes(mu.mem_read(address, min(size, 0x2000)))
                idx = buf.find(b"MZ")
                if idx != -1:
                    off = address + idx
                    try:
                        e_lfanew = struct.unpack_from("<I", buf, idx + 0x3c)[0]
                        pe_off = off + e_lfanew
                        sig = bytes(mu.mem_read(pe_off, 4))
                        if sig == b"PE\x00\x00":
                            stage2_candidates.append(off)
                    except Exception:
                        pass
            except Exception:
                pass
        if address == g_seed:
            init_done["done"] = True
            try:
                val = struct.unpack("<I", mu.mem_read(g_seed, 4))[0]
                print(f"[*] Seed set at 0x{g_seed:08X} = 0x{val:08X}")
            except Exception:
                pass
            if stop_at == "init":
                try:
                    mu.emu_stop()
                except Exception:
                    pass

    mu.hook_add(UC_HOOK_CODE, on_code)
    mu.hook_add(UC_HOOK_MEM_INVALID, on_mem_invalid)
    mu.hook_add(UC_HOOK_MEM_WRITE, on_mem_write)

    k32_base = map_fake_kernel32()
    ntd_base = map_fake_ntdll()
    init_fake_peb()
    # Help the resolver and init: provide a plausible kernel32 base handle in the expected global.
    try:
        mu.mem_write(g_k32, struct.pack("<I", k32_base))
    except Exception:
        pass
    if enc_payload:
        stubs.payload_data = enc_payload

    # If payload is present, run init then decrypt via 0x10001640.
    if enc_payload and mode in ("decrypt", "stage2", "logwrite", "full"):
        payload_addr = 0x00200000
        map_range(payload_addr, len(enc_payload))
        mu.mem_write(payload_addr, enc_payload)
        # Set globals to point at payload; init may update seed/keys.
        mu.mem_write(g_buf, struct.pack("<I", payload_addr))
        mu.mem_write(g_len, struct.pack("<I", len(enc_payload)))
        reset_stack()
        if RUN_INIT_ONLY or stop_at == "init":
            mu.reg_write(UC_X86_REG_EIP, init_va)
            print(f"[+] Running init-only at 0x{init_va:08X}")
            start_addr = init_va
            next_addr = None
        else:
            # Run init first; then next stage depends on mode.
            mu.reg_write(UC_X86_REG_EIP, init_va)
            print(f"[+] Running init at 0x{init_va:08X}")
            start_addr = init_va
            next_addr = logwrite_va if mode in ("logwrite", "full") else decrypt_va
    else:
        # Start execution at LogWrite
        reset_stack(args=[0, 0, 0, image_base])
        mu.reg_write(UC_X86_REG_EIP, logwrite_va)
        start_addr = logwrite_va
        next_addr = None

    print(f"[+] LogWrite RVA: 0x{logwrite_rva:08X}  VA: 0x{logwrite_va:08X}")
    print(f"[+] Breakpoint RVA: 0x{BREAK_RVA:08X} VA: 0x{break_va:08X}")
    print(f"[+] Starting emulation...")

    # Step limit enforced in on_code to allow logging of the stop reason
    try:
        mu.emu_start(start_addr, 0, timeout=0, count=0)
    except UcError as e:
        # Returning to our fake RET commonly manifests as a FETCH_UNMAPPED at 0x41414141.
        # Treat that as a normal end-of-function so we can continue to the next stage.
        try:
            cur = mu.reg_read(UC_X86_REG_EIP)
        except Exception:
            cur = 0
        if "UC_ERR_FETCH_UNMAPPED" in str(e) and cur == RET_ADDR:
            pass
        else:
            # fall through to the legacy handler below
            raise

    try:
        if enc_payload and next_addr:
            if next_addr == decrypt_va and stop_at == "decrypt":
                raise UcError("Stopped at decrypt (requested)") # type: ignore

            def run_decrypt_with_seed(seed: int):
                # Re-point globals to encrypted payload buffer after init.
                mu.mem_write(g_buf, struct.pack("<I", payload_addr))
                mu.mem_write(g_len, struct.pack("<I", len(enc_payload)))
                mu.mem_write(g_seed, struct.pack("<I", seed))
                # restore encrypted bytes (decrypt may be in-place or allocate a new output buffer)
                mu.mem_write(payload_addr, enc_payload)
                reset_stack()
                mu.reg_write(UC_X86_REG_EIP, next_addr)
                insn_count["n"] = 0
                try:
                    mu.emu_start(next_addr, 0, timeout=0, count=0)
                except UcError as e:
                    try:
                        cur = mu.reg_read(UC_X86_REG_EIP)
                    except Exception:
                        cur = 0
                    if "UC_ERR_FETCH_UNMAPPED" in str(e) and cur == RET_ADDR:
                        # treat return to fake RET as normal end
                        pass
                    else:
                        print(f"[!] Decrypt emulation error: {e}")
                try:
                    out_ptr = struct.unpack("<I", mu.mem_read(g_buf, 4))[0]
                    out_len = struct.unpack("<I", mu.mem_read(g_len, 4))[0]
                except Exception:
                    out_ptr, out_len = payload_addr, len(enc_payload)
                out_len = max(0, min(out_len, 0x4000000))
                try:
                    blob = bytes(mu.mem_read(out_ptr, out_len))
                except Exception:
                    blob = b""
                _, ent = score_buffer(blob)
                return out_ptr, out_len, blob, ent

            # Check seed; if init didn't set it, fall back to known value.
            try:
                seed_now = struct.unpack("<I", mu.mem_read(g_seed, 4))[0]
            except Exception:
                seed_now = 0
            if seed_now == 0:
                print("[!] Init did not set seed; applying fallback seed.")
                seed_now = seed_value
            else:
                print(f"[+] Init seed = 0x{seed_now:08X}")

            if next_addr == decrypt_va:
                print(f"[+] Decrypting payload via 0x{next_addr:08X} len={len(enc_payload)} using seed 0x{seed_now:08X}")
                out_ptr1, out_len1, blob1, ent1 = run_decrypt_with_seed(seed_now)
                best_ptr, best_len, best_blob, best_ent, best_seed = out_ptr1, out_len1, blob1, ent1, seed_now

                # If init seed differs from fallback, try fallback and compare entropy.
                if seed_now != seed_value:
                    print(f"[+] Trying fallback seed 0x{seed_value:08X} for comparison")
                    out_ptr2, out_len2, blob2, ent2 = run_decrypt_with_seed(seed_value)
                    if ent2 < best_ent and blob2:
                        best_ptr, best_len, best_blob, best_ent, best_seed = out_ptr2, out_len2, blob2, ent2, seed_value
                    print(f"[+] Decrypt entropy: init={ent1:.3f} fallback={ent2:.3f}; using 0x{best_seed:08X}")
                else:
                    print(f"[+] Decrypt entropy: {ent1:.3f}")

                # Normalize: copy best blob into a stable buffer and point globals at it.
                if best_blob:
                    stable = stubs.virtual_alloc(0, best_len, 0, 0)
                    mu.mem_write(stable, best_blob)
                    mu.mem_write(g_buf, struct.pack("<I", stable))
                    mu.mem_write(g_len, struct.pack("<I", best_len))
            else:
                # Run LogWrite (which calls VirtualProtect + decrypt internally).
                # Ensure globals point at the encrypted payload buffer.
                try:
                    buf_ptr = struct.unpack("<I", mu.mem_read(g_buf, 4))[0]
                except Exception:
                    buf_ptr = 0
                if not buf_ptr:
                    buf_ptr = stubs.virtual_alloc(0, len(enc_payload), 0, 0)
                    mu.mem_write(g_buf, struct.pack("<I", buf_ptr))
                # Copy encrypted bytes into the buffer LogWrite expects.
                try:
                    mu.mem_write(buf_ptr, enc_payload)
                except Exception:
                    map_range(buf_ptr, len(enc_payload))
                    mu.mem_write(buf_ptr, enc_payload)
                mu.mem_write(g_len, struct.pack("<I", len(enc_payload)))
                # If init failed to compute a seed, use the known-good seed from prior runs.
                try:
                    seed_now = struct.unpack("<I", mu.mem_read(g_seed, 4))[0]
                except Exception:
                    seed_now = 0
                if seed_now == 0:
                    seed_now = 0xA043A524
                    mu.mem_write(g_seed, struct.pack("<I", seed_now))
                    print(f"[!] Init produced seed=0; forcing seed=0x{seed_now:08X}")
                else:
                    print(f"[+] Init seed = 0x{seed_now:08X}")

                reset_stack(args=[0, 0, 0, image_base])
                mu.reg_write(UC_X86_REG_EIP, logwrite_va)
                insn_count["n"] = 0
                if stop_at == "logwrite":
                    raise UcError("Stopped at logwrite (requested)") # type: ignore
                mu.emu_start(logwrite_va, 0, timeout=0, count=0)
    except UcError as e:
        # If we hit the known exception site, skip it and continue once.
        try:
            if "UC_ERR_INSN_INVALID" in str(e):
                try:
                    cur = mu.reg_read(UC_X86_REG_EIP)
                except Exception:
                    cur = 0
                insn = decode_insn(cur) if cur else None
                if insn:
                    print(f"[!] Invalid instruction at 0x{cur:08X}: {insn.mnemonic} {insn.op_str}")
                else:
                    try:
                        raw = bytes(mu.mem_read(cur, 16))
                        print(f"[!] Invalid instruction at 0x{cur:08X}: bytes={raw.hex()}")
                    except Exception:
                        pass

            # Stage1 sometimes relies on SEH to recover from intentionally-invalid opcodes.
            # If we fault while executing inside stage1, try a bounded "byte-skip" recovery.
            try:
                cur_eip = mu.reg_read(UC_X86_REG_EIP)
            except Exception:
                cur_eip = 0

            # High-address access faults (exception-driven control flow) recovery:
            # if our invalid-mem hook recorded a stage1 fault, advance EIP once and resume.
            if stage1_fault.get("pending") and stage1_ran["done"] and in_stage1(cur_eip) and (
                "UC_ERR_READ_UNMAPPED" in str(e) or "UC_ERR_WRITE_UNMAPPED" in str(e)
            ):
                stage1_fault["pending"] = False
                stage1_exc_skips["n"] += 1
                if stage1_exc_skips["n"] > 5000:
                    print("[!] Too many stage1 exception-skips; stopping stage1")
                    raise
                try:
                    nxt = int(stage1_fault.get("next_eip") or (cur_eip + 1))
                    print(
                        f"[!] Stage1 exc-skip#{stage1_exc_skips['n']} "
                        f"@0x{cur_eip:08X} addr=0x{int(stage1_fault.get('addr') or 0):08X} "
                        f":: {stage1_fault.get('disasm')}"
                    )
                    mu.reg_write(UC_X86_REG_EIP, nxt)
                    mu.emu_start(mu.reg_read(UC_X86_REG_EIP), 0, timeout=0, count=0)
                    return
                except Exception:
                    raise

            if stage1_ran["done"] and in_stage1(cur_eip) and (
                "UC_ERR_INSN_INVALID" in str(e) or "UC_ERR_EXCEPTION" in str(e)
            ):
                budget = 2048
                while budget > 0:
                    budget -= 1
                    cur = mu.reg_read(UC_X86_REG_EIP)
                    insn = decode_insn(cur)
                    step = insn.size if insn else 1
                    mu.reg_write(UC_X86_REG_EIP, cur + step)
                    if budget in (2047, 2000, 1500, 1000, 500) or (budget % 256 == 0):
                        print(f"[!] Stage1 recovery: advanced EIP 0x{cur:08X} -> 0x{cur+step:08X} (step={step})")
                    try:
                        mu.emu_start(mu.reg_read(UC_X86_REG_EIP), 0, timeout=0, count=0)
                        break
                    except UcError as e2:
                        # Keep skipping while errors remain inside stage1.
                        try:
                            cur2 = mu.reg_read(UC_X86_REG_EIP)
                        except Exception:
                            cur2 = 0
                        if not in_stage1(cur2) or ("UC_ERR_INSN_INVALID" not in str(e2) and "UC_ERR_EXCEPTION" not in str(e2)):
                            raise
                else:
                    print("[!] Stage1 recovery budget exhausted; stopping.")
                    raise
                # If we recovered, don't fall through to generic handler.
                return

            cur_eip = mu.reg_read(UC_X86_REG_EIP)
            if cur_eip == image_base + 0x220E and "UC_ERR_EXCEPTION" in str(e):
                esp = mu.reg_read(UC_X86_REG_ESP)
                ret = struct.unpack("<I", mu.mem_read(esp, 4))[0]
                mu.reg_write(UC_X86_REG_EIP, ret)
                mu.reg_write(UC_X86_REG_ESP, esp + 4)
                print("[!] Skipped exception at 0x1000220E; resuming")
                mu.emu_start(mu.reg_read(UC_X86_REG_EIP), 0, timeout=0, count=0)
            elif image_base + 0xE180 <= cur_eip <= image_base + 0xE300 and "UC_ERR_EXCEPTION" in str(e):
                insn = decode_insn(cur_eip)
                if insn:
                    mu.reg_write(UC_X86_REG_EIP, cur_eip + insn.size)
                    print(f"[!] Skipped exception at 0x{cur_eip:08X}; resuming")
                    mu.emu_start(mu.reg_read(UC_X86_REG_EIP), 0, timeout=0, count=0)
            else:
                print(f"[!] Emulation error: {e}")
        except Exception:
            print(f"[!] Emulation error: {e}")

    try:
        last_eip = mu.reg_read(UC_X86_REG_EIP)
        print(f"[*] Stopped at EIP=0x{last_eip:08X}")
    except Exception:
        pass

    # If we let LogWrite transfer control into the stage1 payload (full mode), prefer dumping what
    # the stage1 actually *wrote* rather than dumping a giant mostly-zero allocation.
    if stage1_ran["done"]:
        try:
            if stage2_pe_write["addr"]:
                base = stage2_pe_write["addr"]
                size = stage2_pe_write["size"] or 0x100000
                size = max(0x1000, min(size, 0x400000))
                blob = bytes(mu.mem_read(base, size))
                with open(out_stage2_path, "wb") as f:
                    f.write(blob)
                print(f"[+] Live dump: wrote PE-like buffer to {out_stage2_path} @0x{base:08X} size=0x{size:X}")
            elif stage2.get("addr"):
                base = stage2["addr"]
                size = 0x100000
                blob = bytes(mu.mem_read(base, size))
                with open(out_stage2_path, "wb") as f:
                    f.write(blob)
                print(f"[+] Live dump: wrote candidate buffer to {out_stage2_path} @0x{base:08X} size=0x{size:X}")
        except Exception as e:
            print(f"[!] Live dump (PE-like) failed: {e}")

        try:
            counts = stage2_page_writes["counts"]
            if counts:
                pages = sorted(counts.keys())
                map_path = out_stage2_live_path + ".map.txt"
                with open(out_stage2_live_path, "wb") as out_f, open(map_path, "w") as map_f:
                    for p in pages:
                        try:
                            data = bytes(mu.mem_read(p, 0x1000))
                        except Exception:
                            continue
                        out_f.write(data)
                        map_f.write(f"0x{p:08X} writes={counts.get(p,0)}\n")
                print(f"[+] Live dump: wrote {len(pages)} written pages to {out_stage2_live_path} (+ {map_path})")

                # Also dump a contiguous span covering all written pages. This is often easier to
                # analyze than the sparse page list, and it captures writes slightly below/above
                # 0x00400000 (e.g., 0x003FF000) that our fixed-base dump might miss.
                try:
                    span_base = pages[0]
                    span_end = pages[-1] + 0x1000
                    span_len = span_end - span_base
                    # Keep it bounded; stage1 can scribble broadly when emulation goes off-rails.
                    span_len = max(0x1000, min(span_len, 0x02000000))  # cap at 32MB
                    # Read per-page so a single unmapped hole doesn't fail the whole dump.
                    with open(out_stage2_span_path, "wb") as f:
                        for p in range(span_base, span_base + span_len, 0x1000):
                            try:
                                f.write(bytes(mu.mem_read(p, 0x1000)))
                            except Exception:
                                f.write(b"\x00" * 0x1000)
                    sh = sha256_file(out_stage2_span_path)
                    print(f"[+] Wrote stage2 written-page span to {out_stage2_span_path} base=0x{span_base:08X} len=0x{span_len:X} sha256={sh}")
                    write_base_file(out_stage2_span_path, span_base, span_len, {"sha256": sh})
                except Exception as e:
                    print(f"[!] Stage2 written-page span dump failed: {e}")
        except Exception as e:
            print(f"[!] Live dump (written-pages) failed: {e}")

        # Additionally, if stage1 wrote anything into the common PE base window (0x00400000),
        # dump a flat memory image from that base. This is easier to feed into PE tooling than
        # the sparse written-pages dump.
        try:
            stage2_pages = sorted([p for p in stage2_page_writes["counts"].keys() if STAGE2_MEMIMG_BASE <= p < 0x01400000])
            if stage2_pages:
                base = STAGE2_MEMIMG_BASE
                hi = stage2_pages[-1] + 0x1000
                length = hi - base
                # If we validated a PE header earlier, prefer its size (capped).
                if stage2_pe_write["addr"] == base and stage2_pe_write.get("size"):
                    sz = int(stage2_pe_write["size"]) # type: ignore
                    if 0x1000 <= sz <= 0x2000000:
                        length = align_up(sz, 0x1000)
                # Ensure we dump enough to include early unpacked headers/sections even if only a
                # single page was written so far.
                length = max(0x20000, min(length, 0x1000000))
                blob = bytes(mu.mem_read(base, length))
                with open(out_stage2_memimg_path, "wb") as f:
                    f.write(blob)
                sh = sha256_file(out_stage2_memimg_path)
                print(f"[+] Wrote stage2 flat memory image to {out_stage2_memimg_path} base=0x{base:08X} len=0x{length:X} sha256={sh}")
                write_base_file(out_stage2_memimg_path, base, length, {"sha256": sh})
        except Exception as e:
            print(f"[!] Stage2 flat memory image dump failed: {e}")

    # If we decrypted directly, dump output buffer after emulation
    if enc_payload and mode in ("decrypt", "full") and not dumped["done"]:
        try:
            out_ptr = struct.unpack("<I", mu.mem_read(g_buf, 4))[0]
            out_len = struct.unpack("<I", mu.mem_read(g_len, 4))[0]
            if out_len <= 0:
                out_len = len(enc_payload)
            blob = bytes(mu.mem_read(out_ptr, out_len))
            with open(out_shellcode_path, "wb") as f:
                f.write(blob)
            sh = sha256_file(out_shellcode_path)
            print(f"[+] Wrote {len(blob)} bytes to {out_shellcode_path} sha256={sh} from decrypted payload buffer @0x{out_ptr:08X}")
            write_stage1_base_file(out_shellcode_path, out_ptr, len(blob), sh)
        except Exception as e:
            print(f"[!] Failed to dump decrypted buffer: {e}")

        # Scan heap allocations for lower-entropy or PE-like buffers.
        best = None
        best_addr = None
        for b2, sz2 in stubs.allocations.items():
            try:
                max_b = min(sz2, 0x400000)
                buf = bytes(mu.mem_read(b2, max_b))
            except Exception:
                continue
            nz, ent = score_buffer(buf)
            # prefer larger non-zero buffers and presence of MZ; don't auto-prefer very low entropy (often just zeroed buffers)
            has_mz = b"MZ" in buf[:0x200]
            score = (nz, 1 if has_mz else 0, -ent)
            if best is None or score > best:
                best = score
                best_addr = b2
                best_buf = buf
        if best_addr is not None:
            with open(out_stage2_path, "wb") as f:
                f.write(best_buf)
            try:
                _, ent = score_buffer(best_buf)
            except Exception:
                ent = 0.0
            print(f"[+] Wrote candidate heap buffer to {out_stage2_path} at 0x{best_addr:08X} (entropy={ent:.3f})")

    if returned["done"] and not dumped["done"]:
        print("[!] LogWrite returned before breakpoint.")
    if not dumped["done"]:
        print("[!] Breakpoint was not reached. See notes below for improving stubs.")

    def find_pe_in_region(start, size, label):
        try:
            buf = bytes(mu.mem_read(start, size))
        except Exception:
            return None
        idx = buf.find(b"MZ")
        if idx == -1:
            return None
        # look for PE sig near e_lfanew
        try:
            e_lfanew = struct.unpack_from("<I", buf, idx + 0x3c)[0]
            pe_off = idx + e_lfanew
            if 0 <= pe_off + 4 <= len(buf) and buf[pe_off:pe_off+4] == b"PE\x00\x00":
                return (start + idx, start + pe_off, label)
        except Exception:
            pass
        return None

    def score_entry(buf, off):
        # Disassemble a small window and score instruction density + basic sanity.
        max_len = min(0x80, len(buf) - off)
        if max_len < 8:
            return None
        window = buf[off:off + max_len]
        total = 0
        insn_count = 0
        bad = 0
        for insn in md.disasm(window, 0):
            insn_count += 1
            total += insn.size
            if insn.mnemonic in ("int3", "int", "ud2"):
                bad += 2
            if insn.mnemonic in ("hlt", "cli", "sti"):
                bad += 1
            if total >= max_len:
                break
        if insn_count == 0:
            return None
        density = total / max_len
        # Small bonuses for common prologue-ish instructions
        bonus = 0
        if window[:2] in (b"\x55\x8B", b"\x60\x8B"):
            bonus += 2
        if window[:1] == b"\xFC":  # cld
            bonus += 1
        score = density * 100 + insn_count + bonus - bad
        return score

    def find_shellcode_entry(buf):
        # Heuristic: scan for plausible shellcode entry points and rank them.
        max_scan = min(len(buf) - 6, 0x40000)
        if max_scan <= 0:
            return [(0, 0.0)]
        seed_candidates = set()
        for i in range(max_scan):
            # call $+5; pop reg
            if buf[i] == 0xE8 and buf[i+1:i+5] == b"\x00\x00\x00\x00" and 0x58 <= buf[i+5] <= 0x5F:
                seed_candidates.add(i)
            # pushad; mov ebp, esp
            if buf[i:i+3] == b"\x60\x8B\xEC":
                seed_candidates.add(i)
            # cld; call
            if buf[i] == 0xFC and i + 5 < max_scan and buf[i+1] == 0xE8:
                seed_candidates.add(i)
            # sub esp, imm8/imm32; call
            if buf[i] == 0x83 and buf[i+1] == 0xEC and i + 4 < max_scan:
                seed_candidates.add(i)

        # Add a light-weight scan every 16 bytes to find dense instruction regions.
        for i in range(0, max_scan, 16):
            sc = score_entry(buf, i)
            if sc is not None and sc > 40:
                seed_candidates.add(i)

        # Always consider offset 0
        seed_candidates.add(0)

        ranked = []
        for off in seed_candidates:
            sc = score_entry(buf, off)
            if sc is None:
                continue
            ranked.append((sc, off))
        ranked.sort(reverse=True)
        return [(off, sc) for sc, off in ranked[:40]]

    # Stage2 emulation: execute decrypted shellcode and look for PE drop.
    if enc_payload and mode in ("stage2", "full") and stop_at != "stage2" and not stage1_ran["done"]:
        try:
            stage2_base = 0x40000000
            try:
                out_ptr = struct.unpack("<I", mu.mem_read(g_buf, 4))[0]
                out_len = struct.unpack("<I", mu.mem_read(g_len, 4))[0]
            except Exception:
                out_ptr, out_len = 0x00200000, len(enc_payload)
            out_len = max(0, min(out_len, 0x4000000))
            dec_buf = bytes(mu.mem_read(out_ptr, out_len))
            map_range(stage2_base, len(dec_buf))
            mu.mem_write(stage2_base, dec_buf)
            stage2_region["base"] = stage2_base
            stage2_region["size"] = len(dec_buf)
            stage2_candidates.clear()
            stage2["found"] = False
            stage2["addr"] = None
            stage2_writes["n"] = 0
            stage2_writes["last_insn"] = 0
            stage2_pe_write["addr"] = None
            stage2_pe_write["size"] = None
            stage2_page_writes["counts"].clear()
            stage2_page_writes["best_page"] = None
            stage2_best_shellcode["addr"] = None
            stage2_best_shellcode["score"] = None
            # Map low memory region often used by shellcode for scratch/PEB-walk tricks.
            try:
                map_range(0x00001000, 0x00100000)
            except Exception:
                pass
            # Map a PE-like region for unpacking (common 0x00400000 base).
            try:
                map_range(0x00400000, 0x01000000)
            except Exception:
                pass
            # Map a high stack region some stages use (0xA0xxxxxx)
            try:
                map_range(0xA0000000, 0x01000000)
            except Exception:
                pass
            # Stage2 stack
            try:
                mu.mem_map(0x0FF00000, 0x00100000)
            except Exception:
                pass
            # Some shellcode pivots ESP near 0x200000; map a low stack region.
            map_range(0x00100000, 0x00300000)
            mu.reg_write(UC_X86_REG_ESP, 0x0FF80000)
            candidates = find_shellcode_entry(dec_buf)
            if not candidates:
                candidates = [(0, 0.0)]
            print("[+] Stage2 candidate offsets (top 10):")
            for off, sc in candidates[:10]:
                print(f"    offset 0x{off:X} score {sc:.1f}")
            for idx, (off, sc) in enumerate(candidates, 1):
                try:
                    stage2_invalid["n"] = 0
                    insn_count["n"] = 0
                    stage2_writes["n"] = 0
                    stage2_writes["last_insn"] = 0
                    stage2_pe_write["addr"] = None
                    stage2_pe_write["size"] = None
                    stage2_page_writes["counts"].clear()
                    stage2_page_writes["best_page"] = None
                    stage2_best_shellcode["addr"] = None
                    stage2_best_shellcode["score"] = None
                    # Set a high ESP to avoid pop/push into unmapped memory
                    mu.reg_write(UC_X86_REG_ESP, 0xA00FF000)
                    entry = stage2_base + off
                    # Skip obviously wrong entrypoints.
                    first = decode_insn(entry)
                    if first and (
                        first.mnemonic in ("ret", "retf", "iret", "iretd")
                        or (first.mnemonic == "push" and ("cs" in first.op_str or "ss" in first.op_str))
                        or first.mnemonic in ("pushal", "pusha")
                    ):
                        print(f"[!] Skipping candidate {idx} (offset 0x{off:X}) due to first insn: {first.mnemonic} {first.op_str}")
                        continue
                    mu.reg_write(UC_X86_REG_EIP, entry)
                    # Seed common regs for shellcode that expects a base pointer.
                    mu.reg_write(UC_X86_REG_EAX, entry)
                    mu.reg_write(UC_X86_REG_EBX, entry)
                    mu.reg_write(UC_X86_REG_ECX, 0xFFFFFFFF)
                    mu.reg_write(UC_X86_REG_EDX, 0)
                    mu.reg_write(UC_X86_REG_ESI, stage2_base)
                    mu.reg_write(UC_X86_REG_EDI, 0x00400000)
                    mu.reg_write(UC_X86_REG_EBP, stage2_base)
                    print(f"[+] Starting stage2 emulation {idx} at 0x{stage2_base + off:08X} (offset 0x{off:X})")
                    stage2_active["on"] = True
                    stage2_active["kind"] = "candidate" 
                    stage2_trace["fh"] = open(out_stage2_trace_path, "w") # type: ignore
                    try:
                        mu.emu_start(entry, 0, timeout=0, count=STAGE2_MAX_INSN)
                    except UcError as e:
                        # Skip invalid instructions/exceptions and continue briefly.
                        if "UC_ERR_INSN_INVALID" in str(e) or "UC_ERR_EXCEPTION" in str(e):
                            for _ in range(50):
                                cur = mu.reg_read(UC_X86_REG_EIP)
                                insn = decode_insn(cur)
                                step = insn.size if insn else 1
                                mu.reg_write(UC_X86_REG_EIP, cur + step)
                                try:
                                    mu.emu_start(mu.reg_read(UC_X86_REG_EIP), 0, timeout=0, count=50_000)
                                    break
                                except UcError:
                                    continue
                        else:
                            raise
                    finally:
                        stage2_active["on"] = False
                        stage2_active["kind"] = "none"
                        if stage2_trace["fh"]:
                            stage2_trace["fh"].close()
                            stage2_trace["fh"] = None
                        print(f"[+] Finished stage2 candidate {idx} (offset 0x{off:X})")
                        if stage2_pe_write["addr"]:
                            print(f"[+] Stage2 produced PE header at 0x{stage2_pe_write['addr']:08X}")
                        # Evaluate most-written page for shellcode-like content
                        if stage2_page_writes["best_page"] is not None:
                            base = stage2_page_writes["best_page"]
                            try:
                                buf = bytes(mu.mem_read(base, STAGE2_DUMP_SIZE))
                                score, ent, insn_count2 = score_shellcode(buf)
                                prev = stage2_best_shellcode["score"]
                                if prev is None or score > prev:
                                    stage2_best_shellcode["score"] = score # type: ignore
                                    stage2_best_shellcode["addr"] = base
                                print(f"[+] Stage2 best-page candidate at 0x{base:08X} score={score:.1f} ent={ent:.3f} insn={insn_count2}")
                            except Exception:
                                pass
                    if stage2["found"]:
                        break
                except Exception as e:
                    stage2_active["on"] = False
                    stage2_active["kind"] = "none"
                    if stage2_trace["fh"]:
                        stage2_trace["fh"].close()
                        stage2_trace["fh"] = None
                    print(f"[!] Stage2 emulation error at offset 0x{off:X}: {e}")
        except Exception as e:
            print(f"[!] Stage2 emulation error: {e}")
        # Scan likely regions for a PE header
        candidates = []
        candidates.append(find_pe_in_region(0x00200000, min(DUMP_MAX, len(enc_payload)), "scratch"))
        candidates.append(find_pe_in_region(stage2_base, min(DUMP_MAX, len(enc_payload)), "stage2_base"))
        for base, sz in stubs.allocations.items():
            candidates.append(find_pe_in_region(base, min(sz, DUMP_MAX), "heap"))
        candidates = [c for c in candidates if c]
        if stage2_candidates:
            try:
                # pick the first candidate that lies in a mapped region
                dump_addr = None
                for cand in stage2_candidates:
                    if in_stage2_region(cand) or in_allocations(cand):
                        dump_addr = cand
                        break
                if dump_addr is None:
                    raise RuntimeError("No mapped stage2 candidates")
                dump_len = 0x100000
                blob = bytes(mu.mem_read(dump_addr, dump_len))
                with open(out_stage2_path, "wb") as f:
                    f.write(blob)
                print(f"[+] Wrote stage2 payload to {out_stage2_path} at 0x{dump_addr:08X} (candidate)")
            except Exception as e:
                print(f"[!] Failed to dump stage2 payload: {e}")
        elif candidates:
            pe_base, pe_sig, label = candidates[0]
            try:
                # dump 1MB from PE base
                dump_addr = pe_base
                dump_len = 0x100000
                blob = bytes(mu.mem_read(dump_addr, dump_len))
                with open(out_stage2_path, "wb") as f:
                    f.write(blob)
                print(f"[+] Wrote stage2 payload to {out_stage2_path} at 0x{dump_addr:08X} ({label})")
            except Exception as e:
                print(f"[!] Failed to dump stage2 payload: {e}")
        elif stage2_pe_write["addr"]:
            try:
                dump_addr = stage2_pe_write["addr"]
                dump_len = stage2_pe_write["size"] or 0x100000
                blob = bytes(mu.mem_read(dump_addr, dump_len))
                with open(out_stage2_path, "wb") as f:
                    f.write(blob)
                print(f"[+] Wrote stage2 payload to {out_stage2_path} at 0x{dump_addr:08X} (pe-region, size=0x{dump_len:X})")
            except Exception as e:
                print(f"[!] Failed to dump stage2 payload from PE region: {e}")
        elif stage2_best_shellcode["addr"] is not None:
            try:
                dump_addr = stage2_best_shellcode["addr"]
                dump_len = STAGE2_DUMP_SIZE
                blob = bytes(mu.mem_read(dump_addr, dump_len))
                with open(out_stage2_path, "wb") as f:
                    f.write(blob)
                print(f"[+] Wrote stage2 shellcode to {out_stage2_path} at 0x{dump_addr:08X} (size=0x{dump_len:X})")
            except Exception as e:
                print(f"[!] Failed to dump stage2 shellcode from best page: {e}")
        elif stage2["found"] and stage2["addr"]:
            try:
                dump_addr = stage2["addr"]
                dump_len = 0x100000
                blob = bytes(mu.mem_read(dump_addr, dump_len))
                with open(out_stage2_path, "wb") as f:
                    f.write(blob)
                print(f"[+] Wrote stage2 payload to {out_stage2_path} at 0x{dump_addr:08X}")
            except Exception as e:
                print(f"[!] Failed to dump stage2 payload: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Emulate log.dll LogWrite/decrypt payload.")
    parser.add_argument("dll", help="Path to log.dll")
    parser.add_argument("--payload", default="encrypted_shellcode.bin", help="Encrypted payload path")
    parser.add_argument("--input-dir", default="input", help="Directory to resolve bare input filenames from")
    parser.add_argument("--output-dir", default="output", help="Directory to write outputs to (created if missing)")
    parser.add_argument("--mode", choices=["decrypt", "logwrite", "stage2", "full"], default="full",
                        help="Which stages to run")
    parser.add_argument("--stop-at", choices=["none", "init", "decrypt", "break", "stage2"], default="none",
                        help="Early stop point")
    parser.add_argument("--stdout-log", default="emu_stdout.log",
                        help="Write stdout to this file (set to 'none' to disable)")
    args = parser.parse_args()

    dll_path = resolve_input_path(args.dll, args.input_dir)
    payload_path = resolve_input_path(args.payload, args.input_dir)
    os.makedirs(args.output_dir, exist_ok=True)

    stdout_log_path = resolve_output_path(args.stdout_log, args.output_dir)
    if stdout_log_path and stdout_log_path.lower() != "none":
        try:
            log_fh = open(stdout_log_path, "w")
            sys.stdout = TeeStdout(sys.stdout, log_fh)
        except Exception as e:
            print(f"[!] Failed to open stdout log {stdout_log_path}: {e}")

    emulate_and_dump(dll_path, payload_path, args.mode, args.stop_at, args.output_dir)
