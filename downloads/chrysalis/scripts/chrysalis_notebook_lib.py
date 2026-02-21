from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def shannon_entropy(b: bytes) -> float:
    if not b:
        return 0.0
    counts = [0] * 256
    for x in b:
        counts[x] += 1
    import math

    n = len(b)
    ent = 0.0
    for c in counts:
        if c == 0:
            continue
        p = c / n
        ent -= p * math.log2(p)
    return ent


def find_repo_root(start: Path) -> Path:
    """
    Try to find the repo root even if Jupyter starts in notebooks/.
    We treat the root as the first ancestor containing `input/` and `scripts/`.
    """
    start = start.resolve()
    candidates = [start, *start.parents]
    for d in candidates:
        if (d / "input").is_dir() and (d / "scripts" / "emulate_logwrite_dump_shellcode.py").exists():
            return d
    # Fallback: accept an ancestor with just input/
    for d in candidates:
        if (d / "input").is_dir():
            return d
    raise FileNotFoundError("Could not locate repo root (expected to find input/).")


def rc4_crypt(data: bytes, key: bytes) -> bytes:
    # Classic RC4 KSA+PRGA.
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    i = 0
    j = 0
    out = bytearray(len(data))
    for n, x in enumerate(data):
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        K = S[(S[i] + S[j]) & 0xFF]
        out[n] = x ^ K
    return bytes(out)

FNV1A_BASIS_32 = 0x811C9DC5
FNV1A_PRIME_32 = 0x01000193


def u32(x: int) -> int:
    return x & 0xFFFFFFFF


def fnv1a32(data: bytes, *, basis: int = FNV1A_BASIS_32, prime: int = FNV1A_PRIME_32) -> int:
    h = u32(basis)
    for b in data:
        h ^= b
        h = u32(h * prime)
    return u32(h)


def chrysalis_loader_finalizer32(h: int) -> int:
    """
    Finalizer observed in log.dll's API resolver (0x100014E0):
      x = h ^ (h >> 15)
      x = x * 0x85EBCA6B
      x = x ^ (x >> 13)
    """
    h = u32(h)
    x = u32(h ^ (h >> 15))
    x = u32(x * 0x85EBCA6B)
    x = u32(x ^ (x >> 13))
    return u32(x)


def loader_api_hash(export_name: str) -> int:
    return chrysalis_loader_finalizer32(fnv1a32(export_name.encode("ascii", errors="ignore")))


def loader_seed_from_host_image(host_image_bytes: bytes, *, seed_len: int = 0x100) -> int:
    """
    Seed derivation used by log.dll init:
      seed = finalizer(fnv1a(host_bytes[:0x100]))
    """
    return chrysalis_loader_finalizer32(fnv1a32(host_image_bytes[:seed_len]))


def loader_target_constant(export_name: str, *, seed: int) -> int:
    """
    log.dll compares:
      loader_api_hash(name) == seed + constant
    => constant = loader_api_hash(name) - seed
    """
    return u32(loader_api_hash(export_name) - seed)


@dataclass(frozen=True)
class Rapid7ConfigSpec:
    offset: int = 0x30808
    size: int = 0x980
    key: bytes = b"qwhvb^435h&*7"


class ConfigExtractor:
    def __init__(self, spec: Rapid7ConfigSpec | None = None) -> None:
        self.spec = spec or Rapid7ConfigSpec()

    def extract_and_decrypt(self, encrypted_shellcode_path: Path) -> bytes:
        b = encrypted_shellcode_path.read_bytes()
        off = self.spec.offset
        size = self.spec.size
        if off + size > len(b):
            raise ValueError(
                f"Config range OOB: off=0x{off:X} size=0x{size:X} file_len=0x{len(b):X}"
            )
        enc = b[off : off + size]
        return rc4_crypt(enc, self.spec.key)


def bxform_byte(x: int, k: int) -> int:
    # Rapid7 main-module per-byte transform.
    x = (x + k) & 0xFF
    x = x ^ k
    x = (x - k) & 0xFF
    return x


def bxform_in_place(buf: bytearray, key: bytes, rounds: int = 1) -> None:
    if len(key) != 8:
        raise ValueError("Expected 8-byte key")
    for _ in range(rounds):
        for i in range(len(buf)):
            buf[i] = bxform_byte(buf[i], key[i & 7])


@dataclass(frozen=True)
class ArgStruct:
    """
    Mirrors the stage1 arg struct layout from Rapid7 for this sample.
    We only care about the region layout and image base.
    """

    dwords: tuple[int, ...]

    @classmethod
    def from_iterable(cls, xs: Iterable[int]) -> "ArgStruct":
        d = tuple(int(x) for x in xs)
        if len(d) != 25:
            raise ValueError(f"Expected 25 dwords, got {len(d)}")
        return cls(dwords=d)

    @property
    def image_base(self) -> int:
        return self.dwords[16]

    @property
    def region_rvas(self) -> list[int]:
        return [self.dwords[2], self.dwords[3], self.dwords[4], self.dwords[5], self.dwords[6]]

    @property
    def region_sizes(self) -> list[int]:
        return [self.dwords[9], self.dwords[10], self.dwords[11], self.dwords[12], self.dwords[13]]


class Stage1Decryptor:
    """
    Calls into the Unicorn-based log.dll emulator directly (no subprocess).
    """

    def __init__(self) -> None:
        # Import lazily so notebooks can run config-only without unicorn installed.
        try:
            from scripts.emulate_logwrite_dump_shellcode import emulate_and_dump
        except Exception:
            from emulate_logwrite_dump_shellcode import emulate_and_dump

        self._emulate_and_dump = emulate_and_dump

    def run(
        self,
        log_dll_path: Path,
        encrypted_payload_path: Path,
        output_dir: Path,
        mode: str = "logwrite",
        stop_at: str = "none",
    ) -> None:
        output_dir.mkdir(parents=True, exist_ok=True)
        self._emulate_and_dump(str(log_dll_path), str(encrypted_payload_path), mode, stop_at, str(output_dir))


class MainModuleMaterializer:
    """
    Offline materializer for the Rapid7 sample's main module:
    - Build a memory image from a container PE (headers + raw sections mapped at RVA)
    - Overwrite 5 RVA regions with encrypted bytes sourced from stage1 (stage1_full dump)
    - Apply the main-module byte transform in-place for those regions
    - Emit:
      - a patched PE on disk (container with those RVA regions overwritten+decrypted)
      - a memory image blob (SizeOfImage bytes, mapped at ImageBase)

    Note: This intentionally avoids emulating stage1/SEH behavior.
    """

    def __init__(self, key: bytes = b"gQ2JR&9;", rounds: int = 1) -> None:
        if len(key) != 8:
            raise ValueError("Expected 8-byte key")
        self.key = key
        self.rounds = rounds

    def _build_container_mem(self, container_pe: bytes) -> tuple[bytearray, int, int, int, list[dict]]:
        # Reuse offline_extract_stage2's PE parser for stable RVA->raw mapping.
        try:
            from scripts.offline_extract_stage2 import parse_pe_sections
        except Exception:
            from offline_extract_stage2 import parse_pe_sections

        image_base, size_of_headers, size_of_image, sections = parse_pe_sections(container_pe)
        mem = bytearray(size_of_image)
        mem[: min(size_of_headers, len(container_pe))] = container_pe[: min(size_of_headers, len(container_pe))]
        for s in sections:
            va, rptr, rsz = s["va"], s["raw"], s["rsz"]
            if rptr >= len(container_pe):
                continue
            mem[va : va + rsz] = container_pe[rptr : rptr + rsz].ljust(rsz, b"\x00")
        return mem, image_base, size_of_headers, size_of_image, sections

    def _apply_regions_from_stage1(
        self,
        mem: bytearray,
        stage1: bytes,
        region_rvas: list[int],
        region_sizes: list[int],
        *,
        stage1_start: int = 0,
    ) -> None:
        # The Rapid7 stage1 provides a contiguous blob containing the 5 regions in order.
        # In our workflow, stage1_full is a 2MB dump where the encrypted region bytes appear
        # at their RVA offsets already, so start=0 is correct for this sample.
        #
        # Keep this simple: if stage1 contains bytes at [rva:rva+size], use those.
        for rva, sz in zip(region_rvas, region_sizes):
            end = rva + sz
            if end <= len(stage1):
                mem[rva:end] = stage1[rva:end]
            else:
                # Partial fill is allowed; remainder stays as-is.
                if rva < len(stage1):
                    mem[rva:len(stage1)] = stage1[rva:len(stage1)]

    def materialize(
        self,
        *,
        container_pe_path: Path,
        stage1_full_path: Path,
        arg_struct: ArgStruct,
        out_patched_pe_path: Path,
        out_mem_image_path: Path,
    ) -> dict:
        container_raw = container_pe_path.read_bytes()
        stage1 = stage1_full_path.read_bytes()

        mem, image_base, size_of_headers, size_of_image, sections = self._build_container_mem(container_raw)

        region_rvas = arg_struct.region_rvas
        region_sizes = arg_struct.region_sizes

        # Inject encrypted bytes
        self._apply_regions_from_stage1(mem, stage1, region_rvas, region_sizes)

        # Decrypt in-place (only those regions)
        for rva, sz in zip(region_rvas, region_sizes):
            view = mem[rva : rva + sz]
            bxform_in_place(view, self.key, rounds=self.rounds)

        # Write memory image (what you'd map at ImageBase)
        out_mem_image_path.write_bytes(bytes(mem))

        # Build patched on-disk PE:
        # start from original file, overwrite raw ranges that correspond to the RVAs.
        # We use section table mapping from parse_pe_sections to convert RVA->file offset.
        patched = bytearray(container_raw)

        def rva_to_raw(rva: int) -> int | None:
            for s in sections:
                va, vsz, raw, rsz = s["va"], s["vsz"], s["raw"], s["rsz"]
                size = max(vsz, rsz)
                if va <= rva < va + size:
                    return raw + (rva - va)
            return None

        for rva, sz in zip(region_rvas, region_sizes):
            raw = rva_to_raw(rva)
            if raw is None:
                continue
            patched[raw : raw + sz] = mem[rva : rva + sz]

        out_patched_pe_path.write_bytes(bytes(patched))

        return {
            "image_base": image_base,
            "size_of_image": size_of_image,
            "size_of_headers": size_of_headers,
            "regions": list(zip(region_rvas, region_sizes)),
            "patched_pe_sha256": sha256_bytes(out_patched_pe_path.read_bytes()),
            "mem_image_sha256": sha256_bytes(out_mem_image_path.read_bytes()),
        }


class ApiHashRainbow:
    """
    Helper for nested rainbow tables produced by api_hash_rainbow.py --format nested.

    Data format:
      { "KERNEL32.dll": { "0x47C204CA": "VirtualProtect", ... }, ... }
    """

    def __init__(self, table: dict[str, dict[str, str | list[str]]]) -> None:
        self.table = table
        # Precompute a reverse index: hash -> list[(dll, export)]
        rev: dict[str, list[tuple[str, str]]] = {}
        for dll, m in table.items():
            for hk, exp in m.items():
                if isinstance(exp, list):
                    items = exp
                else:
                    items = [exp]
                for e in items:
                    rev.setdefault(hk.upper(), []).append((dll, e))
        self._rev = rev

    @classmethod
    def from_nested_json(cls, path: Path) -> "ApiHashRainbow":
        import json

        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("expected dict at top-level")
        return cls(data)

    def lookup(self, h: int) -> list[tuple[str, str]]:
        hk = f"0x{h & 0xFFFFFFFF:08X}"
        return list(self._rev.get(hk.upper(), []))

    def scan_pe_for_dword_hashes(
        self,
        pe_path: Path,
        *,
        only_sections: tuple[str, ...] = (".text",),
        step: int = 1,
        min_hits: int = 1,
    ) -> list[dict]:
        """
        Best-effort scan for immediate DWORD constants that match any rainbow hash.
        Returns a list of dicts: {file_off, rva, va, hash, matches}.

        This is heuristic and may produce false positives.
        """
        import pefile

        pe = pefile.PE(str(pe_path), fast_load=True)
        pe.parse_data_directories()

        wanted = set(self._rev.keys())
        hits: list[dict] = []
        for s in pe.sections:
            name = s.Name.rstrip(b"\x00").decode("ascii", errors="ignore")
            if only_sections and name not in only_sections:
                continue
            data = s.get_data()
            base_rva = s.VirtualAddress
            base_raw = s.PointerToRawData
            # Scan bytes for little-endian DWORDs.
            for off in range(0, max(0, len(data) - 4), step):
                val = struct.unpack_from("<I", data, off)[0]
                hk = f"0x{val:08X}"
                if hk.upper() not in wanted:
                    continue
                file_off = base_raw + off
                rva = base_rva + off
                va = pe.OPTIONAL_HEADER.ImageBase + rva
                hits.append(
                    {
                        "file_off": file_off,
                        "rva": rva,
                        "va": va,
                        "hash": hk,
                        "matches": self._rev[hk.upper()],
                        "section": name,
                    }
                )
        if min_hits and len(hits) < min_hits:
            return hits
        # stable ordering for notebooks
        hits.sort(key=lambda d: (d["rva"], d["file_off"]))
        return hits
