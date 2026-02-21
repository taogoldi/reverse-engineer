---
layout: single
title: "From log.dll To A Decrypted Chrysalis Main Module (Offline On macOS)"
date: 2026-02-21 00:00:00 +0000
permalink: /blog/chrysalis-offline-unpacking/
toc: true
---

This write-up documents an end-to-end offline workflow for unpacking the Lotus Blossom “Chrysalis” chain described by Rapid7 (Feb 2026), without running the malware in a Windows debugger.

The goal was to produce a workflow another analyst could rerun on a different machine and still land on the same bytes, the same hashes, and the same reversing pivots. Instead of relying on a fragile live-debugger session, this approach treats each stage as a measurable checkpoint and keeps the output evidence-centered.

## Summary and Attribution

This project started as a practical engineering exercise: can we turn a good threat-intel write-up into a reproducible unpacking pipeline with auditable outputs? Rapid7 already established the family behavior and high-level chain, so the work here focused on implementation discipline, verification, and handoff quality for other reverse engineers.

Primary upstream research and malware-family analysis credit goes to Rapid7:
- [The Chrysalis Backdoor: A Deep Dive into Lotus Blossom’s toolkit (Rapid7)](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit/)

This post focuses on reproducibility and analyst workflow:
- deterministic offline extraction on macOS/Linux
- scriptable unpacking and config decryption
- SQLite/CFG diff generation for reverse engineering handoff

The constraints are practical:
- The loader and payload are x86 Windows artifacts.
- The analysis environment is an ARM Mac.
- We still want deterministic outputs we can reverse in Ghidra/IDA and share as hashes/artifacts.

## Downloads

Everything referenced in this article is grouped so readers can either consume the write-up quickly or pull the exact scripts and reports needed to reproduce one section at a time. The intent is to make this usable as both a narrative report and a working analysis kit.

### Source and tooling bundles

- Bundle index: [Open]({{ "/downloads/chrysalis/" | relative_url }})
- Scripts/emulators bundle: [Folder]({{ "/downloads/chrysalis/scripts/" | relative_url }})
- IDA automation scripts: [Folder]({{ "/downloads/chrysalis/ida/" | relative_url }})
- Notebooks bundle: [Folder]({{ "/downloads/chrysalis/notebooks/" | relative_url }})
- DB diff CSV reports: [Folder]({{ "/downloads/chrysalis/reports/db_diff_reports/" | relative_url }})
- Binary diff results: [Folder]({{ "/downloads/chrysalis/reports/binary_diff/" | relative_url }})
- Pipeline flowchart assets: [Folder]({{ "/downloads/chrysalis/docs/" | relative_url }})

### Direct files often requested

- `run_chrysalis_pipeline.py`: [download]({{ "/downloads/chrysalis/scripts/run_chrysalis_pipeline.py" | relative_url }})
- `emulate_logwrite_dump_shellcode.py`: [download]({{ "/downloads/chrysalis/scripts/emulate_logwrite_dump_shellcode.py" | relative_url }})
- `offline_extract_stage2.py`: [download]({{ "/downloads/chrysalis/scripts/offline_extract_stage2.py" | relative_url }})
- `render_cfg_diff_html.py`: [download]({{ "/downloads/chrysalis/scripts/render_cfg_diff_html.py" | relative_url }})
- `sqlite_diff_report.py`: [download]({{ "/downloads/chrysalis/scripts/sqlite_diff_report.py" | relative_url }})
- `patched_diff.txt`: [download]({{ "/downloads/chrysalis/reports/binary_diff/patched_diff.txt" | relative_url }})
- `patched_diff.json`: [download]({{ "/downloads/chrysalis/reports/binary_diff/patched_diff.json" | relative_url }})
- `chrysalis_unpacking_walkthrough.ipynb`: [download]({{ "/downloads/chrysalis/notebooks/chrysalis_unpacking_walkthrough.ipynb" | relative_url }})

## File Hashes (Inputs and Produced Artifacts)

The hash table is the trust boundary for the whole report. If a reader cannot match these values, they should assume they are on a different sample, a different transformation path, or a broken environment and stop before drawing conclusions.

All hashes below are SHA-256 values from the workflow run referenced in this report.

| Artifact | Role | SHA-256 | Download |
|---|---|---|---|
| `input/log.dll` | Input sample | `3bdc4c0637591533f1d4198a72a33426c01f69bd2e15ceee547866f65e26b7ad` | Not redistributed |
| `input/BluetoothService.exe` | Input sample | `2da00de67720f5f13b17e9d985fe70f10f153da60c9ab1086fe58f069a156924` | Not redistributed |
| `input/encrypted_shellcode.bin` | Input sample | `77bfea78def679aa1117f569a35e8fd1542df21f7e00e27f192c907e61d63a2e` | Not redistributed |
| `output/shellcode.bin` | Produced (stage1 dump) | `4416729d92e22ccb93e26c6896efe056b851a914727969f0ff604da4ef18ccfa` | Not redistributed (malware-derived) |
| `output/shellcode_full.bin` | Produced (full stage1 region) | `83f17d256d010ebfec8d58c4217f54a73d8237aa51ebab75c3e50f111d883d49` | Not redistributed (malware-derived) |
| `output/main_module_patched.exe` | Produced (patched module) | `bd0fb50084a21876fdbcf33fc7cf1949b78020f9e169086b2dd0b6aae28ad359` | Not redistributed (malware-derived) |
| `output/main_module_mem.bin` | Produced (memory image) | `129a91eaa5e03b112ecfccd858b8c7fc4f482158a53d8300f2505d7c120f87d3` | Not redistributed (malware-derived) |
| `output/config_decrypted.bin` | Produced (decrypted config blob) | `aad018195c5ee6c2e3c00bc3c95313cb4301218534765472124ebc7b5fb7bcb1` | Not redistributed |
| `output/patched_diff.json` | Produced report | `a5fdfdebfd367cabae0c41fa91846a6f54d585fa0090f86d8db0d4cd84facf4f` | [download]({{ "/downloads/chrysalis/reports/binary_diff/patched_diff.json" | relative_url }}) |
| `output/patched_diff.txt` | Produced report | `b462aa52be01625c72965b3b99c2ef37ccc64e834e4fd9cba624a0e6a6c1f5f7` | [download]({{ "/downloads/chrysalis/reports/binary_diff/patched_diff.txt" | relative_url }}) |

## What You Get At The End

The output set is designed around common reverse-engineering handoff needs: one artifact for static diffing, one for memory-oriented analysis, and one for direct config extraction. This reduces back-and-forth when multiple analysts split tasks across tooling.

By the end of this workflow you will have:
- A dumped stage1 buffer (`shellcode.bin`) and the full stage1 executable region (`shellcode_full.bin`).
- A decrypted “main module”:
  - as a patched container on disk (`main_module_patched.exe`)
  - and optionally as a clean in-memory image (`main_module_mem.bin`)
- A decrypted configuration blob (`config_decrypted.bin`) with the C2 and other fields Rapid7 described.

And importantly:
- A repeatable pipeline that does not rely on “it ran in my debugger”.

## Artifacts

The original bundle structure matters because the entire chain depends on realistic file relationships: the sideload container, the malicious DLL, and the encrypted blob are not independent samples. Preserving that context avoids false assumptions when reproducing loader behavior.

The Rapid7 `update.exe` bundle we worked from contains:
- `log.dll` (malicious sideloaded DLL)
- `BluetoothService.exe` (renamed Bitdefender Submission Wizard used as the sideload container)
- `BluetoothService` (encrypted blob; we store as `encrypted_shellcode.bin`)

Rapid7 hashes (and what we observed locally):
- `log.dll` sha256 `3bdc4c0637591533f1d4198a72a33426c01f69bd2e15ceee547866f65e26b7ad`
- `BluetoothService.exe` sha256 `2da00de67720f5f13b17e9d985fe70f10f153da60c9ab1086fe58f069a156924`
- `BluetoothService` / `encrypted_shellcode.bin` sha256 `77bfea78def679aa1117f569a35e8fd1542df21f7e00e27f192c907e61d63a2e`

## Execution Chain (Condensed)

This is the short operational story behind the unpacking work: sideloaded loader, staged decrypt, reflective execution, then config recovery. We keep it condensed here so each deeper section can map back to a single stage boundary.

1. `BluetoothService.exe` loads `log.dll` via DLL sideloading and calls two exports:
   - `LogInit`: loads the encrypted blob into memory.
   - `LogWrite`: resolves APIs via hashing, decrypts the blob, marks it executable, and jumps to it with a 25-dword argument structure.
2. The decrypted blob (stage1) is not a PE. It is a loader-like shellcode that:
   - Decrypts the next module layer using a simple byte transform with key `"gQ2JR&9;"` over 5 regions.
   - Resolves APIs again and transfers execution to the “main module”.
3. The main module behaves like a reflective PE-like implant (“Chrysalis”), performs CRT init, then executes its main logic.
4. The implant decrypts configuration data stored in the `BluetoothService` blob using RC4.

## Why Emulation (And What Not To Emulate)

The key design choice was to emulate only the part that gives high signal with low instability. Trying to fully emulate hostile stage1 code on a constrained analysis host burns time quickly and produces brittle results, while extracting clean bytes at the handoff boundary gives deterministic progress.

The first stage (`log.dll`) is a good fit for emulation:
- It is normal PE code.
- It calls a predictable set of WinAPI functions (heap + virtual memory).
- We can stub the APIs well enough to reach the “decrypted buffer is ready” breakpoint.

Stage1 execution is much less friendly:
- It uses exception-driven control flow and odd instructions (port I/O, segment ops, `retf`, etc.).
- A naïve emulator tends to crash or spin in anti-emulation loops.

Instead of forcing stage1 to “run” perfectly, we use emulation only to **extract the decrypted bytes** and then apply the remaining transforms offline.

## SEH/VEH And “Debugger Problems” (How We Handled Them)

Early attempts that treated exceptions as regular crashes produced misleading dead ends. Reframing those faults as intentional control-flow mechanics changed the strategy from "make everything execute" to "capture stable state at the right boundary and continue offline."

Stage1’s behavior is consistent with SEH/VEH-driven loaders: code that intentionally faults and expects an exception handler to redirect execution. In a normal Windows debug session, those exceptions become “control flow”. In a basic emulator, they become crashes or infinite loops.

We did **not** implement a full Windows SEH/VEH dispatcher in Unicorn.

What we did instead:
- **Avoided** needing stage1 to execute correctly by dumping its decrypted bytes at the `log.dll` breakpoint and continuing offline.
- Added a few **surgical mitigations** to keep emulation from failing too early during `log.dll`/handoff work:
  - map the NULL page and plant a minimal `MZ`/`PE\\0\\0` structure (prevents common “base==0” PE-header reads from faulting),
  - Capstone-assisted decoding for diagnostics and targeted register fixups in specific patterns,
  - optional “skip lists” for a small set of stage1 junk instructions when experimenting (port I/O, segment ops, etc.).

The key takeaway: we didn’t “beat” VEH by perfectly emulating it; we **sidestepped** it by extracting bytes at stable boundaries and applying the remaining transforms offline.

## Tooling Overview

The toolkit is intentionally split into narrow scripts rather than one opaque monolith. That keeps each stage testable, makes failure modes easier to isolate, and lets analysts replace only the piece they need for a variant sample.

We built a small toolkit:
- `emulate_logwrite_dump_shellcode.py`:
  - Unicorn x86 emulation for the `log.dll!LogWrite` path.
  - Minimal API stubs (`HeapAlloc/Free/ReAlloc/Size`, `VirtualAlloc/Protect`, etc.).
  - Dumps stage1 bytes at the decryption breakpoint.
- `offline_extract_stage2.py`:
  - Applies Rapid7’s `"gQ2JR&9;"` per-byte transform over the 5 regions described by the stage1 argument struct.
  - Can output a patched PE on disk or a reconstructed memory image.
- `decrypt_btservice_config.py`:
  - RC4-decrypts the config at offset `0x30808` size `0x980` with key `qwhvb^435h&*7`.
- `api_hash_rainbow.py` (Windows):
  - Builds a rainbow table for the **loader/log.dll API hashing** described by Rapid7.
  - This is useful when reversing `log.dll` (and similar loader components) because it maps a 32-bit “API hash” back to a likely `(dll, export)` pair.
  - Note: Rapid7 also describes a separate, more complex API hashing routine in the decrypted main module; that would be a different tool/implementation.
- `ida_chrysalis_api_hash_resolver.py`:
  - Standalone IDAPython automation for `log.dll`.
  - Builds a local rainbow from Windows DLL exports, resolves resolver constants, and applies enum symbols/comments so disassembly and decompiler show API names instead of raw hex.
- `ida_main_module_triage.py`:
  - Standalone IDAPython automation for `main_module_patched.exe` / `main_module_mem.bin`.
  - Applies command-tag enum labels (`4T..4d`) and can mark patched ranges from JSON output so analysis focuses on malicious regions first.
- `ida_config_path_mapper.py`:
  - Standalone IDAPython config-path triage for patched/memory module views.
  - Scores likely config-decryption functions using immediate/string markers and can export a CSV report.
- `ida_c2_dispatch_lifter.py`:
  - Standalone IDAPython dispatch extractor for command tags (`4T..4d`).
  - Ranks likely dispatcher functions and exports a handler-reference table (CSV).
- `ida_hash_table_apply.py`:
  - Standalone IDAPython hash annotator that ingests nested rainbow JSON and replaces matching immediate constants with enum/comments at scale.

## Step 1: Unicorn Emulation Of `log.dll!LogWrite`

Step 1 is where we establish controlled execution and collect the first high-value artifact. The objective is not full behavioral emulation; the objective is to stop at a known good point where decrypted stage1 bytes are observable and dumpable.

We map `log.dll` at its expected image base (`0x10000000`) and set a breakpoint at:
- `RVA 0x1C11` (VA `0x10001C11`)

At the breakpoint, `EAX` points to the decrypted stage1 buffer. We dump:
- The “reported” stage1 length (201,096 bytes / `0x31188` in this sample)
- The full 2MB region (`0x200000`) that the malware marks executable via `VirtualProtect`

Outputs:
- `shellcode.bin` (stage1)
- `shellcode_full.bin` (stage1 full region)

Why the full 2MB dump matters:
- The stage1 code references data past the initial “payload length”.
- Later offline extraction becomes easier when we keep the whole protected region.

This decision came from debugging pain: "minimal" dumps looked valid but later failed in secondary transforms because required data tails were missing. Capturing the entire protected region removed that ambiguity.

### What We Validate Here

At this point we want the following to be true:
- Our `input/` hashes match Rapid7 (so we know we are working on the same sample family).
- The emulator hits the breakpoint (`0x10001C11`) and prints `EAX=...` pointing into a mapped buffer.
- `shellcode.bin` length is `0x31188` for the Rapid7 sample.
- `shellcode_full.bin` length is `0x200000`.

If these do not hold, stop and fix stage0 first (bad input file, wrong image base, missing stub, etc.).

## Step 2: Offline Main-Module Decryption (“gQ2JR&9;”)

Step 2 converts a dynamic reversing problem into a deterministic byte transform problem. Once we have stable stage1 outputs and argument metadata, we can reconstruct the next stage without depending on fragile runtime control flow.

Rapid7 provides the bytewise transform:

```c
BYTE k = XORKey[counter & 7];
BYTE x = encrypted[pos];
x = x + k;
x = x ^ k;
x = x - k;
decrypted[pos] = x;
```

They also note the transform is applied 5 times, suggesting 5 PE-like regions.

Two key observations that make offline work reliable:
1. The 25-dword argument structure passed to stage1 includes the region RVAs and sizes.
2. The transform is an involution (apply it twice and you get the original byte back), which means:
   - applying it 5 times is equivalent to applying it once.

In our sample the region list is:
- RVAs: `0x1000, 0x24000, 0x2D000, 0x30000, 0x31000`
- Sizes: `0x23000, 0x8E00, 0xC00, 0x200, 0x1C00`
- Total modified bytes: `0x2E800`

We implement an offline decryptor that can:
- Patch a PE on disk (`BluetoothService.exe`) in-place to produce a “decrypted” container (`main_module_patched.exe`)
- Build a decrypted in-memory image (`main_module_mem.bin`)

Producing both artifacts is intentional: file-backed tools and memory-oriented reversing tools answer different questions, and analysts usually need both views during triage.

Important note about signatures:
- VirusTotal will report the patched PE as “signed” + “invalid signature”.
- That’s expected: the container was signed, and we modified it.

### Why A “Patched PE” Is Still Useful

Even though `main_module_patched.exe` remains the Bitdefender container, it is a practical bridge artifact:
- You can point standard PE tooling at it (imports, entrypoint, sections).
- You can confirm the decrypted regions line up with a PE-like layout.
- You can diff it against the original and confirm that exactly `0x2E800` bytes changed.

For deeper reversing, the cleaner artifact is the reconstructed memory image (`main_module_mem.bin`), because it avoids file-offset vs RVA confusion when the malware expects an in-memory view.

## Step 3: RC4 Config Decryption (Exact Match To Rapid7)

Config extraction is sequenced after module recovery so the offset/size interpretation can be validated against the same staged context. Doing it in this order reduces the risk of treating copied indicators as independently discovered facts.

Rapid7 describes the config location:
- Stored in `BluetoothService` blob
- Offset `0x30808`, size `0x980`
- RC4 key `qwhvb^435h&*7`

We decrypt it offline and confirm plaintext fields match:
- `https://api.skycloudcenter.com/a/chat/s/{GUID}`
- module name `BluetoothService`
- Chrome user-agent string

## Validating The “Main Module” Looks Real

Validation here is about avoiding false positives. A blob can decrypt and still be structurally wrong; checking imports, entrypoint shape, and CRT-like startup behavior gives confidence that we recovered executable logic and not partial noise.

Once the decrypted bytes are in place, the PE behaves like a normal x86 user-mode program:
- PE header is intact
- Import directory is populated (kernel32/user32/advapi32/ole32/wininet/etc)
- The entrypoint resembles MSVC CRT scaffolding

This is consistent with Rapid7’s statement that the module “executes the MSVC CRT initialization sequence” before transferring control to main.

## Loader API Hashing (What `api_hash_rainbow.py` Models)

Hash-resolved imports are one of the biggest readability blockers in loader analysis. This section explains why we modeled the loader hash path directly: replacing opaque immediates with likely API names accelerates every downstream review step.

Rapid7 describes `log.dll` as resolving APIs via a hashing subroutine instead of importing everything by name. At a high level, the loader:
1. Enumerates exports of a target DLL (or a module it has already loaded).
2. Hashes each export name with:
   - **FNV-1a** (seed `0x811C9DC5`, prime `0x01000193`)
   - followed by a **MurmurHash-style avalanche finalizer**
3. Applies a **salted comparison** against a hardcoded target hash.

Why a “rainbow table” helps:
- Once you know a target 32-bit hash value, you can brute-force which common WinAPI export name likely produced it (across `C:\\Windows\\System32\\*.dll`).
- This converts “opaque numbers in disassembly” back into recognizable APIs like `VirtualProtect`, `GetProcAddress`, etc.

Practical caveats:
- The exact salting and name normalization (e.g., case folding) can vary by sample. That’s why `api_hash_rainbow.py` exposes knobs:
  - export-name case (`asis/lower/upper`)
  - salt operation (`xor/add/sub`) and whether it’s applied pre/post finalizer
  - whether the avalanche finalizer is enabled

Main-module hashing is different:
- Rapid7 also describes a second hashing routine used in the decrypted main module that walks the PEB and mixes API names in 4-byte blocks with additional rotations/multiplications.
- That is *not* the same as the loader hash above, and would need a separate implementation to generate an accurate rainbow table for main-module-only hashes.

## IDA Automation That Removed Manual Busywork

Manual annotation works for one function, but it does not scale when the same patterns appear across hundreds of callsites. The IDA scripts were written to remove repetitive analyst effort and preserve consistent naming/comments across re-analysis sessions.

Two practical IDA workflows were automated:

1. Loader hash resolution in `log.dll` (`ida_chrysalis_api_hash_resolver.py`)
- Input:
  - `log.dll` opened in IDA
  - Windows export directories (`C:\\Windows\\SysWOW64;C:\\Windows\\System32`)
  - resolver EA (`0x100014E0` in this sample)
  - seed (`0x114DDB33` in this sample)
- Output:
  - Enum-applied immediate operands at resolver callsites
  - Comments such as:
    - `APIHASH 0x47C204CA -> KERNEL32.dll!VirtualProtect`
- Result:
  - constants in disassembly/decompiler become readable API symbols, which is faster than one-off manual comments.

2. Main-module triage in patched/memory artifacts (`ida_main_module_triage.py`)
- Input:
  - `main_module_patched.exe` or `main_module_mem.bin` opened in IDA
  - optional patched-range JSON from `diff_patched_pe.py`
- Output:
  - command-tag enum labels for the C2 dispatch values (`4T..4d`)
  - optional colored/annotated patched ranges to prioritize likely malicious logic
- Result:
  - faster navigation in large mixed binaries (legit container code + injected/decrypted regions).

3. Config-path mapper (`ida_config_path_mapper.py`)
- Input:
  - patched or memory module in IDA
- Output:
  - comments/highlights for constants and strings tied to config path (`0x980`, `0x30808`, and related xrefs)
  - import-xref hits for config-path APIs (`CreateFileW`, `ReadFile`, `SetFilePointerEx`, etc.)
  - ranked candidate functions and optional CSV export
- Notes:
  - if the first pass returns zero hits (common when IDA marks all segments executable), the script retries on all segments automatically
  - you can provide extra marker DWORDs on prompt (for this family, `0x2C5D0` and `0x116A7` are practical anchors)
- Result:
  - faster handoff from broad triage to concrete RC4/config parsing functions.

4. C2 dispatch lifter (`ida_c2_dispatch_lifter.py`)
- Input:
  - patched or memory module in IDA
- Output:
  - enum/comment applied tag references for `4T..4d`
  - dispatcher candidate ranking by unique tag coverage
  - optional CSV for writeups
- Result:
  - deterministic command-handler mapping instead of manual grep through decompiler output.

5. Bulk hash annotation from JSON (`ida_hash_table_apply.py`)
- Input:
  - nested hash JSON (`DLL -> hash -> export`)
  - IDA database with immediate hash constants
- Output:
  - hash constants converted to readable comments/enums at matched sites
- Result:
  - quick cleanup of “opaque constant” surfaces in both disassembly and pseudocode.

6. LogWrite/decrypt decompiler reconstruction (`ida_rebuild_logwrite.py`)
- Input:
  - `log.dll` in IDA
  - function anchors around `LogWrite` (`0x10001B20`) and `mw_decrypt` (`0x10001640`)
- Output:
  - typed/renamed `LogWrite` pseudocode (`VirtualProtect` pointer + stage1 arg struct)
  - explicit no-arg `mw_decrypt` prototype at callsite
  - helper-function naming + key-block comments inside `mw_decrypt` (seed expansion, 0x20-byte schedule, transform, copy-back)
- Result:
  - decompiler output becomes stable enough to map directly to assembly and to the offline Python implementation.

Decompiler pitfall worth calling out:
- `mw_decrypt` uses a nonstandard prologue/SEH setup and reads caller context from stack internals.
- Hex-Rays may invent a pseudo variable (for example `savedregs_anchor`) and treat it like a normal argument.
- In this sample, assembly shows `call mw_decrypt` with no pushes from `LogWrite`, so the correct function boundary model is `void __cdecl mw_decrypt(void)` for decompilation purposes.

## Troubleshooting (The Stuff That Actually Breaks)

This section exists because most time was spent on edge-case breakage, not on the "happy path." Documenting failure signatures and fixes makes the workflow practical for someone who was not present during initial experimentation.

These are the common failure modes we hit while iterating:

1. Emulation crashes early with reads from `0x0000003C` or other low addresses.
Fix:
- Map the NULL page and place a minimal DOS+PE signature there (so “base==0” reads don’t fault immediately).

2. Breakpoint not reached / control flow returns to `0x41414141`.
Explanation:
- That “fake RET” is a guardrail: the emulator used a sentinel return address so we can stop cleanly when the DLL returns.
Fix:
- Ensure you are running the correct `--mode` (`logwrite`), and that stubs are returning to the correct call sites.

3. Stage1 disassembly looks like nonsense (`in`, `out`, `retf`, `int XX`), or loops forever.
Explanation:
- Stage1 is intentionally hostile to simplistic emulation (exception-driven control flow and junk opcodes).
Fix:
- Don’t brute force stage1 execution. Dump bytes and do the offline transforms instead (this is the core design of this workflow).

4. VirusTotal says the patched PE is “invalid-signature”.
Explanation:
- Authenticode signature verification fails after any byte modifications.
Fix:
- None required; this is expected. Validate via diff-bytes and PE structure instead.

## Assembly Walkthrough (With Explicit Image Requests)

This section is intended for the final published write-up where readers want to see concrete assembly context, not only script output.

The assembly snippets below are chosen as proof points: each one links a reversing claim to a concrete instruction pattern and a corresponding script action. If a reader can verify these anchors, they can trust the surrounding automation.

### A) `log.dll!LogWrite` Handoff Boundary

Representative pattern around the stage1 boundary:

```asm
.text:10001B20 call    mw_decrypt
.text:10001B25 mov     eax, [g_decrypted_buf]
.text:10001B2A push    offset old_protect
.text:10001B2F push    40h
.text:10001B31 push    200000h
.text:10001B36 push    eax
.text:10001B37 call    ds:VirtualProtect
.text:10001B3D ...     ; build 25-dword struct
.text:10001B5E call    eax
```

Why this matters:
- This is the exact boundary where stage0 is still tractable and stage1 begins.
- It justifies extracting bytes at the breakpoint instead of emulating full stage1 behavior.

<!-- IMAGE_REQUEST: IDA screenshot centered on log.dll around 0x10001B20..0x10001C11 showing VirtualProtect + call eax handoff. -->

### B) `mw_decrypt` Byte-Transform Core

Representative byte loop behavior (matching the offline script):

```asm
movzx   ecx, byte ptr [esi+edi]   ; encrypted byte
movzx   eax, byte ptr [key+edi&7]
add     ecx, eax
xor     ecx, eax
sub     ecx, eax
mov     [esi+edi], cl
inc     edi
cmp     edi, region_size
jb      short decrypt_loop
```

Why this matters:
- It ties the reversing claim directly to the implemented transform in `offline_extract_stage2.py`.
- It explains why one correct pass over the 5 regions is sufficient in this sample workflow.

<!-- IMAGE_REQUEST: side-by-side screenshot: IDA assembly of mw_decrypt loop + corresponding Python loop in scripts/offline_extract_stage2.py. -->

### C) Stage1 Arg-Struct Region Mapping

The decryption loop depends on stage1-provided region metadata:

```text
RVA list : 0x1000, 0x24000, 0x2D000, 0x30000, 0x31000
Size list: 0x23000, 0x8E00, 0x0C00, 0x0200, 0x1C00
Total    : 0x2E800 bytes
```

Why this matters:
- It explains why patched bytes are concentrated in specific ranges.
- It connects assembly/runtime state to `patched_diff.json` output.

<!-- IMAGE_REQUEST: screenshot of emulator/log output showing arg-struct values plus a second screenshot of output/patched_diff.txt ranges. -->

### D) RC4 Config Decryption Path Fingerprint

Typical config path markers in the main module:

```asm
push    980h            ; size
push    30808h          ; offset
lea     ecx, [rc4_state]
call    rc4_ksa_prga
```

Why this matters:
- It anchors the static analysis to observable constants (`0x980`, `0x30808`).
- It demonstrates that config extraction was not guessed from strings alone.

<!-- IMAGE_REQUEST: disassembler screenshot at the function referencing 0x980/0x30808, with cross-references visible. -->

### E) Loader API Hash Resolution Callsite

Resolver pattern you want to show in the article:

```asm
push    47C204CAh       ; hash for VirtualProtect in this sample context
call    api_hash_resolver
mov     [ebp+virtualprotect_ptr], eax
```

Why this matters:
- It visually explains why the rainbow table and IDA enum/comment automation add immediate value.
- It helps readers connect opaque constants to concrete API behavior.

<!-- IMAGE_REQUEST: before/after screenshot from ida_chrysalis_api_hash_resolver.py showing raw hash constant vs resolved API annotation. -->

## Screenshots To Capture (For A Technical Report Or Blog)

Good screenshots should prove claims, not decorate the page. The list below is ordered to mirror the analyst journey from sample verification to loader boundary to decrypted outputs and then into IDA triage.

If you want a “Rapid7-like” write-up with visuals, these are the screenshots that add real value:

1. `input/` file listing and SHA-256 hashes matching Rapid7 (terminal).
2. `log.dll` exports showing `LogInit` and `LogWrite` (PE viewer / Ghidra/IDA).
3. Emulator run hitting the breakpoint at `0x10001C11` and printing `EAX=...` plus dumped file hashes (terminal).
4. Hex view of `shellcode.bin` at its dumped base (show it’s raw, non-PE).
5. Offline decrypt step printing region RVAs/sizes and output `main_module_patched.exe` SHA-256 (terminal).
6. A PE header view of `main_module_patched.exe` showing:
   - ImageBase `0x400000`
   - EntryPoint RVA `0x471B0`
   - Import directory present
7. Imports view listing the DLLs Rapid7 mentions (kernel32/user32/advapi32/shlwapi/wininet/etc).
8. Config decrypt output showing the C2 URL and UA string (either strings view or a small hexdump + decoded text).
9. `pe_find.py` output locating the `0x980` constant and mapping to VA (terminal), then a screenshot of that VA in the disassembler to show where you started tracing the config path.
10. `ida_chrysalis_api_hash_resolver.py` output panel showing canary + resolved annotations.
11. `ida_c2_dispatch_lifter.py` output panel showing ranked dispatcher candidates.
12. One patched-range highlighted view from `ida_main_module_triage.py` and one hash-annotation example from `ida_hash_table_apply.py`.

## Flowchart (Pipeline Overview)

The flowchart is useful for onboarding: it gives a one-screen model of where emulation stops, where offline transforms begin, and where reporting artifacts are generated. This is especially helpful when handing work to teammates who only need one stage.

The pipeline diagram is captured in `pipeline_flowchart.dot` and can be rendered to:
- `output/pipeline_flowchart.png`

Render command (requires Graphviz `dot`):
```bash
python3 scripts/render_flowchart.py --out output/pipeline_flowchart.png
```

If `dot` is not installed on macOS, install Graphviz (e.g. via Homebrew) and re-run the command.

## Reproduction Commands

See `README.md` for the exact command lines and expected outputs.

When reproducing, run from a clean workspace and save terminal logs with timestamps. If outputs diverge, compare hashes stage-by-stage rather than jumping directly to final artifacts; this is faster for isolating the first failing boundary.

## What’s Next (If You Want Runtime Behavior)

At this point the workflow has already delivered most high-value static outcomes. The next decision is cost versus fidelity: deeper emulation is slower but self-contained, while VM detonation is higher fidelity but operationally heavier.

At this point you have:
- A decrypted PE-like module you can reverse statically.
- A decrypted config blob you can parse.

If you want to observe C2 protocol behavior safely, you still shouldn’t “run it for real” on your host. Options:
- Continue expanding the Unicorn stubs and emulate deeper (time-consuming).
- Use a Windows VM and detonate in an isolated sandbox (more faithful).
- Use targeted static lifting/decompilation for specific routines (best ROI for this sample family).

For most reverse engineering goals (IOCs, API usage, config extraction, control-flow understanding), the offline artifacts are already enough.

## Closing Notes

The broader lesson is methodological: reliable malware analysis often comes from identifying the smallest dynamic slice needed to recover stable bytes, then doing the rest with explicit offline transforms and verification checkpoints. That tradeoff made this chain tractable on an ARM Mac without sacrificing analytical confidence.

The key idea is to split the problem into two parts:
- Emulate only the loader layer that is stable and WinAPI-like (`log.dll`).
- Treat everything after that as a byte recovery problem (documented transforms + deterministic decrypt), not “make every instruction execute correctly”.
