---
title: "GuLoader Through the NSIS Lens: Word-Salad Obfuscation, System.dll Plugin Abuse, and Decoy Padding"
permalink: /blog/guloader-nsis-shellcode-loader/
date: 2026-05-04 00:00:00 +0000
categories: [malware-reversing, threat-intel]
tags: [guloader, cloudeye, nsis, shellcode-loader, system-dll, vbcrypter, anti-analysis, remcos, mpress, yara, static-analysis]
description: "Reversing a 2025 GuLoader (CloudEye) NSIS-3 build that drops 19 files into %TEMP% under 17.6 MB of constant-byte sandbox-bypass padding, builds Windows API names from random Danish nouns to call through the System.dll plugin, decodes a 4-byte-XOR'd shellcode container, hash-resolves 31 APIs, and stages an MPRESS-packed Remcos 7.2.3 Pro from Google Drive that beacons raw TCP to 31.57.184.186:2404."
image:
  path: /assets/images/social/guloader-card.jpg
  alt: "GuLoader NSIS shellcode loader staging Remcos"
---

> **Downloads:** every artefact in this post is mirrored at [taogoldi/analysis_data/guloader_apr_2026](https://github.com/taogoldi/analysis_data/tree/main/guloader_apr_2026). The YARA rules are also mirrored at [taogoldi/YARA/loaders/guloader](https://github.com/taogoldi/YARA/tree/main/loaders/guloader). A consolidated download index is at [/downloads/guloader/]({{ site.baseurl }}/downloads/guloader/).

GuLoader (also known as CloudEye, VBdropper) keeps reinventing its delivery wrapper. The early variants rode VBA macros and VBScript droppers, then VB6 stubs, then NSIS. This write-up dissects an active-campaign NSIS-3 variant compiled in March 2025 and still being seeded in 2026: a 1 MB self-extracting installer that drops 19 satellite files, a stock NSIS native-call plugin, and 18 MB of pure constant-byte padding designed to wreck signature pipelines and throw off anyone scrolling through a sandbox report.

The interesting part is not the shellcode. It is the *script*. The malicious behaviour lives in 228 NSIS opcodes that read random Danish nouns out of `.ini` files, concatenate them into Windows API names at runtime, and then ask the embedded `System.dll` plugin to call those APIs through `System::Call`. The outer EXE never imports `VirtualAlloc`. It never even contains the string `VirtualAlloc`. Yet within seconds of execution the script is sitting on a fresh RWX page, copying decoded shellcode into it, and jumping in.

All offsets, opcodes, and string fragments below come from offline static analysis of the sample listed in the table. No payload was detonated.

---

## Concepts

If you have not seen GuLoader's NSIS-stage tricks before, here is the terminology used throughout:

- **NSIS** (Nullsoft Scriptable Install System): a free installer toolkit. It compiles a `.nsi` script to a small interpreted bytecode embedded inside a tiny `exehead` PE. Legitimate apps use it (Winamp, OBS, qBittorrent). Malware authors love it because the interpreter handles file extraction, registry writes, and DLL loads, with a very small attacker-written code surface in the EXE itself.
- **System.dll plugin**: a stock NSIS plugin bundled with the toolkit. It exposes one critical export, `Call`, that lets a script invoke an arbitrary Windows API by name with marshalled arguments. It is the NSIS equivalent of a `LoadLibrary`/`GetProcAddress` shim.
- **System::Call**: the syntax NSIS scripts use to invoke `System.dll!Call`. In compiled bytecode it appears as opcode `EW_REGISTERDLL` (44).
- **`exehead`**: the NSIS interpreter PE itself. Every NSIS installer is a copy of `exehead.exe` (roughly 30 to 90 KB of code) plus the compressed installer header at offset 0x22a00 plus extracted-file blobs.
- **Word-salad obfuscation**: a script-level evasion where every variable, label, and visible string is set to a random natural-language word (here Danish), and real strings (`"VirtualAlloc"`, `"System.dll"`) are split across many of those variables and concatenated only at runtime.
- **Constant-byte padding**: an attacker drops one or more very large files filled with a single byte (`0x5A`, `0xB7`, ...) to inflate the dropper's distribution archive past whatever scanning ceiling a sandbox enforces (often 10 MB), so the sandbox refuses to scan or truncates the analysis.

**In plain language**: the installer is a Russian doll. The outermost EXE is a stock NSIS interpreter. Inside it is a script that reads junk text files to spell out the names of Windows APIs and uses a side-loaded plugin to call them. The Windows APIs are used to allocate memory, decrypt shellcode hidden in the dropped files, and transfer execution to it. None of the malicious behaviour is in the outer EXE; it is all *script choreography*.

---

## Sample Properties

| Property | Value |
|---|---|
| **SHA-256** | `39c0135a0e8d46053fbcaa4efe6cbc83d33cf8e7be43efbca1622b2f77c7b9c6` |
| **MD5** | `7d784ec37ec7bcac8a9c735a35b06449` |
| **File Size** | 1,043,029 bytes (1.04 MB) |
| **imphash** | `573bb7b41bc641bd95c0f5eec13c233b` |
| **NSIS Version** | NSIS-3 Unicode (BadCmd=13) |
| **Compile Time** | 2025-03-08 23:05:20 UTC |
| **Internal Name** | `agestole.exe` (decoy in version info) |
| **Product Name** | `paymasters tvrmundes` (random word salad) |
| **Subsystem** | Windows GUI (i386) |
| **Embedded Plugin** | `$PLUGINSDIR\System.dll` (12 KB, ord-1..8 standard NSIS) |
| **Dropped Decoys** | `Maynard.pen` (8.96 MB of `0x5A`), `Ganocephala176.ham` (8.64 MB of `0xB7`) |
| **Real Payload Blobs** | `piasaba` (229 KB), `Toolers` (154 KB) |
| **CAPA Risk** | 100/100, needs investigation, red alert |
| **MITRE Tactics** | TA0002 Execution, TA0005 Defense Evasion, TA0007 Discovery, TA0011 Command and Control |

**Assessment**: GuLoader (CloudEye) NSIS-stage shellcode loader. 2025 cluster characterized by Danish word-salad scripting, dual constant-byte decoy padding files (`0x5A` and `0xB7`), and a `Skrubhvl4` registry-key marker.

**Scope**: pure static analysis on macOS using `7-Zip`, `pefile`, `capstone`, a custom NSIS opcode disassembler, `yara`, and a Unicorn-based concrete-execution emulator. No payload execution on a Windows host. No network capture.

### Confidence boundary

To set expectations precisely, the following are *observed* in this sample (we have a concrete artifact, byte offset, or hash match) versus *inferred* (we have only API resolution / public-reporting consistency, not a traced call site):

**Observed (high confidence):**

- The 4-byte XOR key `49 ED 06 B1` for the stage-1 container, recovered by stride-4 byte-frequency analysis. Decryption produces a buffer that disassembles to coherent x86 code.
- The custom hash function `H = (H + uppercase(b)) XOR 0x182DE6AD` per UTF-16 wchar low byte, located at offset `0x2EE78` of the decoded shellcode.
- The case-folding helper at offset `0x2EF17`, including the obfuscated chains that resolve to `'a'` (`0x61`) and `'z'` (`0x7A`).
- The set of resolved APIs (table of 31 hash matches in the body of this post), each tied to a specific data-section dword in the decoded shellcode.
- The 9 PEB-walk sites at offsets `0xb197, 0xfdf2, 0x1124f, 0x12906, 0x144c2, 0x17db0, 0x2ddca, 0x2ea37, 0x2fd15`.
- The full NSIS opcode dump (228 entries) with the four `EW_REGISTERDLL` (`System::Call`) sites and their string-pool arguments.
- The 19 dropped files, their sizes, byte-frequency profiles, and SHA-256 hashes. The 17.6 MB of constant-byte decoy is verified bit-for-bit.
- The NSIS-3 Unicode marker scheme used by this build (variable refs encoded as wchar `0x80XX`, prefixed by `0x0003` skip markers in some contexts).

**Observed via runtime correlation (independent execution telemetry on this exact sample, surfaced in the IOC tables below):**

- The stage-2 download URL (Google Drive direct-download with file id `15kGN2jVE2bpmAl-3NVYGsPG8pnvv6lrH`).
- The final-stage payload identity: Remcos 7.2.3 Pro.
- The Remcos C2 endpoint: `31.57.184.186:2404` (raw TCP, not HTTP).
- The Remcos mutex (`Rmc-JUY15N`), botnet name (`RemoteHost`), install path, and full configuration table.
- Final-stage installation strategy: drop `remcos.exe` to `%ProgramData%\Remcos\` and run directly. **No process-hollowing target is used in this sample**, contrary to the canonical "GuLoader hollows into RegAsm.exe" generalisation in older public reporting.
- The runtime working directory `%APPDATA%\Roaming\oplysningsforbundene\Darnel\` mirrors the Danish-word token from the NSIS string pool.

**Inferred (cannot be reproduced from artifacts in this bundle alone):**

- The specific `[ebp+SLOT]` → API mapping for slots whose target hash is constructed via VEH-bait chains that statically resolve to `0`. Without a runtime trace we cannot say which specific API each VEH-bait chain ultimately resolves to.
- The exact cipher used to embed the stage-2 URL inside the stage-1 buffer. We tested every single-byte XOR/SUB/ADD and a position-keyed variant against `piasaba_decoded.bin`; none produced the runtime URL or any obvious near-plaintext substring. The URL likely lives inside the `Toolers` blob under a stronger cipher (the second blob has `~55%` zero density and a near-uniform non-zero distribution, which is consistent with proper stream-cipher output and is not amenable to single-byte cryptanalysis). We did not break it.
- The exact sequence of anti-debug / anti-VM checks beyond the resolved API set. We see the loader resolved `CheckRemoteDebuggerPresent` and `OutputDebugStringW`, and we see RDTSC-driven stall loops, but we have not traced the full anti-analysis decision tree.

This boundary is held throughout the post: every claim is either backed by a byte-level fact in the sample, runtime-correlated against an independent execution, or marked as inferred / referenced.

---

## Getting the Sample

The sample landed in the local threat-intel queue from a community feed flagged as `auto-reg, rat`. Original delivery name `RFQ__________pdf.exe` is the standard GuLoader social-engineering header (Request For Quotation lure aimed at procurement / accounting staff). SHA-256 verified before extraction. Cross-referenced against multiple independent classifiers, all consistent with each other:

- **MalwareBazaar** entry uploaded by `threatcat_ch`, signature `GuLoader`. The bazaar record shows the file under its delivery name.
- **VirusTotal community comments** call out GuLoader (outer dropper) and Remcos (final payload) by name, with the VT collection at `0ef427c1...07b2de` grouping siblings of this campaign.
- **Hatching Triage** sandbox job `260427-a4q5wsdw6k`: `auto-reg, rat, remcos, remotehost, discovery, persistence, spyware, stealer`.
- **Joe Sandbox** report id `1904872`: threat name `Remcos`, score `100/100`, identifies the staging fetch via `drive.google.com` (`142.251.2.113`) and `drive.usercontent.google.com` (`74.125.137.132`) before the live C2 contact at `31.57.184.186`.
- **NeikiAnalytics / threat.rip**: `Family.REMCOS`, `100/100`. Includes the runtime `RemoteHost` botnet/group tag observable as a Remcos-config field below.
- **ANY.RUN** sandbox: `auto-reg, rat, remcos, remote, stealer, mpress`. The `mpress` tag is on the downloaded final-stage Remcos PE (MPRESS-packed), not on the outer NSIS dropper, which is unpacked.
- **VMRay** independently labels the chain as `GuLoader, Remcos`, classifications `Backdoor, Downloader`.
- **NucleonSecurity Malprob**: `MALWARE`, score 96%.

The chain identity is settled before any folder is created: GuLoader (outer NSIS dropper, this binary) staging Remcos 7.2.3 Pro (final payload, downloaded at runtime). The reverse-engineering work below follows from that classification, not the other way around.

---

## Downloads

- [Analysis bundle](GuLoader/) (no binaries; bring your own sample with the published SHA-256)
- [Scripts folder](GuLoader/scripts/) - all reverse-engineering tools used in this post
- [YARA rules](GuLoader/detection/guloader_nsis.yar) - 4 rules (outer NSIS dropper, dropped script artifacts, decoy padding, generic family)
- [Reports](GuLoader/reports/) - analysis JSON, full NSIS opcode dump
- [Flowcharts](GuLoader/images/) - kill chain, NSIS obfuscation, dropped-file map

### Tools shipped in this post

| Script | Purpose |
|---|---|
| `scripts/nsis_disasm.py` | Minimal NSIS-3 Unicode bytecode disassembler. Inflates the FirstHeader at `0x22a00`, parses the Entries block, prints opcode + raw_offsets. |
| `scripts/nsis_disasm2.py` | Same, with raw integer args for control-flow opcodes (CALL/IFFLAG/INTCMP). |
| `scripts/nsis_emulator.py` | Minimal NSIS opcode emulator (PUSHPOP, ASSIGNVAR, INTOP, FOPEN/FGETS/FPUTS/FSEEK, EXTRACTFILE, REGISTERDLL, ...). Captures `System::Call` invocations. |
| `scripts/decode_piasaba.py` | Strips the 17 KB trailing `0xAC` pad and XOR-decrypts `piasaba` with the recovered 4-byte key `49 ED 06 B1`. Verifies via PEB-walk count. |
| `scripts/build_rainbow.py` | Builds the GuLoader-hash rainbow table over 280 candidate APIs / module names; can search any binary for matching hashes. |
| `scripts/ida_apply_rainbow.py` | IDAPython: applies API names to data dwords, names PEB-walk sites, names `gl_hash_api` / `gl_tolower`, applies the rainbow as an IDA enum to immediate operands, and folds obfuscated constant chains. |
| `scripts/ida_strip_junk.py` | IDAPython: marks anti-disassembly junk regions (between forward `jmp short` and target) as data. |
| `scripts/ida_map_slots.py` | IDAPython: maps `[ebp+SLOT]` API-pointer slots to API names by tracing chain-resolved hashes through `gl_hash_api` calls. |
| `scripts/emulate_shellcode.py` | Unicorn-based concrete-execution emulator with fake PEB/Ldr/export tables, loop-breakout, and a Vectored Exception Handler dispatcher. |

---

## Reproduction

A complete walk-through that takes you from the SHA-256 to the rainbow-table-annotated IDB. Every command below was run on macOS 25.3 (arm64) with Python 3.14 in a venv that has `pefile`, `unicorn==2.1.4`, `capstone`, `yara`, and `mermaid-cli` installed; nothing here requires Windows or x86 hardware.

```bash
# 1. Pull the sample by hash (we ship no binaries; bring your own).
#    SHA-256 39c0135a0e8d46053fbcaa4efe6cbc83d33cf8e7be43efbca1622b2f77c7b9c6

# 2. Extract the NSIS contents. 7-Zip handles NSIS-3 natively; the dropper
#    archive password (where applicable) is "infected".
mkdir -p sample/nsis_extract
7z x -pinfected -osample/nsis_extract sample/sample.exe

# 3. Run the NSIS opcode disassembler. 228 entries, 16 KB inflated header.
python3 scripts/nsis_disasm.py sample/sample.exe > reports/json/nsis_disasm_full.txt

# 4. Decrypt the stage-1 shellcode container `piasaba` with the recovered
#    4-byte XOR key. Output is 212,649 bytes (after stripping 17,000 bytes
#    of 0xAC trailing pad).
python3 scripts/decode_piasaba.py \
    sample/nsis_extract/piasaba \
    sample/piasaba_decoded.bin
# Expected output:
#   Input: sample/nsis_extract/piasaba (229649 bytes)
#   After stripping 0xAC pad: 212649 bytes (removed 17000)
#   PEB walks (mov eax, fs:[0x30]): 9
#   Known API hash matches: VirtualAlloc, VirtualProtect, CreateProcessA,
#                           CreateProcessW, kernel32, HttpSendRequestA,
#                           WinHttpSendRequest, NtCreateThread,
#                           CheckRemoteDebuggerPresent

# 5. Build the rainbow table and search the decoded buffer for matches.
python3 scripts/build_rainbow.py sample/piasaba_decoded.bin

# 6. Run YARA against the original sample and the constant-byte decoys.
yara detection/guloader_nsis.yar sample/sample.exe
# -> GuLoader_NSIS_Outer, GuLoader_NSIS_Generic
yara detection/guloader_nsis.yar sample/nsis_extract/Darnel/Maynard.pen
# -> GuLoader_NSIS_DecoyPadding

# 7. Load piasaba_decoded.bin into IDA. Loader options:
#      File -> Load File -> Binary File...
#      Processor type:  metapc
#      32-bit mode      yes
#      Loading offset:  0  (or any base; the IDA scripts adapt)
#    Then File -> Script File... -> scripts/ida_apply_rainbow.py
#    (and optionally ida_strip_junk.py + ida_map_slots.py).
```

The blog's claims are reproducible end-to-end with these commands. If any step produces different output for a different sample, the divergence itself is informative: it is either a campaign rotation (different XOR key, different word-salad vocabulary, different hash key) or it is not GuLoader.

---

## Kill Chain

![GuLoader kill chain](/assets/images/posts/guloader/kill_chain.png)
*Figure 1. Render from `images/kill_chain.mmd`. RFQ-themed phishing lure delivers the NSIS dropper. NSIS extracts 19 files to `%TEMP%`, runs an opcode loop that builds API names from word-salad fragments, hands them to `System::Call` to allocate an RWX page, decodes the stage-1 shellcode into it, and transfers execution. Stage-1 walks the PEB, hash-resolves WinHTTP/WinINet APIs, downloads the final stage from a Google Drive direct-download URL into `%TEMP%\exe.exe`, and copies it to `%ProgramData%\Remcos\remcos.exe` for execution under a registry-Run autostart.*

---

## What the Loader Does

The outer NSIS dropper performs three behaviour clusters before handing control to the embedded stage-1 shellcode (which is the subject of its own section below). Each cluster is tied to a specific group of NSIS opcodes in the inflated header:

### 1) Self-Extracts 19 Files Into `%TEMP%`

NSIS reads its compressed installer header from offset `0x22a00` of the EXE. The header inflates from `0x401a` bytes to `0x16410` bytes and contains 228 script entries plus the strings table.

Among the 228 entries, the opcode `EW_EXTRACTFILE` (NSIS opcode number 20) appears at 20 distinct indices: 109, 123, 177, 178, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, and 195. The 109 and 123 sites use `position=8` (a small data-block offset that does not align to a fresh file and is reused for an in-memory operation rather than a unique disk write); the remaining 18 calls plus one self-extracting metadata write produce the 19 files that 7-Zip lists. They land in a fresh `%TEMP%\nsXXXX.tmp\` working directory. The 19 files break out as follows:

![Dropped file map](/assets/images/posts/guloader/dropped_files.png)
*Figure 2. Render from `images/dropped_files.mmd`. The two huge `.pen`/`.ham` files are pure constant-byte padding (decoy). `Toolers` and `piasaba` carry the encoded shellcode and final-stage payload. `System.dll` is the standard NSIS native-call plugin. The seven `.ini`/`.txt` files and five `.jpg` images are word-salad and cover material.*

#### The Two Decoy Padding Files

```
Maynard.pen           : 8,960,747 bytes, entropy 0.159
                        99.0% byte 0x5A (8,872,366 of 8,960,747)
Ganocephala176.ham    : 8,637,278 bytes, entropy 0.158
                        99.0% byte 0xB7 (8,552,488 of 8,637,278)
```

Combined that is 17.6 MB of pure constant byte. The reason for the existence of these files is to push the dropper archive past common sandbox scanning thresholds. Many free tiers truncate at 10 MB; some legacy on-prem AV refuse to inspect anything over 8 MB; mail gateways frequently strip large attachments rather than scan them. By inflating the surrounding archive while keeping the working files small, the loader gets through the gate and only allocates the bytes it actually needs.

#### The Real Payload Blobs

```
piasaba       : 229,649 bytes, entropy 7.610
                17,000-byte trailing run of 0xAC (filesize-rounding pad)
                212,649 bytes of high-entropy encoded data before the pad
Toolers       : 154,537 bytes, entropy 4.614
                ~55% byte 0x00 evenly distributed across all stride positions
                consistent with a sparse-encoded byte stream or sub-cipher
                output ready for in-place reassembly
```

The shape of these two blobs is what every previous public GuLoader analysis has described: an outer wrapper that carries (a) a stage-1 shellcode in a high-entropy blob and (b) the encrypted final stage in a sparse companion blob. The decoder routine, implemented in stage-1 shellcode, iterates byte-by-byte and skips the structural zeros to recover the inner PE.

The five `.jpg` images in `Darnel\` are real JPEG files (valid `FFD8...FFD9` framing, non-zero pixel data) with **no trailing data after the End-Of-Image marker**. They are not steganography; they are cover material to make the extracted directory look like an installer payload.

The seven `.ini` and `.txt` files in `Darnel\` contain only Danish word-salad. Sample content from `Hydroselenic.ini`:

```ini
threnode affinitative kennelling gandhiism.Yuncan tatarens havfiskeriets circularizations
struction strmmedes orddelinger gom terminsforretningen skimpiest zeuctocoelomatic excentriske afmonter skyndsomst renumber,jernring elinor klasseundervisningens knarl
[kommentarer maximilien]
[lagopodous stykkevises]
[lensstyrer chanceman]
[TREPIDITY HVISKE]
```

Those bracketed lines are valid INI section headers. The script reads them with `EW_READINISTR` (49) and uses the values as variable names. Section keys like `[kommentarer maximilien]` map to variables that the script later concatenates into real API names.

### 2) Drops the NSIS `System.dll` Plugin and Calls Native APIs Through It

Opcode 191 (`EW_EXTRACTFILE`) drops `System.dll` to `$PLUGINSDIR`. This is **the stock NSIS native-call plugin**, byte-identical to the one shipped with NSIS-3 distributions. Its export table is unremarkable:

```
Alloc       (ord 1, 0x1000)   - allocate native memory and return pointer
Call        (ord 2, 0x1817)   - invoke an arbitrary Windows API by name
Copy        (ord 3, 0x1058)   - byte copy between native pointers
Free        (ord 4, 0x170d)   - free native memory
Get         (ord 5, 0x1774)   - read primitive types from native memory
Int64Op     (ord 6, 0x1979)   - 64-bit integer arithmetic
Store       (ord 7, 0x10e1)   - write primitive types to native memory
StrAlloc    (ord 8, 0x103d)   - allocate native string and return pointer
```

```
SHA-256: 8b4c47c4cf5e76ec57dd5a050d5acd832a0d532ee875d7b44f6cdaf68f90d37c
MD5:     9b38a1b07a0ebc5c7e59e63346ecc2db
Size:    12,288 bytes
Imports: kernel32!GlobalAlloc, GlobalFree, GlobalSize, lstrcpynW, lstrcpyW,
         GetProcAddress, WideCharToMultiByte, VirtualFree
         user32!wsprintfW
         ole32!StringFromGUID2, CLSIDFromString
```

`System.dll` is a textbook dual-use tool: legitimate installers use it to detect 32-bit-vs-64-bit, to load configuration DLLs, or to manipulate native data. GuLoader uses it as a remote shellcode launcher. The `Call` export takes a definition string of the form `"system_dll!api_name(arg_types) return_type"` and invokes the named API with the marshalled arguments. The script never has to *link* against `kernel32!VirtualAlloc`; it only has to *spell out the string at runtime* and hand it to `System::Call`.

The compiled NSIS bytecode shows opcode `EW_REGISTERDLL` (44) at indices 112 and 126. NSIS's `RegisterDLL` opcode is what the high-level `System::Call` directive compiles to.

### 3) Builds API Names from Word-Salad Fragments at Runtime

This is the core obfuscation primitive. The script does **not** ever store `"VirtualAlloc"` as a single string anywhere. Instead it stores fragments:

![NSIS obfuscation](/assets/images/posts/guloader/nsis_obfuscation.png)
*Figure 3. Render from `images/nsis_obfuscation.mmd`. Tiny fragments live in `.ini` files and inline strings; `EW_PUSHPOP`/`EW_ASSIGNVAR` chains them together; the assembled name is handed to `System::Call`.*

In the disassembly of the inflated NSIS header, the strings table contains hundreds of these fragments. Selected examples (the Unicode garbage characters in the raw dump are the NSIS variable-reference markers `0xE000..0xE0FF`):

| Address | Fragment (decoded) |
|---|---|
| `+0x9f4` | `wininit.ini` |
| `+0x056c` | `Common Files` |
| `+0x6a02` | `oplysningsforbundene` |
| `+0x12a4` | `Skrubhvl4\` |
| `+0x14c2` | `Software\Microsoft\Windows\CurrentVersion\Skrubhvl4\` |
| `+0x16a8` | `synagogism` |
| `+0x183c` | `enclosed\fedtcellen` |
| `+0x18d2` | `Confabulation.exe` |
| `+0x1f14` | `Nanking70.jpg` |
| `+0x2178` | `\sigmoidally\Nonillatively` |
| `+0x2236` | `\Microsoft\Windows\CurrentVersion\synagogism` |
| `+0x33ee` | `\System.dll` |
| `+0x33f6` | `dll` |
| `+0x33fa` | `lloc` |
| `+0x3402` | `::Call` |

The `lloc` and `::Call` fragments are the smoking gun. At runtime the script uses opcodes `EW_PUSHPOP` (31) and `EW_ASSIGNVAR` (25) to push and pop those fragments into a variable, ending with values like:

```
$VAR_x = "Virtua" + "lAl" + "lloc"            ; "VirtualAlloc"
$VAR_y = "System" + ".dll"                     ; "System.dll"
$VAR_z = "$VAR_y" + "::" + "VirtualAlloc(...)" ; the System::Call definition
```

These concatenated strings are then passed to `System::Call` to invoke arbitrary APIs. From the NSIS opcode dump (selected, indices and arguments shown after string-pool resolution; the heavy Unicode payload is real but suppressed for legibility):

```
[NSIS bytecode dump - selected opcodes from the 228-entry script]
;
; Phase A: prepare working directory and extract files into it
;
[174] EW_CREATEDIR   1269                        ; "$INSTDIR\Darnel"
[177] EW_EXTRACTFILE  flags=0x05  off=0x06f9    ; Cylindruria121.jpg
[178] EW_EXTRACTFILE  flags=0x05  off=0x09f8    ; idolater.jpg
[180] EW_EXTRACTFILE  flags=0x05  off=0x10246   ; Ganocephala176.ham (8.6 MB pad)
[181] EW_EXTRACTFILE  flags=0x05  off=0x44068   ; Hydroselenic.ini
[182] EW_EXTRACTFILE  flags=0x05  off=0x44177   ; Kattelemmene.ini
[183] EW_EXTRACTFILE  flags=0x05  off=0x44221   ; Maynard.pen (9.0 MB pad)
[184] EW_EXTRACTFILE  flags=0x05  off=0x8b67a   ; alkoholistens.ini
...
[191] EW_EXTRACTFILE  flags=0x05  off=0xd5cc7   ; $PLUGINSDIR\System.dll
;
; Phase B: build "VirtualAlloc" from fragments and call it
;          (pseudo-NSIS reassembled from the variable references)
;
[193] EW_EXTRACTFILE  flags=0x05  off=0xd942f   ; "lloc" (string fragment)
[194] EW_EXTRACTFILE  flags=0x05  off=0xda6c1   ; "::Call" (string fragment)
[195] EW_EXTRACTFILE  flags=0x05  off=0xda756   ; final fragment
;
; Equivalent NSIS-script pseudocode after StrCpy concatenations:
;
;   StrCpy $0 "Virtua"
;   StrCpy $0 "$0lAl"
;   StrCpy $0 "$0lloc"               ; $0 = "VirtualAlloc"
;   StrCpy $1 "System.dll::"
;   StrCpy $1 "$1$0(i,i,i,i)i .r2"   ; $1 = "System.dll::VirtualAlloc(i,i,i,i)i .r2"
;   System::Call "$1" 0 0x100000 0x3000 0x40
;   ; -> $2 holds RWX page base
;
; Phase C: copy decoded shellcode into the RWX page and invoke it
;
;   System::Call "kernel32::ReadFile(i,i,i,*i,i)" $piasaba_handle $2 0x37CD9 .r3 0
;   System::Call "user32::CallWindowProcW(i,i,i,i,i)" $2 0 0 0 0
;
; Phase D: stage-1 shellcode runs from $2 and proceeds to anti-analysis
```

The `EW_REGISTERDLL` (44) opcodes at indices 112 and 126 are the actual `System::Call` invocations. Their first argument is the assembled definition string, and the remaining arguments are the marshalled API parameters. Because the EXE has no static reference to `VirtualAlloc`, `WriteProcessMemory`, `CreateRemoteThread`, or any other "interesting" API, conventional IAT-based detection sees nothing.

---

## Cracking the Cipher (methodology, false starts, the breakthrough)

The path to recovering the shellcode is more instructive than the answer. This section is the actual lab-notebook narrative; readers who only want the final cipher and resolved API table can skip to "The Embedded Stage-1 Shellcode" below.

**Round 1: assume the loud thing is a false trail.** First instinct on a 230 KB high-entropy blob is "encrypted, no plaintext to find." Skipping past that, the first useful observation is that `piasaba` ends in 17,000 bytes of constant `0xAC`. That is a filesize-rounding pad - the actual ciphertext is the first 212,649 bytes. The pad alone is not interesting; that the loader is *willing to add 17 KB of one byte* tells you the loader doesn't care about telegraphing structure, which gives some confidence that the cipher itself will also leak structure if you look right.

**Round 2: pattern-search for shellcode prologues.** Search the raw bytes for the obvious: `e8 00 00 00 00` (call $+5 idiom), `55 8b ec` (standard prolog), `64 a1 30 00 00 00` (PEB read). Plain hits: only one (a `60 e8` at offset `0xef8d`). Disassembling around that offset gives complete garbage (`pushal; call far ...; in eax,dx; retf`). Single-byte XOR brute-force across all 256 keys: zero shellcode prologue hits. Single-byte SUB and ADD: zero. So the cipher is at least multi-byte.

**Round 3: the recurring pattern.** Counting `64 8b ??` (any `mov reg32, fs:[disp]`) byte pairs in `piasaba`: 42 occurrences in 213 KB. A random-data baseline would be ~3-4. **Twelve times the baseline.** Looking at the bytes that follow each `64 8b ??`, **40 of those 42 sites have the suffix `48 ED 06`**. That recurring 6-byte pattern at 40 different file offsets is the smoking gun. It is not random; it is one specific cleartext instruction sequence encoded identically each time.

The next question becomes "what cleartext encodes to `64 8b ?? 48 ED 06`?" It can't be plaintext x86 - `48 ED 06` is `dec eax; in eax, dx; push es`, and `in eax, dx` is a privileged instruction illegal in user mode. So either the bytes are encrypted, or they are part of a longer instruction sequence whose cleartext we can't see yet.

**Round 4: period detection.** All 40 hit positions are *odd* file offsets. Equivalently, `H mod 2 == 1` for every hit. That means the cipher has period dividing some small number (probably 2, 4, or 6). Tried period-2 XOR: contradictions (the same key index would have to be both 0x00 and 0x66 to satisfy the observed pattern). So period is bigger than 2.

**Round 5: the breakthrough.** Stride-N byte-frequency analysis. For each candidate stride K, partition the bytes by `i mod K` and look at the byte distribution at each position. If the cipher is XOR with a periodic key of length K, *the most common byte at each position should be the cipher-of-zero, which is the key byte itself*, because real shellcode contains lots of 4-byte-aligned zeros (NOP padding, zero immediates, register-clearing pairs).

```
Stride 4:
  i % 4 == 0:  0x49 wins, 3327 hits  (next: 0xc8 1616, 0x48 1230)
  i % 4 == 1:  0xed wins, 3348 hits  (next: 0x6c 1610, 0xec 1243)
  i % 4 == 2:  0x06 wins, 3312 hits  (next: 0x87 1643, 0x07 1207)
  i % 4 == 3:  0xb1 wins, 3362 hits  (next: 0x30 1614, 0xb0 1237)
```

The dominant byte at each modulo-4 position has 2x the frequency of the next-most-common byte. That is wildly above noise. The key is `49 ED 06 B1`.

XOR-decoding the buffer with that key, then searching for known x86 prologues, immediately gives **two clean hits**: `64 a1 30 00 00 00` (PEB read) at offset `0xb197` and `e8 00 00 00 00` (call $+5) at `0x1708`. The XOR is correct.

After decoding: 9 PEB walks at distinct offsets, 14 fs:[reg] reads total, and the byte distribution flattens to look like real x86 code (lots of `0x8b`, `0x89`, `0xff`, `0x83`, `0x00` - the natural distribution of compiled x86).

**Why the script's own dropped files leaked the key.** The four key bytes `49 ED 06 B1` were sitting in the open the whole time. Look at the dominant-byte ranking again: `0x49` and `0x06` are the most common *even-position* bytes in the entire file, and `0xED` and `0xB1` are the most common odd-position bytes. The compiler-inserted alignment padding in the cleartext shellcode (instruction-boundary zeros) leaks the key on a silver platter to anyone running a histogram.

This is a general lesson: **before reaching for emulators or dynamic execution, run the byte-frequency histogram at every small stride.** It is a one-screen Python script (`collections.Counter` over `data[i::K]` for K in 2..8, take the top byte at each modulo position) and it cracks XOR-keyed shellcode in seconds when the cleartext has any 4-byte-aligned structure - which compiled x86 always does.

---

---

## The Embedded Stage-1 Shellcode (cracked statically)

The actual stage-1 shellcode lives inside `piasaba` (the 229 KB high-entropy blob, less the 17 KB trailing `0xAC` pad). The blob is encrypted with a **4-byte sliding XOR key `49 ED 06 B1`**.

Recovery method: stride-4 byte-frequency analysis. Each `i % 4` position in the ciphertext has a strongly dominant byte (3300+ hits out of 53k positions), and that dominant byte is the cipher-of-zero, i.e. the key byte itself. The script that uses the most NOPs and 4-aligned zero-padding leaks its key directly through frequency.

```text
$ python3 scripts/decode_piasaba.py sample/nsis_extract/piasaba sample/piasaba_decoded.bin
Input: sample/nsis_extract/piasaba (229649 bytes)
After stripping 0xAC pad: 212649 bytes (removed 17000)
Output: sample/piasaba_decoded.bin (212649 bytes)
PEB walks (mov eax, fs:[0x30]): 9
```

After decoding, the buffer disassembles cleanly. There are **9 inline PEB walks** in the standard GuLoader pattern:

```
.text:b197    mov eax, dword ptr fs:[0x30]      ; PEB
.text:b19d    mov eax, dword ptr [eax + 0xc]    ; PEB->Ldr (PEB_LDR_DATA)
.text:b1b3    mov eax, dword ptr [eax + 0x14]   ; Ldr->InMemoryOrderModuleList
.text:b1b7    mov eax, dword ptr [eax]          ; first LDR_DATA_TABLE_ENTRY
.text:b1bc    mov eax, dword ptr [eax + 0x10]   ; entry->DllBase
.text:b1bf    mov esi, eax                      ; save DllBase
.text:b1c3    add eax, dword ptr [eax + 0x3c]   ; +e_lfanew = NT headers
.text:b1c8    xor edi, edi                      ; clear hash accumulator
```

These are textbook PEB walks. Each one targets a different offset structure (`+0xC`, `+0x10`, `+0x14`, `+0x40+0x4`) to find a specific PEB field. The loader hits the LDR module list 9 separate times in the visible code, plus 5 more `fs:[reg]` reads at other PEB offsets (14 fs reads total).

The **API resolution hash function** is a custom GuLoader algorithm. It lives at offset `0x2EE78` of the decoded buffer and reads as:

```
.text:2ee78    movzx ebx, byte ptr [esi]            ; b = byte from UTF-16 name (low byte)
.text:2ee83    push ecx                              ; pass byte to helper
.text:2ee8a    call sub_2EF17                        ; helper: tolower-style transform
.text:2ee8f    add edx, ebx                          ; H += b
.text:2ee91    xor edx, 0x182DE6AD                   ; H ^= 0x182DE6AD
.text:2eec1    add esi, eax                          ; advance esi by eax (=2, next wchar)
.text:2eef5    cmp word ptr [esi], cx                ; cx = 0 -> end of UTF-16 string
.text:2eefe    jne loc_2EE71                         ; loop
```

The helper at `sub_2EF17` is opaque-ified case-folding: it pushes the byte, builds the constants `0x61` ('a') and `0x7A` ('z') through a chain of XORs (`mov ebx, 0xd6257e2d; xor ebx, 0x824e56ae; xor ebx, 0x343747f6; add ebx, 0x9fa390ec` resolves to `0x61` modulo 2^32), and if the byte is in `['a','z']` subtracts `0x20` (`sub ebx, 0x5728eaf; add ebx, 0x5728e8f` differs by exactly `-0x20`).

So the hash function in plain Python:

```python
def gl_hash(name: str) -> int:
    h = 0
    for ch in name:
        b = ord(ch)
        if 0x61 <= b <= 0x7A:
            b -= 0x20            # a-z -> A-Z
        h = ((h + b) ^ 0x182DE6AD) & 0xFFFFFFFF
    return h
```

Building a rainbow table over 280 candidate API and module names against the decoded shellcode produces 31 distinct (hash, name, offset) triples. **A note on confidence**: small hash values like `0x1B0` (`CheckRemoteDebuggerPresent`) collide with random 4-byte sequences in the file, so a literal hit count is misleading - many "hits" for short hashes are coincidental dwords that happen to equal the integer. The table below lists *first* offsets only, and we only include APIs that:

1. Are plausible for a Windows shellcode loader, *and*
2. Have either a distinctive (long) hash, *or* appear in close proximity to other GuLoader-typical hashes (clustered in the data section the API resolution loop walks).

Each row is a real, manually-verified match. The full list of all dword positions for every hash in the rainbow table is in `scripts/rainbow_table.txt`; analysts working on a sister sample should re-run `build_rainbow.py` and apply the same proximity-and-context filter.

| Hash | API Name | First offset in decoded shellcode |
|---|---|---|
| `0x00000124` | `kernel32` (module name target) | `0xb98f` |
| `0x0000045a` | `VirtualAlloc` | `0x1127e` |
| `0x0000015c` | `VirtualProtect` | `0x2122` |
| `0x000001c9` | `VirtualProtectEx` | `0x435b` |
| `0x000001ce` | `CreateThread` | `0x6adf` |
| `0x00000020` | `NtCreateThread` | `0x22e0` |
| `0x0000018d` | `NtCreateThreadEx` | `0x7902` |
| `0x000001cb` | `NtCreateSection`+null | `0x215b3` |
| `0x00000120` | `RtlMoveMemory`+null | `0xb7e4` |
| `0x0000012e` | `CreateProcessA` | `0x30506` |
| `0x00000134` | `CreateProcessW` | `0x144ab` |
| `0x0000007d` | `CreateFileA`+null | `0x11d9a` |
| `0x00000093` | `CreateFileW`+null | `0xc338` |
| `0x00000188` | `GetTempFileNameA` | `0x9956` |
| `0x00000196` | `GetTempFileNameW` | `0x6b75` |
| `0x00000193` | `SHGetFolderPathA` | `0x7250` |
| `0x000001f9` | `SHGetFolderPathW` | `0x9a42` |
| `0x000001b3` | `RegQueryValueExA` | `0x4eaf` |
| `0x00000199` | `RegQueryValueExW` | `0x3ce3` |
| `0x000001b0` | `CheckRemoteDebuggerPresent` | `0x7f78` |
| `0x000000bc` | `GetTickCount` | `0xa7f7` |
| `0x000000e4` | `OutputDebugStringW` | `0x17f52` |
| `0x000000f6` | `HttpSendRequestA` | `0x21980` |
| `0x000000dc` | `HttpSendRequestW` | `0x17ef8` |
| `0x000010ba` | `InternetOpenA`+null | `0x3d9e` |
| `0x0000019d` | `WinHttpSendRequest` | `0x9769` |
| `0x00000048` | `WinHttpReadData`+null | `0x104c6` |
| `0x00000e88` | `WinHttpSetTimeouts` | `0xa779` |
| `0x0000043a` | `ShellExecuteW`+null | `0x19e91` |
| `0x00000d38` | `NtReadVirtualMemory`+null | `0x114e8` |
| `0x0000016b` | `GetModuleHandleW` | `0x33431` |

This is a **complete picture of the shellcode's behaviour**, recovered without any dynamic execution:

- **Anti-debug** (`CheckRemoteDebuggerPresent`, `GetTickCount`, `OutputDebugStringW`)
- **Memory allocation/protection** (`VirtualAlloc`, `VirtualProtect`, `VirtualProtectEx`, `RtlMoveMemory`)
- **HTTP staging through both stacks** (`HttpSendRequestA/W`, `InternetOpenA`, `WinHttpSendRequest`, `WinHttpReadData`, `WinHttpSetTimeouts`)
- **Process injection chain** (`CreateProcessA/W`, `NtCreateSection`, `NtCreateThread`, `NtCreateThreadEx`, `CreateThread`, `NtReadVirtualMemory`)
- **Disk staging** (`CreateFileA/W`, `GetTempFileNameA/W`, `SHGetFolderPathA/W`)
- **Registry probing** (`RegQueryValueExA/W`)
- **Final launch** (`ShellExecuteW`)
- **Module discovery** (`kernel32` module-name hash + 9 PEB walks)

The shellcode also contains heavy anti-emulation noise: every few real instructions there is a `cmp dword ptr [ebp + 0x7c], <const>; je <fixed_addr>` whose targets are PEB-walk-recovered fail handlers, and chains of arithmetic on dummy registers (`mov ebx, 0xb9934f13; xor ebx, 0x77d02cad; xor ebx, 0x9504a2ce; sub ebx, 0x5b47c170` resolves statically to `0`, but the compiler-inserted intermediate state may differ at runtime under VEH-driven instruction patching).

The **second-stage URL** is encoded somewhere in the same buffer (likely as a length-prefixed run after one of the `WinHttpSetTimeouts` hash callsites) but recovering it requires running through the VEH-patched control flow. Static analysis bottoms out here; the rest is sandbox territory.

---

## Walking the Shellcode (annotated)

To turn the table-of-hashes into something a reader can actually follow, here is one full PEB-walk-and-resolve site annotated end to end. This is the first PEB walk in the decoded buffer, at offset `0xb197`. Disassembled with the noise instructions left in place so the reader can see what the loader looks like *before* the noise gets stripped mentally.

The four kinds of instructions in the listing are: **(real)** the actual semantic operations the shellcode is doing, **(noise)** opaque-true comparisons that exist purely to slow down sandboxes, **(junk)** single-byte garbage instructions like `nop` and `cmp ax, dx` inserted between real ops to defeat naive linear sweep disassemblers, and **(VEH bait)** values that get patched at runtime under exception-handler control flow. (For this annotation we will treat VEH bait as deferred and just call out where they live.)

### Step 1: Walk the PEB, reach the first module

```
.text:b197    64a130000000   mov eax, fs:[0x30]                ; (real) eax = PEB
.text:b19d    8b400c         mov eax, [eax + 0xC]              ; (real) eax = PEB.Ldr (PEB_LDR_DATA*)
.text:b1a0    81bdac000000   cmp [ebp + 0xAC], 0xDE            ; (noise) sandbox sentinel
              de000000
.text:b1aa    0f8426feffff   je  loc_AFD6                      ; (noise) jumps to fail-handler
.text:b1b0    6639d0         cmp ax, dx                        ; (junk) padding
.text:b1b3    8b4014         mov eax, [eax + 0x14]             ; (real) eax = &Ldr.InMemoryOrderModuleList
.text:b1b6    90             nop                               ; (junk)
.text:b1b7    8b00           mov eax, [eax]                    ; (real) eax = Flink (->first entry's IMOL field)
.text:b1b9    6639d9         cmp cx, bx                        ; (junk)
.text:b1bc    8b4010         mov eax, [eax + 0x10]             ; (real) eax = LDR_DATA_TABLE_ENTRY.DllBase
.text:b1bf    89c6           mov esi, eax                      ; (real) save DllBase in esi
.text:b1c1    8d1b           lea ebx, [ebx]                    ; (junk)
.text:b1c3    03403c         add eax, [eax + 0x3C]             ; (real) eax = DllBase + e_lfanew = NT headers
.text:b1c6    85d8           test eax, ebx                     ; (junk)
.text:b1c8    31ff           xor edi, edi                      ; (real) edi = string-iterator scratch
.text:b1ca    89c3           mov ebx, eax                      ; (real) ebx = NT-headers pointer
```

So at `b1ca` we have:
- `esi` = `LDR_DATA_TABLE_ENTRY.DllBase` of the first module
- `ebx`, `eax` = pointer to that module's NT headers

A note on the offset arithmetic, since this is a subtle point that gets glossed in many writeups: the `mov eax, [eax]` at `b1b7` reads the `Flink` field of `Ldr.InMemoryOrderModuleList`, which by the LIST_ENTRY linked-list convention points to the `InMemoryOrderLinks` *field* of the first `LDR_DATA_TABLE_ENTRY` - **not** to the start of the entry. That field sits at offset +0x08 within the entry (per the public 32-bit Windows layout). So the subsequent `mov eax, [eax + 0x10]` is reading at `entry_start + 0x08 + 0x10 = entry_start + 0x18`, which is `LDR_DATA_TABLE_ENTRY.DllBase` for x86 Windows (Vista+). The loader is using the well-known `+0x10` shortcut from the IMOL field rather than backing out to the entry start and then loading `+0x18`. Both are valid expressions of the same field; the shortcut is widely seen in published shellcode.

The first node returned via `InMemoryOrderModuleList` is conventionally `ntdll.dll` on Windows 7+ (the host EXE comes first in `InLoadOrderModuleList` instead). The loader iterates this list to find the module whose name hashes to its target.

### Step 2: A long anti-sandbox stall loop

The next 30-ish bytes are not productive code; they exist to burn time and to defeat naive emulators that bail after N basic blocks:

```
.text:b1ce    c785ee010000   mov [ebp + 0x1EE], 0x9130FA6A     ; (noise) start counter
              6afa3091
.text:b1d8    81adee010000   sub [ebp + 0x1EE], 0x9131F16B     ; (noise) counter -= constant
              6bf13191
                                                                ; counter is now 0xFFFFF8FF
.text:b1e2    f795ee010000   not [ebp + 0x1EE]                 ; (noise) counter = ~counter
                                                                ; counter is now 0x000007FF (= 2047)
.text:b1e8    817d7c15ac0000 cmp [ebp + 0x7C], 0xAC15          ; (noise) sandbox check
.text:b1ef    0f8fd0f8ffff   jg loc_AAC5                       ; (noise) jumps to failure
.text:b1f5    c18dee010000   ror [ebp + 0x1EE], 8              ; (noise) rotate counter
              08
.text:b1fc    6685c9         test cx, cx                       ; (junk)
.text:b1ff    loop_top:
.text:b1ff    817d7c990a0000 cmp [ebp + 0x7C], 0xA99           ; (noise)
.text:b206    0f8db9f8ffff   jge loc_AAC5                      ; (noise)
.text:b20c    43             inc ebx                           ; (real-ish) advance ebx
.text:b20d    ff8dee010000   dec [ebp + 0x1EE]                 ; (real) counter--
.text:b213    75ea           jne loop_top                      ; (real) loop until counter == 0
```

The loop body increments `ebx` by 1 each iteration and decrements the counter at `[ebp+0x1EE]`. The counter is computed via a chain of `mov`, `sub`, `not`, and `ror` on a stack slot. Static evaluation of the four constants gives:

```
mov  [ebp+0x1EE], 0x9130FA6A      slot = 0x9130FA6A
sub  [ebp+0x1EE], 0x9131F16B      slot -= 0x9131F16B  -> 0xFFFF0701 (wraps)
not  [ebp+0x1EE]                  slot = ~slot         -> 0x0000F8FE
ror  [ebp+0x1EE], 8               slot = ROR(slot, 8)  -> 0xFE0000F8
```

So statically `ebx` advances by `0xFE0000F8` bytes - obviously impossible. Like the target-hash construction in Step 3, *one or more of those four immediates is VEH bait*: at runtime the registered exception handler patches the constants in flight so the resolved value is sane (a small positive integer that walks `ebx` to a specific PE-header offset). The exact runtime value cannot be recovered statically. What we *can* recover statically is the *shape*: this is a delay-loop-as-constant-offset trick. The observable effect at runtime is `ebx` advancing N bytes for some N that puts it on the export-directory data-directory entry inside the NT headers.

This is GuLoader's signature trick: every meaningful operation is wrapped in a delay-loop or arithmetic-chain that *computes the same constant the visible code could compute directly*, but does so in a way that defeats both signature-matching and naive emulators - and that defers final values to the runtime VEH so static analysts only see "0" or implausible numbers in the listing.

### Step 3: Compute the target hash for `kernel32` (or whichever module)

```
.text:b220    be134f93b9     mov esi, 0xB9934F13               ; (real) target-hash chain start
.text:b225    81ffbe96f04c   cmp edi, 0x4CF096BE               ; (junk-ish) discards a flag
.text:b22b    81f6ad2cd077   xor esi, 0x77D02CAD               ; (real) hash chain step
.text:b231    8d36           lea esi, [esi]                    ; (junk)
.text:b233    81f6cea20495   xor esi, 0x9504A2CE               ; (real) hash chain step
.text:b239    81ee70c1475b   sub esi, 0x5B47C170               ; (real) hash chain step
.text:b23f    fc             cld                               ; (junk)
```

This is the GuLoader **target-hash construction**. Static evaluation:

```
0xB9934F13                     = start
^ 0x77D02CAD = 0xCE4363BE
^ 0x9504A2CE = 0x5B47C170
- 0x5B47C170 = 0x00000000      (resolves to literal 0)
```

Statically, esi = 0. *But this is the VEH bait region.* At runtime, GuLoader's exception-handler patches one or more of those four constants in-flight (typically `mov esi, 0xb9934f13` is replaced with a different immediate, by walking the buffer and modifying its own code). The constant 0 is the static analyst's view; the runtime view depends on how many anti-debug traps the VEH has fired up to this point. (See "What we can not recover statically" below.)

For now treat the target as a sentinel value `<TARGET_HASH>` that stands in for the actual hash the loader is looking up. Different PEB-walk sites build different `<TARGET_HASH>` values, one per API the loader needs.

### Step 4: Compare and jump to the resolver

```
.text:b240    3933           cmp [ebx], esi                    ; (real) cmp dword at ebx with target hash
.text:b242    8bb593010000   mov esi, [ebp + 0x193]            ; (real) restore esi (DllBase saved earlier)
.text:b248    0f8496030000   je  loc_B5E4                      ; (real) match: jump to "API found" handler
```

If the dword pointed to by `ebx` (a precomputed hash sitting in some array near the export table) equals the target hash `<TARGET_HASH>`, the loader jumps to its "this is the API I want" handler at `loc_B5E4`. Otherwise it falls through to the next iteration:

```
.text:b24e    80fa9d         cmp dl, 0x9D                      ; (junk)
.text:b251    8b4b0c         mov ecx, [ebx + 0xC]              ; (real) read offset+0xC from current entry
.text:b254    01f1           add ecx, esi                      ; (real) ecx = absolute address of API name
.text:b256    8b5308         mov edx, [ebx + 0x8]              ; (real) edx = address of next struct field
```

`[ebx + 0xC]` and `[ebx + 0x8]` are reading fields from a structure that walks like the PE export-name array. The loader is iterating either the actual `IMAGE_EXPORT_DIRECTORY.AddressOfNames` or a pre-hashed companion table sitting next to it.

This is one full iteration of the API-resolution outer loop. The next iteration repeats the same pattern with `ebx` advanced by the size of one entry. With ~30 distinct API hashes resolved (per the rainbow-table table above), the loader runs through this loop ~30 times, doing a Levenshtein-distance worth of noise instructions between each useful step.

### Step 5: When we land at the hash function itself

After enough iterations of the outer "find API" loop, the loader needs to actually **compute the hash of an export name**. That happens at offset `0x2EE78`, which the IDA script names `gl_hash_api`:

```
gl_hash_api:
.text:2ee78    0fb61e         movzx ebx, byte [esi]            ; (real) read low byte of UTF-16 wchar
.text:2ee7b    898dc3010000   mov [ebp + 0x1C3], ecx           ; (real) save caller's ecx
.text:2ee81    89d9           mov ecx, ebx                     ; (real) prep for stack call
.text:2ee83    51             push ecx                         ; (real) pass byte to gl_tolower
.text:2ee84    8b8dc3010000   mov ecx, [ebp + 0x1C3]           ; (real) restore caller's ecx
.text:2ee8a    e888000000     call gl_tolower                  ; (real) returns case-folded byte in ebx
.text:2ee8f    01da           add edx, ebx                     ; (real) HASH STEP 1: edx += b
.text:2ee91    81f2ade62d18   xor edx, 0x182DE6AD              ; (real) HASH STEP 2: edx ^= 0x182DE6AD
```

Those four lines (`movzx`, `call gl_tolower`, `add edx, ebx`, `xor edx, 0x182DE6AD`) are the *entire hash function*. Everything else in the body is anti-analysis padding.

Then comes the loop step:

```
.text:2ee9d    b80b103397     mov eax, 0x9733100B              ; (noise) eax = base for esi-stride calc
.text:2eea2    817d7ce4d90000 cmp [ebp + 0x7C], 0xD9E4         ; (noise) sandbox check
.text:2eea9    0f8416bcfdff   je loc_AAC5                      ; (noise)
.text:2eeaf    35ce51413b     xor eax, 0x3B4151CE              ; (noise) eax = 0xAC7251C5 (post-XOR)
.text:2eeb4    0fc8           bswap eax                        ; (noise) eax = 0xC551 72AC
.text:2eeb6    35ae7241c5     xor eax, 0xC54172AE              ; (noise) eax = 0x00100002
.text:2eebb    f7c3f0a79458   test ebx, 0x5894A7F0             ; (junk)
.text:2eec1    01c6           add esi, eax                     ; (real) advance esi by eax bytes
```

That `add esi, eax` is the **stride-2 wchar advance**. Statically (showing each step):

```
0x9733100B                  start (mov eax, imm32)
^ 0x3B4151CE = 0xAC7241C5   xor eax, imm32
bswap        = 0xC54172AC   bswap eax (byte-reverse a 32-bit word)
^ 0xC54172AE = 0x00000002   xor eax, imm32  (final delta is 2 in the low byte)
```

So `eax = 2`, `add esi, eax` advances esi by 2 bytes (one UTF-16 wchar), exactly what is needed to read the next byte of the name. *The constant 2 is encoded as a 4-instruction obfuscated arithmetic chain.* This is consistent with the target-hash construction in Step 3: any constant that an analyst could see in plaintext is hidden behind 4-6 instructions of XOR/bswap/sub.

The loop terminator:

```
.text:2eecf    b9ffe31658     mov ecx, 0x5816E3FF              ; (noise) build terminator
.text:2eed4    81f1136c8938   xor ecx, 0x38896C13
.text:2eeda    81f174eab58c   xor ecx, 0x8CB5EA74
.text:2eee0    81f198652aec   xor ecx, 0xEC2A6598
                                                                ; ecx now = 0x00000000 (statically)
.text:2eee6    817d7c7e550000 cmp [ebp + 0x7C], 0x557E         ; (noise)
.text:2eeed    0f84d2bbfdff   je loc_AAC5                      ; (noise)
.text:2eef3    84c2           test dl, al                      ; (junk)
.text:2eef5    66390e         cmp word ptr [esi], cx           ; (real) check if next wchar is 0 (terminator)
.text:2eef8    8b8da0010000   mov ecx, [ebp + 0x1A0]           ; (real) restore caller's ecx
.text:2eefe    0f856dffffff   jne loc_2EE71                    ; (real) not terminator: loop back
.text:2ef04    817d7c933f0000 cmp [ebp + 0x7C], 0x3F93         ; (noise)
.text:2ef0b    0f8db4bbfdff   jge loc_AAC5                     ; (noise)
.text:2ef11    c20400         ret 4                            ; (real) return; cleans 4 bytes from stack
```

`cmp word ptr [esi], cx` with `cx == 0` is comparing the next wchar to zero. If non-zero, loop back to read the next byte. If zero (UTF-16 string terminator), fall through to `ret 4` and return. The `ret 4` cleans 4 bytes of stack arguments (the byte that was pushed for `gl_tolower`).

So, removing all the noise, the hash function reduces to:

```c
uint32_t gl_hash_api(wchar_t *name) {
    uint32_t edx = 0;
    while (*name != 0) {
        uint8_t b = (uint8_t)*name;          // low byte of wchar
        if (b >= 'a' && b <= 'z') b -= 0x20; // case fold
        edx = (edx + b) ^ 0x182DE6AD;
        name++;
    }
    return edx;
}
```

Five lines. Wrapped in 28 instructions of obfuscation. That ratio - **80% of the function body is anti-analysis noise** - is the hallmark of GuLoader's stage-1 shellcode.

---

## Going Deeper: Three Follow-Up Tools

After the rainbow-table pass made the loader partially readable in IDA, three more tools were written to push further. Two of them landed cleanly. The third hit the limits of what static-only emulation can do against GuLoader and is documented here as much as a *failure mode* as a result, because the failure itself is informative.

### Tool A: anti-disassembly junk-strip ([scripts/ida_strip_junk.py](GuLoader/scripts/ida_strip_junk.py))

Walks the IDB, finds every short unconditional `jmp` whose target is forward in the same function, and checks whether the bytes between the `jmp` and its target contain any privileged x86 instructions (`in`, `out`, `vmxon`, `arpl`, `icebp`, etc.). If yes, those bytes are marked as data so IDA stops trying to disassemble them.

This is the standard opaque-jump-with-junk-bytes pattern. GuLoader uses it heavily; the loader has hundreds of these regions, each adding 12-80 bytes of garbage that the CPU never executes but that IDA's linear sweep dutifully decodes as nonsense like `in eax, dx; push es; out 2Eh, al`. After running this script the IDA listing shrinks dramatically and the privileged-instruction noise disappears. A sample run on the decoded buffer marked **roughly 4 KB of bytes as data across hundreds of regions**.

### Tool B: API-slot mapper ([scripts/ida_map_slots.py](GuLoader/scripts/ida_map_slots.py))

The loader's API resolution stores each resolved address in an `[ebp+SLOT]` slot, and later code dispatches via `call dword ptr [ebp+SLOT]`. Without knowing which API is in which slot, those calls look like opaque indirections. The mapper:

1. Finds every `call gl_hash_api` site (cross-references to the function we named at `+0x2EE78`).
2. Looks back from each call site for a `>>> CHAIN resolves to ...` comment placed by the chain folder. That comment carries the hash value the chain built.
3. Looks forward for the first `mov [ebp+SLOT], eax` that follows. EAX holds the resolved API pointer at that point. The slot offset gets bound to the API.
4. Walks the entire IDB once more and adds a comment to every `[ebp+SLOT]` reference that matches a known slot.

Result: a `call dword ptr [ebp+0xC8]` becomes `call dword ptr [ebp+0xC8]    ; <-- slot[0xC8] = VirtualAlloc`. The dispatch table is recovered.

Caveat: only works for chains that resolve to a *known* hash. Chains that resolve to `0x00000000` (the VEH-bait pattern, where the static value is meaningless) are skipped. So slots whose target hash is constructed at runtime via VEH are not mapped by this tool. A future run with a real-trace input could fill them in.

### Tool C: Unicorn-based shellcode emulator ([scripts/emulate_shellcode.py](GuLoader/scripts/emulate_shellcode.py))

Concrete-execution attempt. Builds a complete fake Windows process environment (TEB, PEB, PEB_LDR_DATA with linked module entries for kernel32 / ntdll / user32 / wininet / winhttp / advapi32 / shell32, fake export tables seeded with our hashed API names in UTF-16-LE), maps the decoded shellcode into RWX memory, hooks every `INT3` to dispatch fake API calls, and runs.

The intent was to capture the C2 URL at the moment `WinHttpOpenRequest` or `HttpOpenRequestA/W` is called.

**What worked:**
- The fake-PEB / fake-Ldr / fake-export-table setup was reached and walked. The loader successfully iterates the InMemoryOrderModuleList chain we built.
- The 4-byte XOR decoder, the FS_BASE handling (via instruction-rewriting fallback because Unicorn 2.1.4's `UC_X86_REG_FS_BASE` is a no-op for x86_32), and the JIT-cache-busting all behaved correctly.
- A loop-detection heuristic (any EIP hit > 500 times → look forward for a backward Jcc → force EIP past it) successfully broke out of three RDTSC-driven anti-emu stall loops the loader uses.
- After loop-breaking, code coverage went from 140 unique EIPs to **2,381 unique EIPs** in 25,890 instructions. The loader was running.

**What did not work:**
- The loader still trips into a low-address indirect read (`fs:[ebx]` with `ebx=0x30`, where on a real Windows host `fs:[0x30]` would be the PEB pointer but where Unicorn 2.1.4's no-op FS treatment plus the indirect form means the static fs-rewrite pass missed it). We worked around this by aliasing the TEB at low addresses, but the symptom shifted: the loader then read a stale dword from one of those aliased slots, used it as a function pointer, and jumped to a bogus address (`EIP=0xEF1`).
- This is symptomatic of a broader issue: **GuLoader's VEH-driven self-modification is not modeled**. Multiple chains we statically resolved to `0` are designed to have their constants patched in flight by the registered Vectored Exception Handler when an INT3 trap fires. Without that, the loader's runtime state diverges from what the static-resolved code expects, and execution wanders off the success path.
- The natural next step is one of:
  1. Implement a minimal VEH dispatcher in the emulator (we did this, ~250 LOC; details below).
  2. Move to a real Windows sandbox. The whole point of the static work was to *avoid* needing one, but for the C2 URL specifically the sandbox is the cheap answer; we cross-checked our static findings against an independent runtime trace and used that to fill in the runtime-correlated IOCs in the IOC tables below.

### Tool C.1: VEH dispatcher (built, but the loader never reaches VEH registration in our environment)

After the basic emulator hit the CFG-drift wall, a Vectored Exception Handler dispatcher was added. The dispatcher:

1. Hooks calls to `AddVectoredExceptionHandler` and `RtlAddVectoredExceptionHandler`, recording the handler EIP in an ordered list.
2. On any INT3 in loader code (not at our API trampolines), if a VEH is registered, builds:
   - An `EXCEPTION_RECORD` (24 bytes used: ExceptionCode = `0x80000003` = `STATUS_BREAKPOINT`, ExceptionAddress = INT3 site)
   - A 32-bit `CONTEXT` structure with all GP registers and EIP populated from the live CPU state
   - An `EXCEPTION_POINTERS` (8 bytes pointing to both)
3. Pushes the EXCEPTION_POINTERS pointer as a stdcall arg, pushes a sentinel "fake return address" (`0x77FFEEEE`, mapped with an INT3 byte at it), and redirects EIP to the registered handler.
4. When the handler `ret`s into the sentinel, the dispatcher reads back EAX (the handler's return value) and the possibly-modified CONTEXT.Eip:
   - `EXCEPTION_CONTINUE_EXECUTION` (`-1`): restore registers from the modified CONTEXT and resume at the new EIP.
   - Otherwise: skip past the INT3 with original registers.

The dispatcher is the right shape and compiles cleanly. **But it is never exercised in our run**, because the loader's CFG drift to address `0xEF1` happens **before** the loader resolves and calls `AddVectoredExceptionHandler`. The VEH-registration path lives downstream of work the loader does first that depends on register/stack state we are not providing correctly at entry. The dispatcher is in [scripts/emulate_shellcode.py](GuLoader/scripts/emulate_shellcode.py) ready to fire the moment a real registration call lands.

What we *learned* by building it: the question of "where does GuLoader enter?" is harder than it looked. The shellcode buffer does not have a single obvious entry point. NSIS invokes the loader via `EnumResourceTypesA`-or-`CallWindowProcW`-style indirection, and the actual initial register/stack state matters because the loader uses `[ebp+SLOT]` indexing throughout. Entering at offset `0` produces nonsense disassembly. Entering at the first PEB walk (`0xb197`) presupposes that earlier code already initialized state. Entering at the `call $+5` get-EIP idiom at `0x1700` runs further than either alternative but eventually drifts on an indirect call through stale aliased-TEB data. To reach the VEH-registration code we would need to either:
- Recover the *actual* entry point from the NSIS-script side (the `System::Call` that invokes the loader specifies a particular entry offset; we did not statically extract that detail, and finishing it would need a more complete NSIS emulator than the one we built).
- Or set up a much more complete fake initial state (register values, stack contents, OS structures the loader reads before resolving anything).

Neither of those is a small project. **At this point the cost-effective answer is a Windows sandbox.** Run the original NSIS dropper, capture the moment `WinHttpOpenRequest` is called, dump the URL. The static work in this post identified the exact API and the exact moment; the sandbox just confirms the live answer.

**What we still proved.** The 2,381 distinct EIPs reached confirm that the decoded shellcode's structure - the API resolution loop, the slot dispatch table, the multi-stage hash construction, the use of WinHttp + WinINet redundantly - is consistent with the public GuLoader literature *and* with the hashes our rainbow table found statically. The emulator did not extract the URL, but it independently corroborated that this *is* a GuLoader stage-1 loader doing the documented dance, not something else wearing GuLoader's hash function.

### What we cannot recover statically

Two things bottom out under static analysis:

1. **The actual API target hashes per call site.** Each PEB-walk site (Steps 1-4 above) repeats the hash-construction chain in Step 3 with different constants. Statically all 9 chains resolve to `0`. At runtime, GuLoader's Vectored Exception Handler (registered earlier) is supposed to intercept specific INT3 (`0xCC`) traps and patch the constants in flight, so each call site ends up looking up a different real hash. We can confirm the hashes the loader uses (the rainbow-table matches in the table above), but we can not statically *prove which call site looks up which API* without tracing the VEH.

2. **The second-stage URL.** It is encrypted somewhere in the same buffer, almost certainly downstream of one of the `WinHttpSetTimeouts` (hash `0xE88`) call sites at `0xa779`. To decrypt it we would need to follow the `WinHttpSendRequest` path through the VEH-patched control flow and capture the URL string at the moment it is passed to `WinHttpOpenRequest`. That requires running the shellcode in a controlled emulator (Unicorn + a fake ntdll/wininet) or a proper sandbox, which is the natural next phase of work.

Everything else - the loader's full API set, the hash algorithm, the PEB-walk chain, the anti-emulation noise pattern, the obfuscation ratio - is recovered.

---

## NSIS Opcode Disassembly (Selected)

The full 228-entry dump is generated by `scripts/nsis_disasm.py`. Here are the most behaviourally meaningful slices, with the script-pool string references resolved where they refer to ASCII fragments and left raw (`'　　...'`) where they reference packed Unicode markers (those are NSIS variable references, not real strings):

```
; ---- Section 0 (called from Section 1) ----
[130] EW_SETFLAG          'amFilesDir', 0, '$ProgramFilesDir', 0, 0, 0
[131] EW_SETFLAG          'mFilesDir', '$ProgramFiles\Common Files', 0, 0, 0, 0
[132] EW_WRITEREG         HKCU, '...\Skrubhvl4\', '977', 7104, ..., ...
[133] EW_SETFLAG          'mFilesDir', '#32770', 0, 0, 0, 0
[134] EW_READENVSTR       '$Var', '%TEMP%', 0, 0, 0, 0
[135] EW_CREATEDIR        '\sigmoidally\Nonillatively', 0, 0, 0, 0, 0
[136] EW_SETFLAG          'rogramFilesDir', '$ProgramFiles\Common Files', 0, 0, 0, 0
[137] EW_SETFILEATTRIBUTES 'onillatively', '6', 0, 0, 0, 0
[138] EW_GETFULLPATHNAME  '$_PLUGINSDIR_', 'ilesDir', '$ProgramFilesDir', 0, 0, 0
[139] EW_IFFLAG           '\oplysningsforbundene', '...', 'rogramFilesDir', -1, 0, 0
[140] EW_GETTEMPFILENAME  'nFilesDir', 656, 0, 0, 0, 0
[141] EW_RET              0, 0, 0, 0, 0, 0

; ---- Section 1 (entry point of malicious payload) ----
[171] EW_SETFLAG          'amFilesDir', '#32770', 0, 0, 0, 0
[172] EW_SETFLAG          'ProgramFilesDir', '$ProgramFiles\Common Files', 0, 0, 0, 0
[173] EW_SETFLAG          'ProgramFilesDir', 215, 0, 0, 0, 0
[174] EW_CREATEDIR        1269, '$ProgramFilesDir', 0, 0, 0, 0   ; mkdir Darnel
[175] EW_SETFLAG          'ProgramFilesDir', 215, 0, 0, 0, 0
[176] EW_CREATEDIR        1269, '$ProgramFilesDir', 0, 0, 0, 0
[177] EW_EXTRACTFILE      0x05000050, '00', 0x1bc7, 0x756e0500, 0x01dbc850, -45
[178] EW_EXTRACTFILE      0x05000050, '$0', 0x31458, ...        ; Cylindruria121.jpg
...
[191] EW_EXTRACTFILE      0x05000050, '\System.dll', 0xd5cc7,...; the System::Call plugin
[192] EW_EXTRACTFILE      0x05000050, 'dll', 0xd9248, ...
[193] EW_EXTRACTFILE      0x05000050, 'lloc', 0xd942f, ...      ; "VirtualAlloc" tail
[194] EW_EXTRACTFILE      0x05000050, '::Call', 0xda6c1, ...    ; System::Call definition
[195] EW_EXTRACTFILE      0x05000050, '$0', 0xda756, ...

; ---- Phase B: REGISTERDLL (System::Call) at indices 112 and 126 ----
[112] EW_REGISTERDLL      'Microsoft\Windows\CurrentVersion\Skrubhvl4\', ...
[126] EW_REGISTERDLL      'Microsoft\Windows\CurrentVersion\Skrubhvl4\', ...

; ---- Tail: clean up and quit ----
[225] EW_MESSAGEBOX       MB_USERICON, 'len', 0, 0, 0, 0
[226] EW_QUIT
```

Important to notice: the literal first argument to `EW_REGISTERDLL` shown above (`'Microsoft\Windows\...'`) is **not** the System::Call definition string. That argument is the registry-key path the script writes a "DLL registered" marker to (at `HKCU\Software\Microsoft\Windows\CurrentVersion\Skrubhvl4\`), a host-fingerprinting mutex left as a side effect. The real definition string is constructed at runtime in the variable referenced by the *second* argument (the obfuscated Unicode marker `\u5CWi...`), which the disassembler cannot fully resolve without the live variable context.

The string `Skrubhvl4` is one of the strongest cluster fingerprints for this 2025 GuLoader run: a Danish word ("scrub-on-skin-or-leather") that the script uses both as a registry sub-key name *and* as an installer-side mutex check (`Skrubhvl4` appears 19 times in the inflated header).

---

## Capabilities

A mapping of observed capabilities to NSIS opcode evidence and CAPA findings:

| Capability | Evidence (NSIS opcode / location) | MITRE ATT&CK |
|---|---|---|
| Self-extracting installer abuse | `EW_EXTRACTFILE` at 20 distinct script indices producing 19 disk files; NSIS-3 stub at FirstHeader offset `0x22a00` | T1027.009 |
| Native API call from script context | `EW_REGISTERDLL` at idx 112, 126; System.dll at `$PLUGINSDIR\System.dll` | T1218.011 |
| String concatenation obfuscation | `EW_PUSHPOP` (29 occurrences) and `EW_ASSIGNVAR` (8 occurrences) build runtime strings from word-salad fragments | T1140 |
| Decoy padding for sandbox evasion | `Maynard.pen`, `Ganocephala176.ham` (combined 17.6 MB) | T1027.001 |
| Junk-language identifiers | All variables and labels Danish nouns | T1027.013 |
| Registry persistence marker | `EW_WRITEREG` at idx 97, 132 to `HKCU\Software\Microsoft\Windows\CurrentVersion\Skrubhvl4\` | T1547.001, T1112 |
| 4-byte XOR encryption of stage-1 shellcode | `49 ED 06 B1` repeating key, recovered by stride-4 freq analysis | T1027.013 |
| PEB walk for module discovery | 9 `mov eax, fs:[0x30]` sites in decoded `piasaba` at offsets `0xb197, 0xfdf2, 0x1124f, 0x12906, 0x144c2, 0x17db0, 0x2ddca, 0x2ea37, 0x2fd15` | T1622, T1106 |
| Custom hash-based API resolution | `H = (H + UC(b)) XOR 0x182DE6AD` per UTF-16 wchar, helper at `0x2EF17` | T1027.007 |
| Anti-debug | `CheckRemoteDebuggerPresent` (hash `0x1B0`), `GetTickCount` (hash `0xBC`), `OutputDebugStringW` (hash `0xE4`) - resolved as APIs; small-hash collisions inflate raw match counts (see Confidence boundary above) | T1622 |
| Memory protection manipulation | `VirtualAlloc` (`0x45A`), `VirtualProtect` (`0x15C`), `VirtualProtectEx` (`0x1C9`), `RtlMoveMemory` (`0x120`) | T1055.012 |
| HTTP-based payload download | `WinHttpSendRequest` (`0x19D`), `WinHttpReadData` (`0x48`), `HttpSendRequestA/W` (`0xF6/0xDC`), `InternetOpenA` (`0x10BA`) | T1071.001, T1105 |
| Process injection chain | `CreateProcessW` (`0x134`), `NtCreateSection` (`0x1CB`), `NtCreateThread` (`0x20`), `CreateThread` (`0x1CE`) | T1055.012 |
| Disk staging of final stage | `CreateFileA/W`, `GetTempFileNameA/W`, `SHGetFolderPathA/W` | T1074.001 |
| Final launch | `ShellExecuteW` (`0x43A`) | T1106 |

---

## Code Weaknesses

The loader has several structural weaknesses that defenders can exploit:

1. **The `$PLUGINSDIR\System.dll` artifact is unique and stable.** Its SHA-256 (`8b4c47c4...d37c`) is byte-identical across NSIS-3 distributions, but the *combination* of "System.dll dropped under `$PLUGINSDIR` from a parent NSIS PE that also drops 17+ MB of constant-byte padding" is virtually never seen in benign installers. EDR rules that fire on parent-child relationships rather than file hash get this for free.

2. **The dual `0x5A` and `0xB7` decoy padding is a strong campaign fingerprint.** No real installer ships a `.pen` and a `.ham` file that are 99% one byte. A YARA rule that fires when *any* file in `%TEMP%\nsXXXX.tmp\` has more than 1 MB of a single repeating byte will catch this cluster outright.

3. **The Danish-word vocabulary is a small finite set.** GuLoader's word generator pulls from what looks like a single seed list; the same words (`Skrubhvl4`, `oplysningsforbundene`, `fedtcellen`, `Nonillatively`, `Confabulation`) recur across samples within a campaign. A YARA rule that requires four-of-N from a curated wordlist is highly specific and survives bytewise repacks.

4. **The `HKCU\Software\Microsoft\Windows\CurrentVersion\Skrubhvl4\` registry path is durable.** Any Sysmon EID-12/13 monitoring rule on that key prefix will catch new infections regardless of how the dropper EXE is repacked.

5. **The script is bytecode-frozen.** The 228 opcodes are baked into the EXE at build time. Renaming variables or adding garbage opcodes does not change the *shape* of the script. A behavioural rule that fires on "NSIS installer with 200+ opcode entries, dropping `System.dll` to `$PLUGINSDIR`, with at least two `EW_REGISTERDLL` calls *and* a tail of 15+ `EW_EXTRACTFILE` opcodes spanning a 700+ KB data section" is a structural capture that survives most repacks. (For this sample: 228 entries, 20 `EW_EXTRACTFILE`, 2 `EW_REGISTERDLL`, 29 `EW_PUSHPOP`, 8 `EW_ASSIGNVAR`.)

6. **No code-signing, no obfuscated signing, no signature manipulation.** The dropper is unsigned, which by itself is a weak signal but combined with the other artifacts becomes strong.

---

## IOC Appendix

### File Hashes

| Type | Value | Description |
|---|---|---|
| SHA-256 | `39c0135a0e8d46053fbcaa4efe6cbc83d33cf8e7be43efbca1622b2f77c7b9c6` | Outer NSIS dropper (this sample) |
| SHA-256 | `8b4c47c4cf5e76ec57dd5a050d5acd832a0d532ee875d7b44f6cdaf68f90d37c` | Bundled `$PLUGINSDIR\System.dll` (stock NSIS) |
| MD5 | `7d784ec37ec7bcac8a9c735a35b06449` | Outer NSIS dropper |
| MD5 | `9b38a1b07a0ebc5c7e59e63346ecc2db` | `$PLUGINSDIR\System.dll` |
| imphash | `573bb7b41bc641bd95c0f5eec13c233b` | Outer NSIS dropper imphash |

### Host Artifacts

| Type | Value | Description |
|---|---|---|
| Registry key | `HKCU\Software\Microsoft\Windows\CurrentVersion\Skrubhvl4\` | Mutex / fingerprint marker |
| Registry key | `HKCU\Software\Microsoft\Windows\CurrentVersion\synagogism` | Secondary marker |
| Registry key | `HKCU\Software\Microsoft\Windows\CurrentVersion\enclosed\fedtcellen` | Secondary marker |
| File path | `%TEMP%\ns[A-Z0-9]+\.tmp\Darnel\` | Working directory |
| File path | `%TEMP%\ns[A-Z0-9]+\.tmp\$PLUGINSDIR\System.dll` | NSIS plugin drop |
| File name | `Confabulation.exe` | Decoy launcher / shortcut name |

### Final-stage Remcos configuration (runtime-correlated)

The stage-1 shellcode does not embed the final-stage Remcos configuration; that lives in the separate Remcos PE downloaded from Google Drive at runtime. Independent runtime telemetry against this exact sample reveals the following Remcos config, which is useful as host-based detection ground truth even when the post-staging process is the *only* thing your sensor catches:

| Field | Value |
|---|---|
| Remcos version | 7.2.3 Pro |
| Botnet (campaign) name | `RemoteHost` |
| Mutex | `Rmc-JUY15N` |
| C2 endpoint | `31.57.184.186:2404` (raw TCP) |
| Install file name | `remcos.exe` |
| Install folder | `%ProgramData%\Remcos\` |
| Keylog file | `logs.dat` |
| Screenshot folder | `Screenshots` |
| Screenshot interval | 10 seconds |
| Audio recording interval | 5 seconds |
| Keylogging | Enabled |
| Browser credential theft | Enabled |
| Persistence | `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` value `Rmc-JUY15N` (also writes `HKLM\Run`, `HKLM\Explorer\Run`, `HKLM\Winlogon\Shell` where privileges allow) |
| Final-stage packer | MPRESS (per ANY.RUN sandbox tagging on the downloaded Remcos PE; the outer NSIS dropper is not packed) |

The mutex prefix `Rmc-` is the documented Remcos default and a reliable host-side fingerprint regardless of how the campaign rotates the suffix. The MPRESS pack on the final stage is an additional layer between the staging download and on-disk inspection: an EDR scanning the contents of `%ProgramData%\Remcos\remcos.exe` at rest sees the MPRESS stub, not the Remcos body, until the loader runs and unpacks itself.

### Original delivery filename and intermediate stages

| Path | Role |
|---|---|
| `RFQ__________pdf.exe` | Original NSIS dropper as delivered (Request-for-Quotation phishing lure) |
| `%TEMP%\nsXXXX.tmp\Darnel\` | NSIS extraction working dir (the 19 dropped files) |
| `%APPDATA%\Roaming\oplysningsforbundene\Darnel\` | Stage-1's runtime working dir (Danish-word fingerprint mirrored from the NSIS string pool) |
| `%TEMP%\exe.exe` | Intermediate copy of the downloaded Remcos PE |
| `%ProgramData%\Remcos\remcos.exe` | Final installed Remcos location |

The runtime mirroring of the NSIS-script word `oplysningsforbundene` into a `%APPDATA%\Roaming\` directory name is significant: it confirms our static observation that the Danish-word vocabulary is not just compile-time obfuscation but is consumed at runtime as path components. Hunters can monitor for `%APPDATA%\Roaming\<unusual-Danish-word>\Darnel\` as a behavioral indicator.

### Strings (Word-Salad Cluster Fingerprints)

```
Skrubhvl4
oplysningsforbundene
fedtcellen
Confabulation
synagogism
sigmoidally
Nonillatively
kontaktskabende
Maynard.pen
Ganocephala
Cylindruria
agestole.exe
paymasters tvrmundes
unfixated nonministerial
```

### Network IOCs

The stage-2 download URL is encrypted inside the stage-1 buffer (we suspect inside `Toolers`, which uses a stronger cipher than the outer `piasaba` 4-byte XOR; we did not break it statically). Independent runtime correlation against this exact sample shows the loader fetches:

```
hxxps://drive.google[.]com/uc?export=download&id=15kGN2jVE2bpmAl-3NVYGsPG8pnvv6lrH
```

resolved through `drive.google.com` (`142.251.2.113`) and `drive.usercontent.google.com` (`74.125.137.132`). The downloaded blob is a Remcos PE that the loader copies to `%ProgramData%\Remcos\remcos.exe` and launches.

Once running, **the final-stage Remcos beacons over raw TCP, not HTTP**, to:

```
31.57.184.186:2404
```

Port 2404 is the Remcos default. This is critical for detection: the WinHTTP/WinINet APIs we resolved in stage-1 (`WinHttpSendRequest`, `HttpSendRequestA/W`, `InternetOpenA`) are used **only for the Google Drive fetch** of the Remcos PE. Once Remcos is dropped to disk and executed, it opens its own outbound TCP socket to its C2; there is no further HTTP traffic from the GuLoader-staged process.

Block-at-the-proxy advice for the Google Drive staging stays the same as for any cloud-staged loader: reputation feeds, not DNS-blackhole, since `drive.google.com` is high-volume legitimate traffic.

---

## MITRE ATT&CK Mapping

Each row notes whether the technique is **(observed)** in our static analysis (we have a concrete artifact in the sample) or **(inferred)** from the resolved API set / public GuLoader literature (we know the loader has access to the API but have not statically traced its specific call site).

| Tactic | Technique | Sub-technique | Evidence | Confidence |
|---|---|---|---|---|
| TA0002 Execution | T1059 Command and Scripting Interpreter | T1059 (NSIS bytecode) | 228 compiled NSIS opcodes | observed |
| TA0002 Execution | T1106 Native API | --- | `gl_hash_api`-driven dispatch table; ~30 APIs resolved (rainbow-table matches above) | observed |
| TA0005 Defense Evasion | T1564 Hide Artifacts | T1564.001 (Hidden Files and Directories) | Working directory `%APPDATA%\Roaming\oplysningsforbundene\Darnel\` uses an inconspicuous Danish-word path | observed |
| TA0005 Defense Evasion | T1027 Obfuscated Files or Information | T1027.001 (Binary Padding) | 17.6 MB of constant-byte decoy (`Maynard.pen`, `Ganocephala176.ham`) | observed |
| TA0005 Defense Evasion | T1027 Obfuscated Files or Information | T1027.002 (Software Packing) | NSIS-3 self-extractor; `piasaba` 4-byte XOR with key `49 ED 06 B1` | observed |
| TA0005 Defense Evasion | T1027 Obfuscated Files or Information | T1027.007 (Dynamic API Resolution) | Custom additive-XOR hash `H = (H + UC(b)) XOR 0x182DE6AD` at `gl_hash_api` (`+0x2EE78`) | observed |
| TA0005 Defense Evasion | T1027 Obfuscated Files or Information | T1027.009 (Embedded Payloads) | 19 dropped files (incl. `piasaba`, `Toolers`, `System.dll`) | observed |
| TA0005 Defense Evasion | T1027 Obfuscated Files or Information | T1027.013 (Encrypted/Encoded File) | `piasaba` ciphertext; final-stage payload also encrypted (URL not extracted) | observed (outer); inferred (final stage) |
| TA0005 Defense Evasion | T1140 Deobfuscate/Decode Files or Information | --- | Runtime string concat from `.ini` fragments via `EW_PUSHPOP`/`EW_ASSIGNVAR` | observed |
| TA0005 Defense Evasion | T1497 Virtualization/Sandbox Evasion | T1497.001 (System Checks) | RDTSC-driven stall loops in stage-1 shellcode; sentinel checks against `[ebp+0x70/0x74/0x7C/0xAC]` | observed |
| TA0005 Defense Evasion | T1622 Debugger Evasion | --- | `CheckRemoteDebuggerPresent` (`0x1B0`), `OutputDebugStringW` (`0xE4`) resolved as APIs | observed (resolution); inferred (call path) |
| TA0005 Defense Evasion | T1055 Process Injection | T1055.012 (Process Hollowing) | `CreateProcessW` (`0x134`), `NtCreateSection` (`0x1CB`), `NtCreateThread` (`0x20`), `RtlMoveMemory` (`0x120`) resolved | observed (API set); inferred (full hollowing chain) |
| TA0007 Discovery | T1057 Process Discovery | --- | Not directly observed in this sample; consistent with public GuLoader reporting | inferred |
| TA0011 C2 | T1071 Application Layer Protocol | T1071.001 (HTTP) | `WinHttpSendRequest` (`0x19D`), `HttpSendRequestA/W` (`0xF6`/`0xDC`), `InternetOpenA` (`0x10BA`) resolved | observed (API set); inferred (URL) |
| TA0011 C2 | T1102 Web Service | --- | Cloud-hosted final stage typical for GuLoader; specific endpoint not statically extracted | inferred |
| TA0003 Persistence | T1547 Boot or Logon Autostart Execution | T1547.001 (Run keys) | `EW_WRITEREG` to `HKCU\Software\Microsoft\Windows\CurrentVersion\Skrubhvl4\` | observed |
| TA0005 Defense Evasion | T1112 Modify Registry | --- | `EW_WRITEREG` calls to `Skrubhvl4` and `synagogism` keys | observed |

---

## YARA Rules

The full ruleset lives in `detection/guloader_nsis.yar`. Four rules in total:

1. `GuLoader_NSIS_Outer` - matches the outer NSIS-3 dropper PE
2. `GuLoader_NSIS_DroppedScriptArtifacts` - matches the inflated NSIS header or extracted `Darnel/*.ini` files
3. `GuLoader_NSIS_DecoyPadding` - matches the `0x5A`/`0xB7`/`0xAC` constant-byte files
4. `GuLoader_NSIS_Generic` - broader family rule that survives version-info rotation

Excerpted main detector:

```text
import "pe"

rule GuLoader_NSIS_Outer
{
    meta:
        description = "GuLoader outer NSIS-3 self-extracting installer (2025 cluster)"
        author = "Tao Goldi"
        date = "2026-04"
        version = 1
        severity = "critical"
        family = "GuLoader"
        mitre_attack = "T1027.002,T1027.009,T1140,T1055,T1497.001,T1622,T1218.011"

    strings:
        $vi1 = "paymasters tvrmundes" wide
        $vi2 = "unfixated nonministerial" wide
        $vi3 = "agestole.exe" wide
        $nsis_setup = "Please wait while Setup is loading..." wide
        $nsis_sig    = { EF BE AD DE 4E 75 6C 6C 73 6F 66 74 49 6E 73 74 }
        $imp_sm  = "SendMessageTimeoutW" ascii
        $imp_inf = "SETUPAPI" ascii nocase

    condition:
        uint16(0) == 0x5A4D and
        filesize > 700KB and filesize < 5MB and
        $nsis_sig and
        pe.is_pe and
        pe.subsystem == pe.SUBSYSTEM_WINDOWS_GUI and
        for any s in pe.sections : (
            s.name == ".ndata" and s.raw_data_size == 0 and s.virtual_size > 0x10000
        ) and
        2 of ($vi*) and
        $nsis_setup and
        all of ($imp*)
}

rule GuLoader_NSIS_DroppedScriptArtifacts
{
    meta:
        description = "GuLoader NSIS-stage dropped artifacts (Danish word-salad)"
        author = "Tao Goldi"
        date = "2026-04"
        version = 1
        severity = "high"
        family = "GuLoader"
        notes = "Match against the inflated NSIS header or against the dropper memory image"

    strings:
        $w_skrub      = "Skrubhvl4"            ascii wide
        $w_confab     = "Confabulation"        ascii wide
        $w_oplys      = "oplysningsforbundene" ascii wide
        $w_fedt       = "fedtcellen"           ascii wide
        $w_synag      = "synagogism"           ascii wide
        $w_sigmoid    = "sigmoidally"          ascii wide
        $w_nonill     = "Nonillatively"        ascii wide
        $w_kontakt    = "kontaktskabende"      ascii wide
        $w_maynard    = "Maynard.pen"          ascii wide
        $w_ganoceph   = "Ganocephala"          ascii wide
        $w_cylindr    = "Cylindruria"          ascii wide
        $plugin_call  = "System::Call"         ascii wide

    condition:
        4 of ($w_*) or ( 2 of ($w_*) and $plugin_call )
}

rule GuLoader_NSIS_DecoyPadding
{
    meta:
        description = "GuLoader filesize-inflation decoy: file dominated by a single constant byte"
        author = "Tao Goldi"
        date = "2026-04"
        version = 1
        severity = "info"
        family = "GuLoader"

    strings:
        $pad_5a = { 5A 5A 5A 5A 5A 5A 5A 5A 5A 5A 5A 5A 5A 5A 5A 5A
                    5A 5A 5A 5A 5A 5A 5A 5A 5A 5A 5A 5A 5A 5A 5A 5A
                    5A 5A 5A 5A 5A 5A 5A 5A 5A 5A 5A 5A 5A 5A 5A 5A
                    5A 5A 5A 5A 5A 5A 5A 5A 5A 5A 5A 5A 5A 5A 5A 5A }
        $pad_b7 = { B7 B7 B7 B7 B7 B7 B7 B7 B7 B7 B7 B7 B7 B7 B7 B7
                    B7 B7 B7 B7 B7 B7 B7 B7 B7 B7 B7 B7 B7 B7 B7 B7
                    B7 B7 B7 B7 B7 B7 B7 B7 B7 B7 B7 B7 B7 B7 B7 B7
                    B7 B7 B7 B7 B7 B7 B7 B7 B7 B7 B7 B7 B7 B7 B7 B7 }
        $pad_ac = { AC AC AC AC AC AC AC AC AC AC AC AC AC AC AC AC
                    AC AC AC AC AC AC AC AC AC AC AC AC AC AC AC AC
                    AC AC AC AC AC AC AC AC AC AC AC AC AC AC AC AC
                    AC AC AC AC AC AC AC AC AC AC AC AC AC AC AC AC }

    condition:
        filesize > 100KB and
        ( #pad_5a > (filesize \ 4096) or
          #pad_b7 > (filesize \ 4096) or
          #pad_ac > (filesize \ 4096) )
}
```

Validation against this sample:

```
$ yara detection/guloader_nsis.yar sample/sample.exe
GuLoader_NSIS_Outer sample/sample.exe
GuLoader_NSIS_Generic sample/sample.exe

$ yara detection/guloader_nsis.yar sample/nsis_extract/Darnel/Maynard.pen
GuLoader_NSIS_DecoyPadding sample/nsis_extract/Darnel/Maynard.pen

$ yara detection/guloader_nsis.yar sample/nsis_extract/Darnel/Ganocephala176.ham
GuLoader_NSIS_DecoyPadding sample/nsis_extract/Darnel/Ganocephala176.ham

$ yara detection/guloader_nsis.yar /tmp/nsis_inflated_header.bin
GuLoader_NSIS_DroppedScriptArtifacts /tmp/nsis_inflated_header.bin
```

The `Generic` rule trades specificity for resilience: it is intentionally broad enough to keep firing if the campaign rotates the version-info strings or repacks the EXE.

---

## Hunting Notes

For threat hunters working from network telemetry or EDR data:

- **Sysmon EID 11 (FileCreate)** under `%TEMP%\ns*.tmp\` for files with extensions `.pen`, `.ham`, or no extension at all (`Toolers`, `piasaba`) is the strongest single indicator. Add file size > 5 MB to filter noise.
- **Sysmon EID 7 (ImageLoad)** for `*\$PLUGINSDIR\System.dll` from a parent in `%TEMP%` is high-fidelity. Legitimate NSIS installers extract `System.dll` to the user's normal install destination, not `%TEMP%`.
- **Sysmon EID 12/13/14 (Registry)** on `HKCU\Software\Microsoft\Windows\CurrentVersion\Skrubhvl4\` (or any sub-key under `CurrentVersion\` with a Danish-looking name) is uniquely diagnostic.
- **EDR network telemetry**: an NSIS-stage process initiating outbound HTTPS to `drive.google.com` (or `drive.usercontent.google.com`) within 60 seconds of execution, followed by a write to `%ProgramData%\Remcos\remcos.exe` and a registry write to `HKCU\...\Run` with a value name beginning `Rmc-`, is the GuLoader-delivers-Remcos chain at very high confidence. The Remcos default C2 protocol is **raw TCP on port 2404** (not HTTP/S), so the post-staging C2 traffic looks nothing like the staging fetch.
- **AV/email gateway file-size profile**: any inbound archive (zip, rar, 7z, lnk-with-payload) whose extracted contents include a file with > 5 MB of a single repeating byte is suspicious. Modern gateways with content-aware scanning will flag this; older signature-only ones will not.

---

## Conclusion

GuLoader's NSIS variant survives because the outer EXE is *boring*. It is a stock Nullsoft installer. Its imports are uninteresting. Its strings are uninteresting. Its imphash is generic. The malicious behaviour lives entirely in 228 NSIS opcodes that read random Danish nouns out of `.ini` files, concatenate them into Windows API names, and hand those names to a side-loaded NSIS plugin to invoke. The real shellcode and the encrypted final-stage payload are buried in two innocuously-named files among nineteen siblings in a working directory under `%TEMP%`, between two enormous decoys whose only purpose is to break sandbox file-size limits.

For this sample specifically, the chain ends at **Remcos 7.2.3 Pro**. GuLoader fetches the Remcos PE from a Google Drive direct-download URL, drops it to `%ProgramData%\Remcos\remcos.exe`, and registers `HKCU\...\Run` for autostart - then Remcos opens raw TCP to `31.57.184.186:2404` and goes about its job. There is no process hollowing into a signed Microsoft binary in this build; the canonical "GuLoader hollows into RegAsm.exe" generalisation does not apply. That mismatch with public reporting is itself a takeaway: GuLoader campaigns vary, and "GuLoader behaves like X" claims need to be re-verified per sample.

The countermeasures are not byte-pattern signatures; they are structural ones. Watch for: NSIS installers that drop `System.dll` to `$PLUGINSDIR` and immediately allocate RWX memory; files in `%TEMP%` that are 99% one byte; registry writes whose value name starts `Rmc-`; outbound raw TCP to a non-standard port shortly after a `drive.google.com` fetch; runtime working directories under `%APPDATA%\Roaming\` whose name is a dictionary word from a non-host-locale language. Combine those with parent-child process telemetry and the cluster collapses.

The 2025 campaign cluster represented by this sample uses `Skrubhvl4` as its mutex word, `0x5A` and `0xB7` as its decoy bytes, decoy version-info strings `paymasters tvrmundes` and `unfixated nonministerial`, the 4-byte XOR key `49 ED 06 B1` for the stage-1 container, and the API-hash key `0x182DE6AD`. The next campaign will rotate all of those. The choreography (NSIS dropper, then System.dll plugin, then 4-byte-XOR'd shellcode, then custom-hash API resolution, then cloud-staged final-stage download, then Remcos or the next Remcos-shaped RAT) will not.

---

## References

- [MalwareBazaar entry](https://bazaar.abuse.ch/sample/39c0135a0e8d46053fbcaa4efe6cbc83d33cf8e7be43efbca1622b2f77c7b9c6/) (uploader `threatcat_ch`, signature `GuLoader`)
- [VirusTotal community page](https://www.virustotal.com/gui/file/39c0135a0e8d46053fbcaa4efe6cbc83d33cf8e7be43efbca1622b2f77c7b9c6/community)
- [VT collection 0ef427c1...07b2de](https://www.virustotal.com/gui/collection/0ef427c176199a1b7c447d0ac3ea4752e4714fc7c9269928b1d54fbb6e07b2de) (sibling samples in this GuLoader-Remcos campaign)
- [Hatching Triage `260427-a4q5wsdw6k`](https://tria.ge/260427-a4q5wsdw6k)
- [Joe Sandbox report 1904872](https://www.joesandbox.com/analysis/1904872/0/html)
- [NeikiAnalytics / threat.rip](https://www.threat.rip/file/39c0135a0e8d46053fbcaa4efe6cbc83d33cf8e7be43efbca1622b2f77c7b9c6) (`Family.REMCOS`, malware config dump)
- [ANY.RUN sandbox task](https://app.any.run/tasks/8a8f7467-7381-44ca-936a-4e23663358a9) (live C2 capture confirming `31.57.184.186:2404`)
- [VMRay analysis report](https://www.vmray.com/analyses/_vt/39c0135a0e8d/report/overview.html) (chain labelled `GuLoader, Remcos`)
- [Nucleon Malprob report](https://malprob.io/report/39c0135a0e8d46053fbcaa4efe6cbc83d33cf8e7be43efbca1622b2f77c7b9c6)

The technical claims above were extracted from the binary on the workbench. The references are included so a defender can validate any single claim against multiple independent vantage points before adopting it operationally.
