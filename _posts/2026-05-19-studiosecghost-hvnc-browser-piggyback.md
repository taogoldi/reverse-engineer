---
title: "StudioSecGhost: A Browser-Piggyback hVNC Agent That Skips the Hidden Desktop"
permalink: /blog/studiosecghost-hvnc-browser-piggyback/
date: 2026-05-19 00:00:00 +0000
categories: [malware-reversing, threat-intel]
tags: [hvnc, windows, browser-hijack, amadey, dropper, yara, suricata, ioc, scheduled-task, persistence, anti-analysis, gdiplus, c2]
description: "Full static teardown of StudioSecGhost, a novel native x64 hVNC agent that piggybacks on Chrome/Edge/Firefox via per-window ghost cloaking, skipping CreateDesktopW entirely. C2: 2.26.122[.]211:4444. Pure disassembly, no sandbox required."
image:
  path: /assets/images/social/studiosecghost-card.png
  alt: "StudioSecGhost hVNC agent -- browser piggyback"
---

> **Downloads:** all artifacts for this post are mirrored at [taogoldi/analysis_data/studiosecghost_may_2026](https://github.com/taogoldi/analysis_data/tree/main/studiosecghost_may_2026). The YARA rules are also available at [taogoldi/YARA/hvnc/studiosecghost](https://github.com/taogoldi/YARA/tree/main/hvnc/studiosecghost). A full download index is at [/downloads/studiosecghost/]({{ site.baseurl }}/downloads/studiosecghost/).

Most hidden-VNC implants carve out an invisible `CreateDesktopW` desktop, spawn a fresh browser process on it, and stream whatever the operator clicks. StudioSecGhost does none of that. It launches a real, already-installed Chromium or Firefox process with a set of UI-suppression flags, navigates that process to a local HTML file whose `<title>` is its own internal codename, waits for `EnumWindows` to surface that titled window, and then cloaks the window with `ShowWindow(SW_HIDE)` + `SetWindowPos(SWP_HIDEWINDOW)` -- all inside the same Chromium process tree the victim is already using. The operator gets a ghost browser that shares the victim's cookies and logged-in state. The victim gets a layered "SECURITY AUDIT IN PROGRESS" banner and no explanation.

The sample arrived in the last 24 hours of ingest and carries zero public attribution as of the analysis date. This post is a full technical teardown: static analysis, each subsystem in detail, kill chain, detection, and IOCs.

### TL;DR

- **What it is.** A native x86-64 hidden-VNC agent, internal codename `StudioSecGhost`, that pilots a sibling browser window inside the victim's existing Chrome / Edge / Firefox process tree.
- **Why it is different.** It does *not* call `CreateDesktopW` / `SetThreadDesktop` (the standard hVNC pattern used by Pandora, DarkVNC, LOBSHOT). Instead it cloaks a per-window ghost via `WS_EX_LAYERED` + `WS_EX_TOOLWINDOW` + `SetLayeredWindowAttributes(alpha=0)`, then races to hide it before first paint through an `EnumWindows`-based callback the binary calls the "Interceptor."
- **Static indicators.** Internal markers `StudioSecGhost`, `StudioSecVNC_Banner`, `.SecAnchor`, `GSystem`. Drop names `studiosec_bounce.html` / `chrome_update_manifest.html` / `chrome_task_<n>.xml` / `ssv_cleanup.bat`. Victim overlay text `  WARNING!  SECURITY AUDIT IN PROGRESS.  `.
- **C2 and persistence.** Raw TCP, custom binary protocol, no TLS, to `2.26.122[.]211:4444` (AS201988 / VPSPay, Helsinki). Persistence via `schtasks /Create /XML` with `LogonTrigger` + `TimeTrigger PT2M` + `RestartOnFailure Count=999`, multiple replica slots on disk, and an in-process watchdog thread.
- **Detection opportunities.** YARA on the internal markers + 3-of-10 log-format prefixes; Suricata on TCP/4444 outbound and on JPEG-SOI bytes inside non-HTTP TCP frames; host-side hunt on `%TEMP%\chrome_task_<n>.xml` drops; Firefox `prefs.js` carrying both `browser.sessionstore.resume_from_crash=false` and `toolkit.startup.max_resumed_crashes=-1` as a forensic indicator.
- **Caveat.** The first-party analysis is **pure static** -- disassembly only, no dynamic detonation. Behavioral inferences are grounded in the disassembly cited at every claim site. Several of those inferences (C2 IP+port, Chrome User Data access, bounce-HTML drop, scheduled-task XML staging) have since been corroborated against public sandbox telemetry for the same SHA-256; see **Public Sandbox Corroboration**. Items not yet validated dynamically are flagged in **Remaining Open Questions**.

---

## Sample Properties

| Field | Value |
|---|---|
| Filename observed | `ahy.exe` |
| Size | 353,280 bytes (345 KB) |
| Architecture | x86-64 PE, subsystem GUI (2) |
| Compile timestamp | 2026-05-17 01:46:09 UTC |
| MD5 | `c1b29c991b45789bda71074cd41a0ca8` |
| SHA-1 | `0590fd821c037b404527566eae38d63519ee6a11` |
| SHA-256 | `5940c41ab003399680a04d726587eed242e4ad8969abe4b5617d712ff190a852` |
| Imphash | `26edff0935c20dff74e040648243639a` |
| OriginalFilename (version info) | `ahy.exe` |
| ProductName / FileDescription | `ahy` |
| Family marker | `StudioSecGhost` (in bounce-HTML title and window search string) |
| C2 | `2.26.122[.]211` (VPSPay AS201988, Helsinki, FI) |
| TLP | TLP:CLEAR |

---

## Getting the Sample

The binary was pulled from the internal threat-intel platform ingest queue inside the 24-hour window ending 2026-05-19. The platform's first-pass classifier tagged it `spyware/stealer` (a generic bucket) with no family attribution. At the time of triage, the SHA-256 had no VirusTotal entry, no MalwareBazaar report, and no public sandbox detonation visible to OSINT.

The file is a single 353,280-byte PE; no installer wrapper, no dropper, no overlay. It is the agent itself, not a stage one. The way it arrived at the ingest -- a single self-contained EXE with no carrier -- is consistent with the binary being delivered as the payload of a separate loader or via direct execution after a credential-access foothold; the delivery vector itself is outside the visibility of this analysis.

The internal builder codename `StudioSecGhost` is embedded as a plaintext UTF-16LE string in `.rdata` at file offset `0x48bb8`. It doubles as the ghost window's HTML title and as the string literal passed to the `EnumWindows` callback for the `GetWindowTextW` comparison. The companion window class `StudioSecVNC_Banner`, the anchor window classes `GSystem` / `.SecAnchor`, and the four filesystem-artifact names (`studiosec_bounce.html`, `chrome_update_manifest.html`, `chrome_task_%u.xml`, `ssv_cleanup.bat`) follow in the same data region. None of these strings are obfuscated; no stack-strings, no XOR, no RC4-with-hardcoded-key, no resource-decryption stub.

Family naming follows the binary's own self-identifier: **StudioSecGhost**. The folder, YARA rule prefix, and blog title all derive from the same source string used by the binary internally.

---

## Methodology and Toolchain

This analysis is **pure static** -- no dynamic detonation, no sandbox run, no debugger. Every behavioral claim is derived from disassembly of the on-disk PE. The work is reproducible from the shipped scripts; nothing here required a one-off tool or a manual IDA session.

The toolchain is three short Python scripts in `scripts/`:

### `recon.py` -- packing and obfuscation indicators

A first-pass `pefile` + `capstone` sweep covering TLS callback table inspection, 4KB-windowed Shannon entropy across every section, anomalous-import detection (`LoadLibraryA` + `VirtualAlloc` + `GetProcAddress` combos), and counts of OLLVM-style control-flow indicators (`je rel32 ; jne rel32` chains, `xor reg,reg ; jcc` opaque-predicate patterns, `nop` runs). Output goes to stdout; the figures cited in the **First-Pass Static Analysis** posture paragraph come from a verbatim run of `python scripts/recon.py`.

![recon.py output -- packing/obfuscation indicator pass on the sample](/assets/images/posts/studiosecghost/screenshot_recon.png)

### `extract_config.py` -- sample-agnostic config lifter

The agent stores everything operational as plain UTF-16LE wide strings in `.rdata`. The extractor walks `.rdata`, builds the wide-string list, then buckets each string by predicate (`endswith(".html")`, `s.isdigit()`, `wcsicmp` to a known anchor literal, etc.). It does not hardcode any sample-specific offsets, so it should work against future StudioSecGhost builds that rotate filenames or rearrange `.rdata`. The JSON output is in `reports/json/extracted_config.json`.

![extract_config.py output -- the full static config lifted from .rdata](/assets/images/posts/studiosecghost/screenshot_extract_config.png)

### `deep_disasm.py` -- targeted function reversing

The third script does the heavy lifting. Given a small set of *string anchors* (each is the VA of a `lea rXX, [string]` instruction that loads a known log format string), it:

1. **Finds all function starts in `.text`** by scanning for `int3`-padding boundaries followed by common MSVC x64 prologue bytes (`48` REX.W, `4C` REX.WR, `55` push rbp, `53` push rbx, etc.). On this sample, 879 functions are recovered.
2. **Maps each anchor VA to its containing function** by binary-searching the prologue list.
3. **Finds API caller sets** for any IAT entry of interest. The blocklist-scan function was located by enumerating callers of `CreateToolhelp32Snapshot` and `Process32FirstW`. (Both turned out to be inside `chrome_lifecycle_manager`, not the anti-analysis routine; the *real* anti-analysis routine was found by xref'ing the wide-string literal `x64dbg.exe`, which has exactly one lea reference in the entire binary -- VA `0x14000587F`.)
4. **Locates references to specific data literals** by replaying the disassembly and computing `insn.address + insn.size + disp` for every `lea reg, [rip + disp]`, filtering for hits on a target VA. This is how the ghost-window search was tied to its one call site, and how the wcsstr compare function at `0x1400153E0` was identified by counting its callers.
5. **Annotates every IAT call and lea** with the resolved DLL/function name or the destination string (decoded as either ASCII or UTF-16LE). The output reads like an IDA listing without needing IDA -- IAT references show as `; -> KERNEL32.dll:WaitForSingleObject` and string references show as `; -> 0x14004ABE8 = L"..."`.
6. **Reports register-write candidates** for "where does this register get loaded?" questions. The C2 port was identified by enumerating every `mov ebx, imm32 / mov ebx, [...]` inside `agent_main_loop` and inspecting the surrounding context for each candidate.

The full output is captured to `reports/json/deep_disasm.txt` (about 3,500 lines) and is the source-of-truth for every disassembly snippet quoted in this article.

---

## First-Pass Static Analysis

### Section Table

| Section | VSize | Raw | Entropy | Notes |
|---|---|---|---|---|
| `.text` | 232,268 | 232,448 | 6.456 | Native x64 code; no packing signature |
| `.rdata` | 96,070 | 96,256 | 5.155 | Import table + UTF-16LE config strings |
| `.data` | 16,684 | 7,168 | 2.422 | BSS-heavy; global state |
| `.pdata` | 11,580 | 11,776 | 5.529 | x64 SEH unwind table (RUNTIME_FUNCTION array; ABI-mandated for x64 PE) |
| `.fptable` | 256 | 512 | 0.000 | Function-pointer / load-config table; padded with zeros |
| `.rsrc` | 1,048 | 1,536 | 3.220 | Minimal resources; no icon or manifest |
| `.reloc` | 2,556 | 2,560 | 5.430 | Relocations present; ASLR enabled |

Entropy across all executable sections sits in the 5-6.5 range, consistent with unobfuscated native code. There is no overlay and no packed stub.

### Import Summary

The import table is a direct read on the binary's subsystem responsibilities:

- **KERNEL32.dll** (122 imports): process/thread management (`CreateThread`, `CreateToolhelp32Snapshot`, `Process32FirstW`/`NextW`, `CreateProcessW`), file I/O (`CreateFileW`, `WriteFile`, `CopyFileW`, `DeleteFileW`), anti-debug (`IsDebuggerPresent`, `CheckRemoteDebuggerPresent`), synchronization (`CreateMutexW`, `WaitForSingleObject`, `AcquireSRWLockExclusive`)
- **USER32.dll** (40 imports): full window-management suite -- `RegisterClassExW`, `CreateWindowExW`, `EnumWindows`, `GetWindowTextW`, `ShowWindow`, `SetWindowPos`, `SetLayeredWindowAttributes`, `PrintWindow`, `GetDC`
- **GDI32.dll** (11 imports): off-screen bitmap pipeline -- `CreateCompatibleDC`, `CreateCompatibleBitmap`, `BitBlt`, `CreateFontW`
- **gdiplus.dll** (10 imports): `GdiplusStartup`, `GdipCreateBitmapFromHBITMAP`, `GdipSaveImageToStream` -- JPEG encoding
- **WS2_32.dll** (10 imports): raw BSD-socket API -- `WSAStartup`, `getaddrinfo`, `connect`, `send`, `recv`
- **ADVAPI32.dll** (4 imports): registry reads (`RegOpenKeyExW`, `RegQueryValueExW`) + `GetUserNameW`
- **SHELL32.dll** (1 import): `SHGetFolderPathW` -- for resolving `%TEMP%` and `%APPDATA%`
- **ole32.dll** (4 imports): `CoInitializeEx`, `CreateStreamOnHGlobal`, `CoCreateInstance`, `CoUninitialize` -- COM stream for GDI+ JPEG output

Fully native Win64 binary. No managed-runtime or scripting-engine imports.

### String Observations

All operational strings are stored as UTF-16LE wide strings in `.rdata`, recoverable via `strings -e l`. The exceptions are the ASCII literals at VA `0x1400490A0` (`browser.sessionstore.resume_from_crash`) and `0x1400490C8` (`user_pref`), both written directly into the Firefox `prefs.js` file (an ASCII format, so the encoding is consistent).

Recovered strings include:

- C2 target literal: `2.26.122[.]211` as a standalone wide string at VA `0x140049BB8`
- C2 log format: `[NET] AgentNetwork started. Target: %ls:%u` at VA `0x14004A280`
- Log prefixes: `[INIT]`, `[CHROME]`, `[VNC]`, `[NET]` -- one per subsystem
- Bounce HTML format strings: `%sstudiosec_bounce.html`, `%s\chrome_update_manifest.html`
- Scheduled task XML filename format: `%schrome_task_%u.xml`
- Cleanup batch format: `%s\ssv_cleanup.bat`
- Browser process names: `chrome.exe`, `msedge.exe`, `firefox.exe`
- Browser install paths: full `C:\Program Files[ (x86)]\...` paths for all three browsers
- Banner text: `  WARNING!  SECURITY AUDIT IN PROGRESS.  `
- Anti-analysis strings: all 15 analyst/debugger tool names (see Anti-Analysis section)

The full extracted config is available as JSON via the `scripts/extract_config.py` tool included with this analysis (see the **Config Extraction** section below).

### Posture

The binary is statically linked against the CRT (`/MT`), is not packed, and is not obfuscated. The TLS callback table is empty, `.text` 4KB-windowed entropy stays in the 5.13-6.51 range, neither `LoadLibraryA` nor `VirtualAlloc` is imported (ruling out the usual runtime-unpacker pattern), and a sweep of `.text` for OLLVM-style indicators (`je rel32 ; jne rel32` chains, `xor reg,reg ; jcc` opaque predicates, long NOP runs) returns zero hits. Numbers come from `scripts/recon.py`.

---

## Decompiler-Level Reversing

This section walks the four routines that define StudioSecGhost's behavior, with concrete virtual addresses. The companion script `scripts/ida_rename_studiosecghost.py` automates the function-rename pass that produced these names; load it via `exec(open(...).read())` in IDA Python.

### Main Loop and Network Thread Bootstrap (function @ `0x140003a40`)

The bootstrap function at VA `0x140003a40` owns the lifecycle of every long-lived subsystem: Winsock, GDI+, the network thread, the lifecycle manager. The C2 connection itself is dispatched to a worker thread spawned here. The port is **hardcoded as an immediate** in this function:

```text
.text:140005dec  mov  ebx, 0x115c                  ; port = 4444 (decimal)
.text:140005df1  xor  r9d, r9d
.text:140005df4  xor  r8d, r8d
.text:140005df7  mov  word ptr [rbp + 0xb8], bx    ; stash port (u16) on the stack
.text:140005dfe  mov  edx, 1                       ; bManualReset = TRUE
.text:140005e03  xor  ecx, ecx                     ; lpEventAttributes = NULL
.text:140005e05  call cs:CreateEventW              ; -> KERNEL32.dll
.text:140005e0b  mov  [rbp + 0x58], rax            ; save event handle
.text:140005e12  je   <cleanup>                    ; if CreateEvent failed
.text:140005e1d  lea  r8,  [rip + 0x898c]          ; r8 = 0x14000E7B0 (thread entry)
.text:140005e34  call cs:CreateThread              ; -> network thread
```

The port `0x115c` = **4444** -- the canonical Metasploit / Meterpreter default. The thread entry point at VA `0x14000E7B0` is the actual `net_agent_start` (handles handshake, AUTH_LOGIN, command loop). The C2 IP and port are then passed to the per-session log call right after the thread is alive:

```text
.text:140005f75  mov  r8d, ebx                     ; port = 4444
.text:140005f78  lea  rdx, [rip + 0x43c39]         ; -> L"2.26.122[.]211"  (VA 0x140049BB8)
.text:140005f7f  lea  rcx, [rip + 0x442fa]         ; -> "[NET] AgentNetwork started. Target: %ls:%u"
.text:140005f86  call agent_log                    ; -> 0x14000E480
```

Cleanup (taken when the connection drops or `CMD_UNINSTALL` arrives) waits the worker thread out with a 5-second timeout, then tears down Winsock and GDI+:

```text
.text:140005f1e  mov  edx, 0x1388                  ; 5000 ms
.text:140005f23  call cs:WaitForSingleObject       ; wait on the net thread
.text:140005f30  call cs:CloseHandle
.text:140005e6b  call cs:WSACleanup
.text:140005e75  call cs:GdiplusShutdown
```

**Both the C2 IP and port are statically extractable in this build.** The IP is a `.rdata` literal at VA `0x140049BB8`. The port is the immediate operand of a `mov ebx` instruction at VA `0x140005DEC` and can be lifted by any disassembler that resolves immediates -- including the supplemental `extract_config.py` (which can be extended with a `mov rXX, imm32` scan keyed off the format-string lea). For new builds, hunt for the byte pattern `BB 5C 11 00 00` (mov ebx, 0x115c) to fingerprint identical port choices; if the operator rebuilds with a different port, the same `mov ebx, <imm32>` pattern preceded by a write to `[rbp+0xb8]` will still be the signature.

![deep_disasm.py output -- the port lift at VA 0x140005DEC, followed by CreateEventW + CreateThread spawning the network thread at 0x14000E7B0](/assets/images/posts/studiosecghost/screenshot_deep_disasm_port.png)

### Anti-Analysis Routine (function @ `0x140005700`)

The anti-analysis gate runs early in the bootstrap path, *before* any network init, window registration, or persistence. It is structured as a single function with three stacked checks; tripping any one of them branches to `ReleaseMutex` and process exit at `0x1400059EF`.

**Check 1: QueryPerformanceCounter timing trip-wire** (`0x140005710-0x14000577C`).

```text
.text:140005710  call cs:QueryPerformanceFrequency      ; freq
.text:14000571d  call cs:QueryPerformanceCounter        ; t0
.text:140005730  mov  eax, [rsp + 0x60]                 ; busy loop:
.text:140005734  add  eax, ecx                          ;   acc += i
.text:140005736  inc  ecx                               ;   i++
.text:14000573c  cmp  ecx, 0x3e8                        ; 1000 iterations
.text:140005742  jl   0x140005730
.text:14000574b  call cs:QueryPerformanceCounter        ; t1
.text:140005765  cvtsi2sd xmm0, [rbp - 0x70]            ; xmm0 = freq (double)
.text:14000576b  cvtsi2sd xmm1, rax                     ; xmm1 = (t1-t0)
.text:140005770  divsd    xmm1, xmm0                    ; xmm1 = elapsed seconds
.text:140005774  comisd   xmm1, [rip + 0x4546c]         ; threshold (xmmword in .rdata)
.text:14000577c  ja       0x1400059ef                   ; jump exit if elapsed > threshold
```

A 1000-iteration `inc/add` loop should complete in single-digit microseconds on any modern CPU. If a debugger is single-stepping or instruction-tracing the loop, the elapsed time inflates by orders of magnitude and the agent exits. This is a textbook RDTSC/QPC anti-debug. The threshold is a `double` constant at VA `0x14004ABE8` with value **0.5 seconds** -- raw little-endian bytes `00 00 00 00 00 00 e0 3f` (IEEE-754 double for 0.5). That threshold is generous: single-stepping the loop trips it instantly, but an emulator or sandbox running at full instruction speed sails through.

**Check 2: NtQueryInformationProcess + parent-process inspection** (`0x140005782-0x14000585E`).

```text
.text:140005782  lea  rcx, [rip + 0x4267f]               ; -> L"ntdll.dll"
.text:140005789  call cs:GetModuleHandleW
.text:140005792  lea  rdx, [rip + 0x42687]               ; -> "NtQueryInformationProcess"
.text:140005799  call cs:GetProcAddress                  ; resolve dynamically
.text:14000579f  mov  rbx, rax                           ; rbx = NtQuery fn ptr
.text:1400057be  call cs:GetCurrentProcess
.text:1400057c4  mov  r9d, 0x30                          ; sizeof(PROCESS_BASIC_INFORMATION)
.text:1400057d1  xor  edx, edx                           ; class = ProcessBasicInformation (0)
.text:1400057dc  call rbx                                ; NtQueryInformationProcess(...)
.text:1400057e6  mov  r8d, [rbp + 0x48]                  ; parent PID (PBI.InheritedFromUniqueProcessId)
.text:1400057ec  mov  ecx, 0x1000                        ; PROCESS_QUERY_LIMITED_INFORMATION
.text:1400057f1  call cs:OpenProcess                     ; open parent
.text:140005830  call cs:QueryFullProcessImageNameW      ; parent's image path
.text:14000585e  call PathFindFileNameW_equiv            ; strip directory
```

The agent does **not** enumerate the running process list. It looks at its **own parent process** and checks whether that parent's executable name matches a debugger / analyst tool. `NtQueryInformationProcess` is resolved at runtime via `GetModuleHandleW(L"ntdll.dll")` + `GetProcAddress("NtQueryInformationProcess")` -- the syscall is not statically imported, so IAT-only scanners miss it.

**Check 3: substring match against 15 blocklisted parent names** (`0x140005863-0x1400059ED`).

After the parent's executable name is in `[rbp + 0x670]`, the agent runs a chain of `wcsstr` calls -- not `_wcsicmp` and not `_wcsnicmp`. The chain is fully unrolled into 15 sequential `lea rdx, <blocklist[i]> ; lea rcx, parent_name ; call wcsstr ; test rax,rax ; jne exit` blocks, e.g.:

```text
.text:140005863  lea  rdx, [rip + 0x425d6]   ; -> L"ollydbg.exe"
.text:14000586a  lea  rcx, [rbp + 0x670]     ; parent exe name
.text:140005871  call wcsstr_sse2            ; -> 0x1400153E0
.text:140005876  test rax, rax
.text:140005879  jne  0x1400059ef            ; exit on substring hit
.text:14000587f  lea  rdx, [rip + 0x425d2]   ; -> L"x64dbg.exe"
... (13 more entries, same pattern) ...
.text:1400059d7  lea  rdx, [rip + 0x425ba]   ; -> L"cheatengine"
.text:1400059de  lea  rcx, [rbp + 0x670]
.text:1400059e5  call wcsstr_sse2
.text:1400059ea  je   0x140005a11            ; clean path -- continue agent bootstrap
```

The compare function at `0x1400153E0` is the SSE2-vectorized `wcsstr` (it uses `pshuflw / pshufd / pcmpeqw / pmovmskb` to scan 8 wide chars per iteration). The semantics are **substring match**: `wcsstr(parent, L"ghidra") != NULL` returns true for any parent whose name *contains* the substring `ghidra`, regardless of position. That answer applies to all 15 entries equally -- the choice to drop the `.exe` suffix on `ghidra` and `cheatengine` reflects the fact that those tools have many version-suffixed binary names (`ghidra-12.0.exe`, `cheatengine-x86_64.exe`), so the operator matched a stable prefix instead of any one specific filename.

![deep_disasm.py output -- the unrolled 15-call wcsstr chain that compares the parent process name against the analyst-tool blocklist](/assets/images/posts/studiosecghost/screenshot_deep_disasm_blocklist.png)

The 15 wide-string blocklist entries live in a contiguous array at VAs `0x140047E40` through `0x140047F90`, immediately preceded by the `ntdll.dll` string (VA `0x140047E08`) used in the dynamic `GetProcAddress` lookup above.

**Defensive implications of the parent-process design.**

Because the agent only checks the parent PID's executable name (and uses substring matching), the practical bypasses are different from what a "scan all running processes" check would imply:

- Launching the sample from `cmd.exe`, `powershell.exe`, `explorer.exe`, or any sandbox monitor (Cuckoo's `python.exe`, CAPE's monitor processes) -- **bypasses every check**, regardless of which analyst tools are running elsewhere on the host.
- Double-clicking the sample with IDA Pro running in a separate window -- **bypasses**, because the parent is `explorer.exe`, not `ida64.exe`.
- Loading the sample via IDA's "Run -> Run process" -- **caught**, because the parent is `ida64.exe`.
- Spawning the sample from a custom debugger named `my_x64dbg_wrapper.exe` -- **caught** by substring match on `x64dbg.exe`.
- Renaming `x64dbg.exe` to `not_a_debugger.exe` before launching the sample -- **bypasses**, because the substring no longer matches.

The QPC timing check is more of an obstacle, but only for live single-stepping. A timing-aware analyst tool that fakes `QueryPerformanceCounter` (or any sandbox that runs the binary at full speed without instrumentation) will sail through it.

### Ghost-Window Acquisition (`chrome_acquire_ghost` @ `0x140008870`) and the "Interceptor"

Once the browser process is launched, the agent runs two distinct hide mechanisms in parallel. The first is the *Interceptor*, which races to hide the ghost window before it draws to the screen. The second is the `EnumWindows` fallback that scans the live z-order for any window whose title contains `StudioSecGhost`.

**The Interceptor (cloak callback @ `0x140008500`).** The lifecycle manager runs a tight `EnumWindows` polling loop whose callback is invoked against every top-level window each iteration. There is no `SetWindowsHookEx` evidence in the import table or call graph -- the "interceptor" name in the binary's own log strings refers to a fast `EnumWindows`-based race against window creation, not a true Windows hook. The callback is at VA `0x140008500`. Its logic:

```text
.text:140008556  call cs:GetClassNameW                ; get target window's class
.text:140008568  call wcsstr_sse2                     ; substring match against g_class_filter
.text:14000856f  je   <ignore>                        ;   skip if not the target class
.text:14000858b  call cs:GetWindowLongPtrW (GWL_EXSTYLE)
.text:140008594  bt   rax, 0x13                       ; test WS_EX_TOOLWINDOW (0x80)
.text:140008599  jb   <already_cloaked>               ;   bit set -> already hidden
.text:1400085de  or   rdi, 0x80080                    ; add WS_EX_LAYERED | WS_EX_TOOLWINDOW
.text:1400085f0  call cs:SetWindowLongPtrW            ; install layered+toolwindow style
.text:140008604  call cs:SetLayeredWindowAttributes   ; alpha = 0, transparent
```

The combination of `WS_EX_LAYERED` + `WS_EX_TOOLWINDOW` + `SetLayeredWindowAttributes(hwnd, 0, 0, LWA_ALPHA)` hides the window from the taskbar (toolwindow) and from the screen (alpha=0) without requiring `ShowWindow`. The log string at VA `0x1400492A0` is the success message for this fast path: `[CHROME] Interceptor caught ghost HWND=%p -- hidden before paint.`

**The EnumWindows fallback (function @ `0x140008870`).** When the Interceptor misses (e.g., race on browser cold-start), this routine polls `EnumWindows` until a top-level window whose title *contains* `StudioSecGhost` appears. The callback:

```text
.text:140008668  call cs:GetWindowTextW              ; title -> [rsp+0x130]
.text:14000866e  lea  rdx, [rip + 0x40c0b]           ; -> L"StudioSecGhost"  (VA 0x140049280)
.text:140008675  lea  rcx, [rsp + 0x130]
.text:14000867d  call wcsstr_sse2                    ; -> 0x1400153E0
.text:140008682  test rax, rax
.text:140008685  je   <not_found_continue_enum>      ; rax == NULL -> wcsstr didn't match
.text:14000868a  mov  [rip + 0x4d9ff], rbx           ; g_ghost_hwnd = hwnd
.text:140008691  lea  rcx, [rip + 0x40c08]           ; -> log format
.text:140008698  call agent_log
.text:14000869d  xor  eax, eax                       ; return 0 (stop EnumWindows)
```

The compare is the same SSE2 `wcsstr` used in the anti-analysis routine -- so the title match is a **substring search, not an exact match**. Any top-level window whose title contains the literal `StudioSecGhost` anywhere is a candidate for cloaking. In practice the only window with that substring is the agent's own bounce HTML page (Chromium uses the HTML `<title>` as the window title), so the substring-vs-exact distinction does not change the operational outcome. It does, however, mean an analyst can poison the search by opening any process with `StudioSecGhost` in its title -- the agent will cloak that decoy window and miss its own ghost.

![deep_disasm.py output -- the EnumWindows callback that GetWindowTextW's each top-level window and substring-matches against L"StudioSecGhost" at VA 0x140049280](/assets/images/posts/studiosecghost/screenshot_deep_disasm_ghost.png)

After the HWND is captured, the same `WS_EX_LAYERED` + `WS_EX_TOOLWINDOW` cloak from the Interceptor is applied, and the HWND is handed to `vnc_stream_thread`.

The lifecycle manager also runs a second `EnumWindows` callback at VA `0x140009230` whose purpose is to find the agent's **own** anchor window (class `GSystem`). The callback inline-compares the first 8 wide chars of every window title against `L"GSystem"` (stored at VA `0x1400496C8`) -- this is the agent looking up its own message-pump window to deliver lifecycle commands.

### Frame Capture Pipeline (`vnc_stream_thread`)

The streaming subsystem is the most COM-heavy part of the binary. The pipeline below is reconstructed from the import-call sequence visible at the `[VNC] StreamThread started` lea (VA `0x14000f607`) and the GDI+ entries used by the surrounding code:

```c
// One-time init:
CoInitializeEx(NULL, COINIT_MULTITHREADED);
GdiplusStartupInput in = {1, NULL, FALSE, FALSE};
GdiplusStartup(&g_gdip_token, &in, NULL);

// Per-frame loop:
HDC win_dc = GetDC(ghost_hwnd);
HDC mem_dc = CreateCompatibleDC(win_dc);
HBITMAP hbmp = CreateCompatibleBitmap(win_dc, w, h);
SelectObject(mem_dc, hbmp);
PrintWindow(ghost_hwnd, mem_dc, PW_RENDERFULLCONTENT);

GpBitmap *gp_bmp;
GdipCreateBitmapFromHBITMAP(hbmp, NULL, &gp_bmp);

IStream *stream;
CreateStreamOnHGlobal(NULL, TRUE, &stream);
GdipSaveImageToStream(gp_bmp, stream, &CLSID_JPEG, &enc_params);

// Pull bytes back out of the IStream, length-prefix, and send():
HGLOBAL hg; GetHGlobalFromStream(stream, &hg);
SIZE_T size = GlobalSize(hg);
void *jpeg = GlobalLock(hg);
net_send_screenshot(jpeg, size, w, h);
GlobalUnlock(hg);

// Cleanup
stream->Release();
GdipDisposeImage(gp_bmp);
DeleteObject(hbmp);
DeleteDC(mem_dc);
ReleaseDC(ghost_hwnd, win_dc);
```

`PrintWindow` with the `PW_RENDERFULLCONTENT` flag (value `0x02`) is the key API choice: it forces the target window to render its full client area into the DC even when occluded or off-screen, which is exactly the condition our ghost window is in (cloaked via `SW_HIDE`). Without that flag, the resulting bitmap would be black. The `--disable-occlusion-tracking` flag passed to Chromium at launch (see Browser Piggyback section) is the complement: it prevents Chromium from suspending GPU work for the cloaked window between `PrintWindow` calls.

### Firefox `prefs.js` Patch (`chrome_patch_firefox_prefs` @ `0x140006910`)

The Firefox profile patch writes **two** preferences, not one. Both are stored as ASCII literals in `.rdata` and appended to the user's `prefs.js` via a C++ `std::ofstream` (the vtable pointers for the stream object are at VAs `0x140049F28`, `0x140049F58`, `0x140049F80`, `0x140049F90`).

The two preference lines are:

| VA | ASCII content |
|---|---|
| `0x1400490C8` | `user_pref("browser.sessionstore.resume_from_crash", false);\n` |
| `0x140049130` | `user_pref("toolkit.startup.max_resumed_crashes", -1);\n` |

In disassembly (with the `r12b` / `r13b` flags gating whether each line is appended):

```text
.text:14000759c  mov  r8d, 0x3c                            ; 60 bytes = first pref line length
.text:1400075a2  lea  rdx, [rip + 0x41b1f]                 ; -> "user_pref(\"browser.sessionstore.resume_from_crash\", false);\n"
.text:1400075ad  call <ofstream::operator<<>                ; append line 1
.text:1400075b7  mov  r8d, 0x36                            ; 54 bytes = second pref line length
.text:1400075bd  lea  rdx, [rip + 0x41b6c]                 ; -> "user_pref(\"toolkit.startup.max_resumed_crashes\", -1);\n"
.text:1400075c8  call <ofstream::operator<<>                ; append line 2
.text:14000762f  lea  rcx, [rip + 0x41b3a]                 ; -> "[CHROME] Firefox prefs.js patched: crash recovery disabled."
.text:140007636  call agent_log
```

The first preference disables the per-session crash-recovery dialog. The second is more aggressive: setting `toolkit.startup.max_resumed_crashes` to `-1` instructs Firefox to **never** offer to restore a previous session regardless of how many consecutive crashes have occurred. With both prefs in place, Firefox will silently start fresh after a crash and present no UI indication that the prior session ended abnormally.

The patch is unconditional and the inverse is never written. After the agent is removed, both `user_pref(...)` lines remain in the victim's `prefs.js` -- a persistent forensic artifact and a real degradation of Firefox's normal recovery behavior. Note the patch is **append-only**: if either preference was already set by the user or by another extension, the agent will write a duplicate `user_pref(...)` line, which Firefox will resolve by using the *last* one read (i.e., the malicious value wins).

### Remaining Open Questions

After the static disassembly pass above, two routines remain partially characterized and would benefit from a Hex-Rays decompile to close out:

1. **`vnc_stream_thread`** (function @ `0x14000F300`, anchor lea at VA `0x14000F607`). The frame loop and GDI+ pipeline are described above based on import-call patterns. What is *not* fully nailed down: the exact JPEG quality value passed to `GdipSaveImageToStream` and whether that value is mutable mid-session via an operator command. The encoder-parameter setup uses a static `EncoderParameters` struct that should be visible at a fixed `.rdata` offset.
2. **Network thread @ `0x14000E7B0`** -- the actual `getaddrinfo` + `connect` + handshake state machine. The bootstrap code spawns it via `CreateThread` with this entry point, but tracing the full request/response loop inside the thread requires walking another ~0x600 bytes of disassembly. The packet structure (1-byte opcode header, length-prefix layout, AUTH_LOGIN body) is described in the **Command-and-Control Protocol** section based on string anchors; the exact wire-format byte offsets need a Hex-Rays pass.

These two are nice-to-haves rather than blockers. The major behavioral claims in the analysis are now grounded in real disassembly.

---

## Config Extraction

The script `scripts/extract_config.py` (included with this analysis) statically extracts the full operational config from `.rdata` using `pefile`. It does not execute the binary and does not require IDA. The technique is straightforward because the agent stores everything in plain UTF-16LE: walk the `.rdata` section, build the wide-string list, then bucket each string by predicate (`endswith(".html")`, `isdigit()`, `wcsicmp` to a known anchor, etc.).

Output for the analyzed sample:

```json
{
  "c2_ip": "2.26.122[.]211",
  "c2_port_candidates": [],
  "bounce_html_filenames": [
    "%s\\chrome_update_manifest.html",
    "%sstudiosec_bounce.html"
  ],
  "task_xml_filename_fmt": "%schrome_task_%u.xml",
  "cleanup_batch": "%s\\ssv_cleanup.bat",
  "banner_class": "StudioSecVNC_Banner",
  "banner_title": "StudioSecVNC Banner",
  "anchor_class_a": "GSystem",
  "anchor_class_b": ".SecAnchor",
  "ghost_window_title": "StudioSecGhost",
  "browsers": [
    { "name": "Chrome",  "process": "chrome.exe",  "install_paths_observed": [ "..." ] },
    { "name": "Edge",    "process": "msedge.exe", "install_paths_observed": [ "..." ] },
    { "name": "Firefox", "process": "firefox.exe","install_paths_observed": [ "..." ] }
  ],
  "blocklist": [
    "cheatengine", "devenv.exe", "dnspy.exe", "ghidra",
    "ida.exe", "ida64.exe", "idaq.exe", "idaq64.exe",
    "ollydbg.exe", "processhacker.exe", "procexp.exe",
    "procmon.exe", "windbg.exe", "x32dbg.exe", "x64dbg.exe"
  ],
  "browser_args_chromium": "\"%s\" --app=\"%s\" --disable-infobars --hide-crash-restore-bubble --disable-backgrounding-occluded-windows --disable-renderer-backgrounding --disable-occlusion-tracking",
  "browser_args_firefox":  "\"%s\" -new-instance -no-remote -url \"%s\""
}
```

`c2_port_candidates` is empty for the wide-string scan, but the static analysis pass in **Decompiler-Level Reversing** above recovers the actual port directly from the `.text` section: `mov ebx, 0x115c` at VA `0x140005DEC` = port **4444**. A future revision of `extract_config.py` should add a `mov ebx, imm32` scan keyed off the format-string lea to fold this into the JSON output.

For tracking across new builds: re-run `extract_config.py` against each new sample. The script makes no assumptions specific to the analyzed SHA-256; it discovers strings by predicate.

---

## hVNC Technique: Per-Window Ghost Cloaking

The canonical hVNC pattern used by Pandora, DarkVNC, and LOBSHOT follows the same basic playbook: call `CreateDesktopW` to create a hidden desktop, call `SetThreadDesktop` on a new thread, and launch a fresh browser process on that invisible desktop. Everything that process renders is invisible to the victim because the desktop it is running on is never selected as the interactive desktop.

StudioSecGhost takes a different approach that avoids `CreateDesktopW` entirely.

Instead of a hidden desktop, it uses a hidden *window* inside an otherwise normal browser process. Here is the sequence:

1. The agent detects which of Chrome, Edge, or Firefox is installed by checking a hardcoded list of install paths.
2. It writes a minimal bounce HTML file to `%TEMP%` with the title `<title>StudioSecGhost</title>`. The body contains a `setTimeout` + `window.location.replace()` call that redirects to whatever URL the operator wants to pilot.
3. For Chromium-based browsers, it launches the browser with:
   ```
   --app="file://<bounce_html>"
   --disable-infobars
   --hide-crash-restore-bubble
   --disable-backgrounding-occluded-windows
   --disable-renderer-backgrounding
   --disable-occlusion-tracking
   ```
   The `--app` flag creates a minimal app-mode window with no tab bar. The other flags suppress any UI that might signal an anomaly to the victim. For Firefox, the equivalent is `-new-instance -no-remote -url <bounce_html>`.
4. An `EnumWindows` loop runs on a thread, calling `GetWindowTextW` on every top-level window until it finds one whose title matches `StudioSecGhost`.
5. On match, the agent calls `ShowWindow(SW_HIDE)` and `SetWindowPos(..., SWP_HIDEWINDOW)` to cloak the window from the task bar and the screen. The window continues to receive and render content; the victim just cannot see it.
6. The HWND is handed to the streaming subsystem, which calls `PrintWindow` on it each frame, feeds the result through `GdipCreateBitmapFromHBITMAP` + `GdipSaveImageToStream`, and sends the JPEG over the C2 TCP connection.

**Why this matters operationally:** because the agent launches the ghost browser against the victim's existing profile context (Chromium `--app=` without a `--user-data-dir` override uses the default `User Data` profile; Firefox `-new-instance -no-remote` selects the default profile identified via the `profiles.ini` lookup the agent has already performed for the prefs patch), the ghost window inherits whatever the profile already holds. The disassembly confirms the launch path uses the existing browser profile context, making profile-backed cookies and authenticated web sessions available to the launched browser process where those sessions are valid. Depending on browser configuration, autofill, and password-manager state, the operator may also reach saved credentials or autofill-backed login paths -- but this last step requires the operator to drive the UI and is not directly observable from static analysis. The point is that no separate credential-theft module is shipped: the implant gets browser-mediated access to whatever the profile is currently logged into.

**Why this matters for detection:** per-window cloaking is harder to detect with tools that look for hidden desktops. `CreateDesktopW` / `OpenDesktop` calls are a well-known indicator; `ShowWindow(SW_HIDE)` on a browser HWND is much less unusual in isolation. The window is invisible but its process and its GDI objects are live.

---

## Browser Piggyback and Firefox Patching

### Chromium Path

The agent builds a format string of the form:
```
"<browser_exe>" --app="<bounce_html>" --disable-infobars --hide-crash-restore-bubble
  --disable-backgrounding-occluded-windows --disable-renderer-backgrounding
  --disable-occlusion-tracking
```
and hands it to `CreateProcessW`. The `--disable-occlusion-tracking` flag is particularly telling: without it, Chromium will suspend rendering for occluded windows, which would stop the frame stream the moment the ghost window is hidden.

If Chrome or Edge is already running when the agent starts, the `[CHROME] Chrome already running. Piggybacking immediately.` log message fires and the agent skips the launch step, instead starting the `EnumWindows` search directly against the running process's windows.

### Firefox Path

Firefox does not support an `--app` flag, so the agent uses `-new-instance -no-remote -url <bounce_html>` instead. This creates an isolated Firefox instance (its own process tree, separate from any running Firefox) pointed at the bounce HTML.

Before launching, the agent patches the Firefox profile to suppress both the crash-recovery dialog and the session-restore prompt that would otherwise appear on next startup. It:
1. Reads `%APPDATA%\Mozilla\Firefox\profiles.ini` to locate the default profile directory.
2. Opens `prefs.js` in that directory for append.
3. Appends **two** `user_pref(...)` lines (full disassembly in **Decompiler-Level Reversing**):
   - `user_pref("browser.sessionstore.resume_from_crash", false);`
   - `user_pref("toolkit.startup.max_resumed_crashes", -1);`

This is a hardcoded prefs patch executed unconditionally for any Firefox profile found. The change is permanent: both lines persist in the victim's `prefs.js` after the agent is removed, unless the user manually edits the file to delete them.

### Hot-Swap

The agent supports operator-commanded browser switching via a `CMD` that triggers `[CHROME] Switching browser: %ls -> %ls`. On receipt, the agent tears down the current ghost lifecycle, closes the stale HWND, and restarts the lifecycle loop targeting the newly specified browser.

---

## Persistence

The agent installs persistence via Windows Scheduled Tasks using XML import (`schtasks /Create /XML`). The XML *staging file* is rendered to `%TEMP%\chrome_task_<random>.xml`; the random component varies per replica slot, and multiple slots are deployed in parallel for redundancy. The XML filename is **not** the scheduled-task name -- it is the on-disk artifact that `schtasks` consumes to create the task entry.

The scheduled-task names themselves masquerade as legitimate Windows / Google update tasks. Public sandbox telemetry for this SHA-256 observed task activity under the names `Google\Update\CrashReportTask`, `Microsoft\Windows\DeviceSync\Routine`, and repeated `schtasks /Query` checks against `Microsoft\Windows\AppID\PolicyConverter`. Treat the XML filename as a file-system IOC and the task names as separate persistence IOCs (see the **IOC Appendix**).

The task XML includes two triggers:

| Trigger | Configuration |
|---|---|
| `LogonTrigger` | Enabled, Delay=PT1M |
| `TimeTrigger` | Interval=PT2M, Duration=P1D, StopAtDurationEnd=false |

Task settings:

| Setting | Value |
|---|---|
| `MultipleInstancesPolicy` | Parallel |
| `DisallowStartIfOnBatteries` | false |
| `StopIfGoingOnBatteries` | false |
| `ExecutionTimeLimit` | PT0S (no limit) |
| `StartWhenAvailable` | true |
| `RestartOnFailure` | Interval=PT1M, Count=999 |

The `RestartOnFailure Count=999` is the agent's primary resilience mechanism: if the process crashes or is killed, the task scheduler restarts it up to 999 times with a one-minute gap between attempts.

On top of scheduled tasks, a dedicated watchdog thread runs inside the agent process itself. It periodically checks each replica slot -- both the binary on disk and the corresponding scheduled task entry -- and redeploys any that have been removed. The log string `[INIT] Watchdog restored replica slot %d` fires each time it repairs a slot.

The agent copies itself to replica slots under `%TEMP%` and/or `%APPDATA%` paths. The exact slot layout is inferred from the `Replica deploy failed slot %d` / `Replica deployed: slot %d` log strings; at least two slots are deployed.

---

## Command-and-Control Protocol

The agent communicates over raw TCP to `2.26.122[.]211:4444`. The IP is stored as a UTF-16LE `.rdata` literal at VA `0x140049BB8`, while the port is recovered from `.text` as the immediate operand `0x115c` (4444 decimal) of the `mov ebx, 0x115c` instruction at VA `0x140005DEC`. Public sandbox telemetry for this SHA-256 records outbound TCP to `2.26.122[.]211:4444` at runtime, corroborating both the IP and port via a second method. There is no TLS. The wire format is a custom binary protocol with a 1-byte opcode header.

### Session Lifecycle

```
Client                              C2
  |--- TCP connect ------------------>|
  |<-- Handshake challenge -----------|
  |--- Handshake response ----------->|
  |<-- Handshake ACK -----------------|
  |--- AUTH_LOGIN (operator tag,      |
  |    browser count, active index) ->|
  |<-- CMD_* -------------------------|
  |--- responses, frames ------------>|
  |    [reconnect loop with backoff]
```

The AUTH_LOGIN packet contains the operator tag as a UTF-16LE string, the count of detected browsers, and the index of the currently active browser. This allows the C2 to display a browser inventory to the operator at session open.

### Client-to-Server Packets

| Packet | Description |
|---|---|
| `AUTH_LOGIN` | Operator tag + browser inventory |
| `BROWSERS_UPDATED` | Sent after `CMD_RE_DETECT_BROWSERS` |
| `SYSTEM_INFO` | OS version, display version, CPU name, username, disk/memory |
| Screenshot frame | JPEG blob with width/height header; sent every tick when streaming is active |

### Server-to-Client Commands

| Command | Effect |
|---|---|
| `CMD_START_VIEWING` | Begin the frame-stream loop |
| `CMD_STOP_VIEWING` | Pause frame stream |
| `CMD_SCREENSHOT_REQUEST` | Send a single frame on demand |
| `CMD_RE_DETECT_BROWSERS` | Re-run browser detection; send `BROWSERS_UPDATED` |
| `CMD_UPLOAD_EXECUTE` | Receive filename + bytes, drop to disk, `CreateProcessW`, return exit code |
| `CMD_UNINSTALL` | Full removal sequence |
| Mouse injection | Send `VK` code + character + cursor position |
| Keyboard injection | Send `VK` code + character |

`CMD_UPLOAD_EXECUTE` is an arbitrary remote-execution primitive: the operator pushes any binary, the agent writes it to disk and runs it under the current user context. Exit code is returned in the reply packet.

### JPEG Frame Pipeline

```
PrintWindow(ghost_hwnd)
  --> BitBlt into compatible DC
  --> GdipCreateBitmapFromHBITMAP
  --> GdipSaveImageToStream  (JPEG, quality preset set by operator)
  --> CreateStreamOnHGlobal + COM IStream
  --> length-prefixed TCP send
```

The disassembly suggests the JPEG quality parameter is loaded from a per-session field rather than a build-time constant -- consistent with operator-side control -- but the exact opcode that mutates the field has not been traced and the claim should be treated as suggestive pending a dynamic run (see **Remaining Open Questions**). A packet-size guard tied to the log string `[NET] Oversized packet dropped` is present and rejects malformed inbound frames.

---

## Victim Overlay

While the operator session is active, the agent creates a fullscreen layered window using the class `StudioSecVNC_Banner` and the title `StudioSecVNC Banner`. The window displays:

```
  WARNING!  SECURITY AUDIT IN PROGRESS.
```

in Segoe UI on a dark background, rendered via `DrawTextW` with a `STATIC` control. The window is created with `WS_EX_LAYERED` and `SetLayeredWindowAttributes` so it can be rendered above all other windows without capturing input focus.

The social engineering intent is transparent: the banner convinces the victim that an authorized security audit is underway, discouraging them from interacting with their machine while the operator pilots the ghost browser.

---

## Kill Chain

![StudioSecGhost 8-stage kill chain](/assets/images/posts/studiosecghost/killchain.png)

Stages 0-3 are sequential; stages 4-7 run concurrently as independent threads spawned during bootstrap. Stage 8 is invoked on demand by the operator.

**Stage 0 -- Drop and Launch:** Dropper delivers `ahy.exe` (353 KB, x64, compiled 2026-05-17).

**Stage 1 -- Self-Check and Anti-Analysis:** `CreateMutexW` for single-instance enforcement. `QueryPerformanceCounter`-based 1000-iteration timing trip-wire detects live single-stepping. `NtQueryInformationProcess` (resolved via `GetModuleHandleW("ntdll.dll")` + `GetProcAddress`) reads the agent's own parent PID; `QueryFullProcessImageNameW` returns the parent's image path; the basename is run through 15 sequential `wcsstr` substring matches against debugger / analyst tool names. Any hit triggers a clean `ReleaseMutex` and process exit, with no C2 beacon and no artifact cleanup. See Anti-Analysis Notes for the full table.

**Stage 2 -- Persistence:** Multiple replica copies are dropped to disk; `chrome_task_<n>.xml` files are rendered (one per replica slot) and imported via a child `schtasks /Create /XML` invocation. Triggers: `LogonTrigger` + `TimeTrigger Interval=PT2M Duration=P1D`. Settings: `RestartOnFailure Count=999, Interval=PT1M`.

**Stage 3 -- Bootstrap:** `GdiplusStartup`, `WSAStartup`. `RegisterClassExW` for both the anchor window (`GSystem` / `.SecAnchor`) and the banner window (`StudioSecVNC_Banner`). Spawns the four concurrent worker threads listed below.

**Stage 4 (thread) -- C2 Network:** `getaddrinfo` + `connect` to `2.26.122[.]211:<port>`. Custom binary handshake; `AUTH_LOGIN` with operator tag and browser inventory; command-dispatch loop; reconnect with backoff on close.

**Stage 5 (thread) -- Browser Lifecycle:** Detect installed browser; write bounce HTML; for Firefox, patch `prefs.js`; launch the browser with suppression flags (Chromium) or `-new-instance -no-remote` (Firefox); poll for hot-swap commands.

**Stage 6 (thread) -- Ghost-Window Acquisition:** `EnumWindows` + `GetWindowTextW` polling for a top-level window titled `StudioSecGhost`. On match: `ShowWindow(SW_HIDE)` + `SetWindowPos(SWP_HIDEWINDOW)`. The HWND is handed off to the streaming subsystem.

**Stage 7 (thread) -- Operator Session:** StreamThread runs `PrintWindow --> GDI+ --> JPEG --> TCP send` loop into the C2 thread's outbound queue. Banner thread paints the `StudioSecVNC_Banner` victim overlay. Watchdog thread monitors replica slots and redeploys missing copies. Net thread dispatches mouse/keyboard injection, `CMD_UPLOAD_EXECUTE`, `CMD_RE_DETECT_BROWSERS`, and `CMD_UNINSTALL` as they arrive.

**Stage 8 -- Self-Removal (on `CMD_UNINSTALL`):** `schtasks /Delete` for each known task slot; write `ssv_cleanup.bat` to `%TEMP%`; launch `cmd.exe /C ssv_cleanup.bat`; `WM_CLOSE` to ghost and anchor windows; process exits.

---

## Anti-Analysis Notes

### Process Blocklist (Parent-Process Inspection)

A complete walk of the anti-analysis routine is in the **Decompiler-Level Reversing** section above. Summary:

- The agent does **not** enumerate the running process list with `CreateToolhelp32Snapshot`. It calls `NtQueryInformationProcess` (resolved at runtime via `GetModuleHandleW("ntdll.dll")` + `GetProcAddress`) to read its **own parent process's PID** from `PROCESS_BASIC_INFORMATION.InheritedFromUniqueProcessId`.
- That parent PID is opened with `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, ...)`, `QueryFullProcessImageNameW` produces the full path, and a `PathFindFileNameW`-equivalent strips the directory.
- The bare parent filename is then run through 15 sequential `wcsstr(parent_name, blocklist[i])` calls. Any non-NULL return triggers the silent-exit path at VA `0x1400059EF`.

The 15 blocklist literals (UTF-16LE, contiguous array in `.rdata`):

| # | VA | Literal | Tool |
|---|---|---|---|
| 1 | `0x140047E40` | `ollydbg.exe` | OllyDbg |
| 2 | `0x140047E58` | `x64dbg.exe` | x64dbg |
| 3 | `0x140047E70` | `x32dbg.exe` | x32dbg (x86 build) |
| 4 | `0x140047E88` | `windbg.exe` | WinDbg |
| 5 | `0x140047EA0` | `ida.exe` | IDA (classic) |
| 6 | `0x140047EB0` | `ida64.exe` | IDA (x64) |
| 7 | `0x140047EC8` | `idaq.exe` | IDA Qt (x86) |
| 8 | `0x140047EE0` | `idaq64.exe` | IDA Qt (x64) |
| 9 | `0x140047EF8` | `devenv.exe` | Visual Studio host |
| 10 | `0x140047F10` | `processhacker.exe` | Process Hacker |
| 11 | `0x140047F38` | `procmon.exe` | Sysinternals Process Monitor |
| 12 | `0x140047F50` | `procexp.exe` | Sysinternals Process Explorer |
| 13 | `0x140047F68` | `dnspy.exe` | dnSpy |
| 14 | `0x140047F80` | `ghidra` | Ghidra (substring) |
| 15 | `0x140047F90` | `cheatengine` | Cheat Engine (substring) |

Comparison is **case-sensitive substring match** (`wcsstr`, not `_wcsicmp`). The blocklist is therefore brittle against renamed analyst tools but immune to most case-folding tricks because the canonical executable filenames are already lowercase on disk.

### Timing Check (Pre-Blocklist)

Before the parent-process check runs, the agent measures a 1000-iteration arithmetic loop with `QueryPerformanceCounter` and exits if the elapsed time exceeds **0.5 seconds** (threshold stored as a `double` at VA `0x14004ABE8`). See the disassembly in **Decompiler-Level Reversing** for the exact sequence. This blocks live single-stepping but is bypassed by any sandbox that runs the binary at full instruction speed.

### Debugger-API Imports

`KERNEL32!IsDebuggerPresent` and `KERNEL32!CheckRemoteDebuggerPresent` are present in the import table. Their call sites have not been mapped in this build, so we cannot assert they are actively invoked from the bootstrap path; given the otherwise methodical anti-analysis posture they are unlikely to be dead imports, but treating them as confirmed runtime checks would overstate the static evidence.

### Response on Detection

The log string `[INIT] Agent already running. Exiting.` and the single-instance mutex suggest the exit path is a clean process exit with no beaconing or alerting of the C2 on analyst detection. The binary does not destroy any artifacts before exiting.

---

## Observations and Attribution Notes

As of 2026-05-19, the string `StudioSecGhost` does not appear in any public threat intelligence source. The companion strings `StudioSecVNC_Banner`, `.SecAnchor`, and `ssv_cleanup.bat` also return zero results. MalwareBazaar carries the SHA-256 but lists it as `Threat unknown`; multi-engine sandbox detections use generic labels (`Trojan.Win64.*`, `HVNC.Generic`) rather than a family name. This post therefore names the family from the binary's own internal marker: **StudioSecGhost**.

**Delivery context (not family attribution).** MalwareBazaar metadata associates this SHA-256 with `dropped-by-amadey` and exposes a web-download source URL of the form `hxxp://91.92.242[.]236/files-129312398/files/file_e353c81a9a32e76e.exe`. This indicates Amadey (a well-known commodity loader) was observed delivering the agent in at least one campaign, but it does **not** make StudioSecGhost part of the Amadey family -- Amadey is the loader, StudioSecGhost is the post-loader payload. Treat the relationship as a delivery pairing only.

**No encryption in the wire protocol.** The agent communicates over raw TCP with no TLS wrapper, no symmetric encryption, and no challenge-response key exchange. Every frame and every command is transmitted in plaintext. This is unusual for a tool that is otherwise carefully designed.

**C2 infrastructure.** The single observed C2 IP, `2.26.122[.]211`, is announced by AS201988 (VPSPay, Helsinki, Finland). The abuse contact for the ASN is `abuse@vpspay[.]cloud`. Independent reputation history for this ASN is not asserted here; treat the IP as a single-VPS pivot point only. The destination port is **TCP/4444**, recovered statically from `.text` as the immediate operand of `mov ebx, 0x115c` at VA `0x140005DEC` (full validation chain in **Methodology and Toolchain**). The wide-string config extractor did not surface the port because it is not stored as a wide string in `.rdata` -- it lives as a code-section immediate. The disassembly pass picked it up directly.

**Operator-tag naming.** The `AUTH_LOGIN` packet includes an `operator tag` field (`[NET] AUTH_LOGIN sent: '%ls'`). This suggests a panel-based C2 with named operator accounts -- consistent with a for-hire or multi-operator model rather than a single-actor tool.

**Version info is a placeholder.** `ProductName=ahy`, `FileDescription=ahy`, `OriginalFilename=ahy.exe`, `FileVersion=1.0.0.0`. The version block was left at MSVC defaults with all string fields filled with the bare project name `ahy`. There is no company name, no copyright, and no internal product description -- the builder did not bother to populate the PE version resource beyond what `link.exe` requires.

**Authenticode.** The binary is unsigned. The PE `SECURITY` data directory is empty (VA=0, Size=0). A check that flagged the sample on one public source as having a signing-related indicator does not survive direct inspection -- treat it as a sandbox heuristic false positive.

---

## Public Sandbox Corroboration

After the static writeup was completed, public sandbox coverage appeared for the same SHA-256. The sandbox results do not provide a stable family name; MalwareBazaar lists the sample as `Threat unknown`, and vendor labels remain generic. The dynamic data does, however, corroborate several of the static-analysis findings, raising the confidence level on each from single-method (disassembly) to dual-method (disassembly + runtime telemetry):

- **C2 confirmed.** `ahy.exe` contacts `2.26.122[.]211:4444` over TCP at runtime, matching both the statically recovered IP (`.rdata` literal at VA `0x140049BB8`) and the port (`mov ebx, 0x115c` at VA `0x140005DEC`).
- **Browser profile access confirmed.** The process accesses Chrome profile paths under `%LOCALAPPDATA%\Google\Chrome\User Data\...`, including the bounce HTML drop at `%LOCALAPPDATA%\Google\Chrome\User Data\chrome_update_manifest.html` and reads against `Default\Preferences`. This supports the browser-profile piggybacking model: the launched browser process uses the victim's existing User Data profile.
- **Bounce HTML title confirmed.** Runtime strings expose `<title>StudioSecGhost</title>` in the dropped HTML, matching the static finding that this is both the search target for the ghost-window acquisition loop and the family's internal codename.
- **Scheduled-task XML staging confirmed; task names differ from filenames.** `%TEMP%\chrome_task_<random>.xml` is written and consumed by `schtasks /Create /XML`. The observed task entries, however, use camouflage names: `Google\Update\CrashReportTask`, `Microsoft\Windows\DeviceSync\Routine`, and repeated `schtasks /Query` against `Microsoft\Windows\AppID\PolicyConverter`. The original draft conflated the XML staging filename with the task name; this is now corrected in the **Persistence** section and the **IOC Appendix**.
- **Delivery via Amadey observed.** MalwareBazaar tags the sample `dropped-by-amadey` with a delivery URL of `hxxp://91.92.242[.]236/files-129312398/files/file_e353c81a9a32e76e.exe`. Treat as delivery context, not family attribution.

The article keeps its MITRE ATT&CK table restricted to behavior directly supported by static reversing or corroborated runtime telemetry. Generic sandbox-mapped techniques (every API category mechanically mapped to an ATT&CK ID) are not imported wholesale.

---

## Code Weaknesses

1. **No wire encryption.** All C2 traffic -- auth tokens, operator commands, JPEG frames, file payloads -- transits in cleartext over raw TCP. A network tap or MITM between the agent and `2.26.122[.]211` exposes the full session without any decryption step.

2. **Plaintext config in `.rdata`.** Every operational string (C2 IP format, log prefixes, browser paths, window class names, task XML filename template, cleanup batch name) is stored as unencrypted UTF-16LE. A `strings -e l` run on the binary recovers the entire config without executing a single instruction.

3. **Hardcoded C2 IP.** The IP `2.26.122[.]211` appears verbatim in `.rdata`. A single takedown of the VPS severs every deployed instance simultaneously. There is no DGA, no backup domain, and no fast-flux mechanism.

4. **Process-name blocklist as the only anti-analysis gate.** The check is trivially bypassed by renaming the analyst tool executable. `x64dbg_renamed.exe` would not match. The blocklist also does not cover a number of common analysis tools: WireShark, Fiddler, API Monitor, Cutter, Binary Ninja, PE-bear.

5. **Single-string ghost-window title.** The entire browser piggybacking technique depends on the window title `StudioSecGhost` being findable via `GetWindowTextW`. Changing this title in a recompile is a one-character edit. In the current build, it is a trivially searchable indicator.

6. **Persistence via `schtasks` command visible in shell history.** The agent calls `CreateProcessW` to execute `schtasks /Create /TN ... /XML ...`. This invocation will appear in `cmd.exe` process creation events (Windows Security Event ID 4688) and in any EDR that logs process command lines. The XML-import approach does not avoid the child process.

7. **`ssv_cleanup.bat` on disk before execution.** The self-delete sequence writes the batch file to `%TEMP%` and then launches it. There is a window between the write and the execution where the batch file exists on disk and can be captured.

8. **Firefox `prefs.js` patch is permanent and writes two prefs.** Both `browser.sessionstore.resume_from_crash = false` and `toolkit.startup.max_resumed_crashes = -1` are appended unconditionally and never restored on uninstall. Post-incident, the victim's Firefox profile retains both modifications. A forensic examiner can spot both lines as `user_pref(...)` entries at the tail of `prefs.js`.

9. **Operator tag in plaintext AUTH_LOGIN.** The operator tag sent in `AUTH_LOGIN` is a UTF-16LE string transmitted without encryption. Any intermediate network observer can read the tag, which may contain identifying or operational information useful to investigators.

10. **No HTTPS or domain fronting for C2.** The combination of a static IP, a non-standard raw TCP port, and no TLS makes the agent trivially detectable at the network perimeter. Any IDS/IPS rule that flags JPEG SOI bytes on non-HTTP ports or a direct connection to the C2 IP will catch this variant.

---

## IOC Appendix

### Network

| Type | Value | Notes |
|---|---|---|
| IP | `2.26.122[.]211` | C2; AS201988 (VPSPay, Helsinki, FI). Corroborated by public sandbox telemetry. |
| Port | TCP/4444 | Hardcoded in `.text` as `mov ebx, 0x115c` at VA `0x140005DEC`. Corroborated by public sandbox telemetry. |
| ASN | AS201988 | VPSPay / vpspay[.]cloud |
| Protocol | Raw TCP, custom binary, no TLS | 1-byte opcode header, length-prefix framing |
| Abuse contact | `abuse@vpspay[.]cloud` | |
| Delivery URL (observed) | `hxxp://91.92.242[.]236/files-129312398/files/file_e353c81a9a32e76e.exe` | Web-download stage observed in MalwareBazaar metadata; tagged `dropped-by-amadey`. Delivery context only. |

### File and Registry

| Type | Value | Notes |
|---|---|---|
| Drop path | `%TEMP%\studiosec_bounce.html` | Bounce HTML (default name) |
| Drop path | `%TEMP%\chrome_update_manifest.html` | Bounce HTML (alternative name) |
| Drop path (XML staging) | `%TEMP%\chrome_task_<random>.xml` | Temporary XML file consumed by `schtasks /Create /XML`; **not** the scheduled-task name |
| Drop path | `%TEMP%\ssv_cleanup.bat` | Self-delete batch |
| Window class (anchor) | `GSystem` | |
| Window class (anchor) | `.SecAnchor` | |
| Window class (banner) | `StudioSecVNC_Banner` | |
| Window title (banner) | `StudioSecVNC Banner` | |
| Registry read | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductName` | For SYSTEM_INFO packet |
| Registry read | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\DisplayVersion` | For SYSTEM_INFO packet |
| Registry read | `HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\0\ProcessorNameString` | For SYSTEM_INFO packet |

### Scheduled Tasks (observed)

| Type | Value | Notes |
|---|---|---|
| XML staging path | `%TEMP%\chrome_task_<random>.xml` | File-system IOC; consumed by `schtasks /Create /XML` |
| Observed task name | `Google\Update\CrashReportTask` | Public sandbox observation |
| Observed task name | `Microsoft\Windows\DeviceSync\Routine` | Public sandbox observation |
| Observed task name / query target | `Microsoft\Windows\AppID\PolicyConverter` | Repeated `schtasks /Query` checks observed |

### Hashes

| Algorithm | Hash |
|---|---|
| MD5 | `c1b29c991b45789bda71074cd41a0ca8` |
| SHA-1 | `0590fd821c037b404527566eae38d63519ee6a11` |
| SHA-256 | `5940c41ab003399680a04d726587eed242e4ad8969abe4b5617d712ff190a852` |
| Imphash | `26edff0935c20dff74e040648243639a` |

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Notes |
|---|---|---|---|
| Execution | Command and Scripting Interpreter: Windows Command Shell | T1059.003 | `cmd.exe /C ssv_cleanup.bat` self-delete sequence |
| Persistence | Scheduled Task / Job: Scheduled Task | T1053.005 | `schtasks /Create /XML` with LogonTrigger + TimeTrigger |
| Persistence | Boot or Logon Autostart Execution | T1547 | LogonTrigger fires on each user logon (Delay=PT1M) |
| Defense Evasion | Masquerading: Match Legitimate Name or Location | T1036.005 | Scheduled task names masquerade as legitimate Windows / Google update tasks |
| Defense Evasion | Indicator Removal: File Deletion | T1070.004 | `ssv_cleanup.bat`, scheduled task XML, and replica files removed on `CMD_UNINSTALL` |
| Defense Evasion | Hide Artifacts: Hidden Window | T1564.003 | `ShowWindow(SW_HIDE)` + `SetWindowPos(SWP_HIDEWINDOW)` on the ghost browser HWND |
| Defense Evasion | Debugger Evasion | T1622 | Anti-debug API imports paired with process blocklist exit |
| Discovery | Process Discovery | T1057 | `CreateToolhelp32Snapshot` + `Process32Next` used by Chrome lifecycle manager to detect running browsers. Analyst-tool blocklist uses `NtQueryInformationProcess` against parent PID instead. |
| Discovery | System Information Discovery | T1082 | Reads `ProductName`, `DisplayVersion`, `ProcessorNameString` for `SYSTEM_INFO` |
| Collection | Screen Capture | T1113 | `PrintWindow` + GDI+ JPEG frame streaming |
| Collection | Input Capture: GUI Input Capture | T1056.002 | Mouse position + click injection to ghost HWND |
| Collection | Browser Session Hijacking | T1185 | Ghost window shares User Data profile with victim's live browser |
| Command and Control | Application Layer Protocol: Non-Application Layer Protocol | T1095 | Custom binary protocol over raw TCP, no HTTP/TLS envelope |
| Command and Control | Non-Standard Port | T1571 | Raw TCP to TCP/4444; port recovered from `.text` as `mov ebx, 0x115c` at VA `0x140005DEC` |
| Command and Control | Ingress Tool Transfer | T1105 | `CMD_UPLOAD_EXECUTE` drops and runs arbitrary operator-supplied binaries |
| Exfiltration | Exfiltration Over C2 Channel | T1041 | JPEG screenshots and `SYSTEM_INFO` exfil over the same raw-TCP C2 connection |

---

## YARA Rules

The following rules are production-ready. The main PE rule uses composite conditions to minimize false positives: it requires the PE header, the AMD64 machine type, at least one of the three primary identity strings, at least three of the ten operational log-format strings, and at least one of the four known filesystem-artifact strings.

Rules are available for download at [taogoldi/YARA/hvnc/studiosecghost](https://github.com/taogoldi/YARA/tree/main/hvnc/studiosecghost).

```yara
// StudioSecGhost hVNC + browser-piggyback agent
// Author: taogoldi
// Date:   2026-05-19
// TLP:    TLP:CLEAR
// Hash:   5940c41ab003399680a04d726587eed242e4ad8969abe4b5617d712ff190a852

import "pe"

rule StudioSecGhost_HVNC_Agent
{
    meta:
        author      = "taogoldi"
        version     = 1
        date        = "2026-05-19"
        hash        = "5940c41ab003399680a04d726587eed242e4ad8969abe4b5617d712ff190a852"
        tlp         = "TLP:CLEAR"
        family      = "StudioSecGhost"
        description = "Native x64 hidden-VNC agent that piggybacks on real Chrome/Edge/Firefox and cloaks a sibling ghost window."

    strings:
        $bid_title          = "<html><head><title>StudioSecGhost</title></head><body>" ascii
        $bid_search         = "StudioSecGhost" wide
        $bid_banner_class   = "StudioSecVNC_Banner" wide
        $bid_banner_title   = "StudioSecVNC Banner" wide
        $bid_anchor_a       = "GSystem" wide
        $bid_anchor_b       = ".SecAnchor" wide

        $log_chrome_pigg    = "[CHROME] Chrome already running. Piggybacking immediately." ascii
        $log_chrome_ghost   = "[CHROME] Found ghost among hidden windows: HWND=%p" ascii
        $log_chrome_prefs   = "[CHROME] Firefox prefs.js patched: crash recovery disabled." ascii
        $log_chrome_bounce  = "[CHROME] Failed to resolve bounce path." ascii
        $log_vnc_stream     = "[VNC] StreamThread started (%dx%d)%s." ascii
        $log_vnc_capture    = "[VNC] WindowCapturer: init OK (%dx%d), HWND=%p." ascii
        $log_net_auth       = "[NET] AUTH_LOGIN sent: '%ls' (browsers: %d, active: %d)" ascii
        $log_net_target     = "[NET] AgentNetwork started. Target: %ls:%u" ascii
        $log_init_replica   = "[INIT] Replica deployed: slot %d" ascii
        $log_init_watchdog  = "[INIT] Watchdog restored replica slot %d" ascii

        $art_bounce_a       = "studiosec_bounce.html" wide
        $art_bounce_b       = "chrome_update_manifest.html" wide
        $art_task_xml       = "chrome_task_%u.xml" wide
        $art_cleanup        = "ssv_cleanup.bat" wide

        $banner_text        = "  WARNING!  SECURITY AUDIT IN PROGRESS.  " wide
        $browser_args       = "--hide-crash-restore-bubble --disable-backgrounding-occluded-windows --disable-renderer-backgrounding --disable-occlusion-tracking" wide

    condition:
        uint16(0) == 0x5a4d
        and pe.machine == pe.MACHINE_AMD64
        and pe.imports("mscoree.dll") == 0
        and pe.imports("gdiplus.dll", "GdipSaveImageToStream")
        and pe.imports("WS2_32.dll", "send")
        and (
            $bid_search
            or $bid_title
            or $bid_banner_class
        )
        and 3 of ($log_*)
        and any of ($art_*)
}

rule StudioSecGhost_Bounce_HTML
{
    meta:
        author      = "taogoldi"
        version     = 1
        date        = "2026-05-19"
        tlp         = "TLP:CLEAR"
        family      = "StudioSecGhost"
        description = "Dropped bounce HTML. Lives at %TEMP%\\studiosec_bounce.html or %TEMP%\\chrome_update_manifest.html."

    strings:
        $a = "<html><head><title>StudioSecGhost</title></head><body>" ascii
        $b = "window.location.replace(" ascii
        $c = "setTimeout(function(){" ascii

    condition:
        filesize < 4KB and all of them
}
```

Suricata rules covering the C2 IP and the JPEG-on-raw-TCP signature are available at [taogoldi/analysis_data/studiosecghost_may_2026/detection](https://github.com/taogoldi/analysis_data/tree/main/studiosecghost_may_2026/detection).

---

## Conclusion

StudioSecGhost is a native x64 hidden-VNC agent built around a novel browser piggybacking technique that avoids the well-monitored `CreateDesktopW` / `SetThreadDesktop` pattern used by every major prior hVNC family. By launching a real, installed Chromium or Firefox process, navigating it to a titled bounce page, and cloaking the resulting window per-HWND rather than per-desktop, the agent obtains an operator-controlled browser that is already authenticated to all of the victim's active web sessions. The ghost window shares the victim's User Data profile directory: no credential extraction step is needed.

The persistence design is solid: multiple replica slots, a dual-trigger scheduled task with 999-restart failsafe, and an in-process watchdog combine to make manual removal without knowing all slot numbers genuinely difficult for a non-technical victim. The Firefox prefs-patching is a permanent side effect that survives uninstallation.

Against that, the operational security is poor. The wire protocol is unauthenticated cleartext. The entire config -- C2 IP, window class names, artifact filenames, log prefixes -- sits unobfuscated in `.rdata` and is recoverable with `strings -e l`. The process blocklist is bypassed by renaming any analyst tool executable. The single static C2 IP makes infrastructure-level blocking straightforward.

The family is unattributed as of the publication date. The operator-tag field in AUTH_LOGIN suggests this is a panel-based tool with multiple operators rather than a single-actor implant. The `ahy.exe` filename and placeholder version info offer no further pivot. The C2 is announced by AS201988 (VPSPay) out of Helsinki; no reputation claim is made for the ASN here, but the single static IP is the most actionable pivot point we have for this build.

Detection teams should prioritize the YARA rule for memory and filesystem scanning, the Suricata IP rule for perimeter blocking, and the scheduled task XML drop (`chrome_task_<n>.xml` in `%TEMP%`) as a host-based hunt artifact. The Firefox `prefs.js` modification is a useful forensic indicator when investigating potential compromised hosts post-incident.

---

*taogoldi -- TLP:CLEAR -- 2026-05-19*
