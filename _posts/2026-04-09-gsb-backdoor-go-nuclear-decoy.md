---
title: "Backdoor.Win64.Gsb: A Go Implant Hiding Behind Nuclear Reactor Simulations"
permalink: /blog/gsb-backdoor-go-nuclear-decoy/
date: 2026-04-09 00:00:00 +0000
categories: [malware-reversing, threat-intel]
tags: [golang, backdoor, gsb, gcleaner, go-malware, static-analysis, yara, radare2, obfuscation]
image: /assets/images/social/gsb-backdoor-card.png
description: "Reversing a novel Go-compiled backdoor distributed by GCleaner that uses nuclear reactor physics type names and CJK-obfuscated function names to evade detection — with only 15.8% VirusTotal detection despite allocating RWX memory and calling SyscallN directly."
---

Something strange showed up at the top of my triage queue yesterday morning. A 1.4MB PE binary, tagged as a Go executable, zero family matches in our similarity engine, and a risk score that pinned the needle. My first thought was that it was mislabeled — Go binaries are bulky by nature, and the automated packer detection had flagged it as MPRESS, which turned out to be a false positive. The entropy was normal. The sections looked standard. Nothing screamed malware at a glance.

Then I opened the strings.

Mixed in with the usual Go runtime noise were type names I had never seen in a malware sample before: `BeamEnvelope`, `ControlDrum`, `FuelRodBundle`, `XenonTransientTable`, `dopplerCoefficientNeg`. These are real nuclear reactor physics terms — control drums are used in space reactor designs, xenon transients affect reactor power output, fuel rod bundles are core structural elements. Either someone was accidentally compiling a nuclear engineering simulation with malicious intent, or this was the most creative obfuscation scheme I'd encountered.

It was the latter.

Buried under the reactor math, I found `syscall.LoadLibrary`, `syscall.GetProcAddress`, `syscall.SyscallN`, and a `VirtualAlloc` call requesting `PAGE_EXECUTE_READWRITE` memory. The function names weren't in English — they were randomized Chinese characters. The build path pointed to a framework called `Factory-v3`. And the binary was signed with a valid Authenticode certificate from `www.glass.com`.

This post documents the full teardown: how I mapped the obfuscation layers, identified the malicious functions hiding inside reactor simulation code, traced the kill chain back to a GCleaner Pay-Per-Install distribution network, and extracted the C2 configuration. At the time of analysis, only 12 out of 76 VirusTotal engines detected this sample.

---

## Sample

| Property | Value |
|---|---|
| **SHA-256** | `072533c1d31d83b056a1a9f4174a23763c53597df1c89ad9c545df2c3bb35f5e` |
| **MD5** | `650c00bed1b3ce7db2e8ddfb949a5576` |
| **SHA-1** | `350c7b55675d1cd6903ac8f12dcdceace13f1d43` |
| **File Size** | 1,448,064 bytes (1.38 MB) |
| **Format** | PE32+ x86-64, Windows GUI subsystem |
| **Language** | Go 1.24.5 |
| **Sections** | 8 (including `.symtab` — Go symbol table) |
| **Overlay** | 2,176 bytes — Authenticode signature |
| **Certificate** | Valid, issued to `www.glass.com` (Country Unknown) |
| **Timestamp** | 0 (zeroed — deliberately stripped) |
| **Build Path** | `Factory-v3/builder/temp/7061c16a7a05b72f2cf8d5e57bdcc1d0/main.go` |
| **Compiled** | ~2026-04-06 (first seen date) |
| **VT Detection** | 12/76 (15.8%) |

**Identification**: Backdoor.Win64.Gsb (Kaspersky dynamic detection). Distributed as a second-stage payload by the GCleaner Pay-Per-Install loader.

---

## Kill Chain

![Kill chain](/assets/images/posts/gsb/1_killchain.png)
*GCleaner PPI → Go backdoor drop → reactor cover code → payload build → VirtualAlloc RWX → dynamic API resolution → SyscallN → C2 connection*

The sample doesn't arrive on its own. According to [Loader Insight Agency](https://loaderinsight.agency), this binary is distributed by **GCleaner** — a Pay-Per-Install (PPI) service that has been active since 2019. GCleaner operators sell installation slots on compromised machines to other threat actors, who provide their payloads for distribution. Five separate delivery tasks were observed between April 6–8, 2026.

The chain:

```
Victim machine (pre-compromised)
    → GCleaner PPI stub executes
    → Downloads 072533c1...exe from C2
    → Drops and executes the Go backdoor
    → Backdoor connects to 72.61.25.108:6789/tcp
```

This means the Gsb backdoor operator is likely **distinct** from the GCleaner operator — they're a customer of the PPI service. MalwareBazaar tagged this sample as "SmokeLoader," but that appears to be a misclassification — SmokeLoader is traditionally a Delphi/C++ loader, not a Go binary.

---

## Why This Sample Evades Detection

Before diving into the reversing, it's worth understanding why only 15.8% of AV engines flagged this. The evasion isn't based on packing or encryption — it's structural:

1. **Valid Authenticode signature** — the binary is signed by `www.glass.com` with a valid certificate chain. Many AV engines and EDR products apply reduced scrutiny to signed binaries.

2. **Go binary structure** — Go compiles to statically linked, monolithic executables with thousands of standard library functions embedded. The malicious code is a tiny fraction of the binary, drowned out by legitimate Go runtime.

3. **Nuclear reactor simulation cover code** — the binary performs actual floating-point math operations on reactor physics data structures (`map[GridRef]float64`), making behavioral heuristics see "math application" rather than "backdoor."

4. **CJK function names** — signature engines that pattern-match on ASCII function names find nothing recognizable. The obfuscated names are randomized Chinese character sequences.

5. **Runtime-encrypted C2 config** — no plaintext URLs, IPs, or domains in the binary. Static scanners have nothing to match.

6. **Dynamic API resolution** — instead of importing suspicious APIs in the PE import table, the binary resolves them at runtime via `LoadLibrary`/`GetProcAddress`.

The result: Kaspersky's dynamic sandbox is the only vendor that identified this as `Backdoor.Win64.Gsb`. ReversingLabs flagged it with a generic heuristic. Most engines rated it clean.

---

## The Two Obfuscation Layers

![Obfuscation layers](/assets/images/posts/gsb/2_obfuscation.png)
*Three concentric layers: nuclear physics decoy types → CJK garble function names → runtime-encrypted config and API names*

### Layer 1: Nuclear Reactor Physics Decoy Types

The Go type system embeds type names in the binary. The developer chose names from nuclear reactor engineering:

| Type Name | Nuclear Engineering Meaning |
|---|---|
| `main.BeamEnvelope` | Neutron beam spatial distribution profile |
| `main.ControlDrum` | Rotatable absorber cylinder in space reactors |
| `main.FuelRodBundle` | Assembly of fuel rods in a reactor core |
| `main.GridRef` | Core lattice coordinate reference |
| `main.LatticeCell` | Single unit cell in the reactor core grid |
| `main.MagnetFlavor` | Magnetic confinement parameter (fusion context) |
| `main.XenonTransientTable` | Xenon-135 poisoning transient lookup data |

And the field names go deeper: `reactivityWorthCurve`, `dopplerCoefficientNeg`, `xenonConcentrationPpm`, `claddingIntegrityScore`, `rotationAngleDegrees`. These aren't random strings — they're technically accurate physics terms that would pass cursory inspection by an analyst unfamiliar with nuclear engineering.

![Nuclear type names in IDA strings](/assets/images/posts/gsb/ida_nuclear_strings.png)
*IDA strings view showing `*main.ControlDrum` and `*main.LatticeCell` among Go runtime type metadata*

The binary actually performs reactor simulation math. In `main.main`, I found `map[GridRef]float64` being populated with IEEE 754 double values like `1.0`, `1.5`, and `125.7` — plausible reactor parameters. The `runtime.rand` calls seed the simulation. This isn't dead code — it executes and produces results. It's a functional cover story.

### Layer 2: CJK Garble-Style Function Names

The actual function names are randomized Chinese character sequences — a technique associated with the [garble](https://github.com/burrowers/garble) obfuscation tool or a custom variant of it:

| Address | CJK Name | Translation | Actual Purpose |
|---|---|---|---|
| `0x471740` | `main.简短平衡战斗` | Brief Balance Battle | DLL procedure execution via `LazyProc.Call` |
| `0x471ec0` | `main.main` | (not obfuscated) | Entry point — reactor setup + goroutine launch |
| `0x4727a0` | `main.提升武装意识到` | Improve Armed Awareness | Slice/map operations, `runtime.rand` |
| `0x472fc0` | `main.账户男孩酒吧` | Account Boy Bar | **`LoadLibrary` + `GetProcAddress`** |
| `0x4738a0` | `main.也青铜爆炸` | Also Bronze Explosion | Map access, memory allocation |
| `0x473d60` | `main.牛肉古代桥` | Beef Ancient Bridge | **String decryption** (called before `GetProcAddress`) |
| `0x4740e0` | `main.资产酒吧协助` | Asset Bar Assist | **`SyscallN` + `LazyProc.Find`** — direct syscalls |
| `0x4747c0` | `main.讨价还价黄铜道歉` | Bargain Brass Apology | **Largest function (3,973 bytes)** — payload builder |

The Chinese characters form grammatically nonsensical phrases — "Beef Ancient Bridge," "Bargain Brass Apology" — which is the hallmark of garble's random word selection from a CJK dictionary. The names survive in the `.symtab` section because the developer didn't strip symbols, probably to avoid breaking Go's runtime reflection.

---

## Reversing the Malicious Core

I used radare2 for disassembly since GoReSym failed to parse the pclntab (it was stripped or modified). The `afl` command with Go-aware analysis (`aang`) recovered all function boundaries.

### The Entry Point: Reactor Math → Payload Launch

![IDA graph view of main.main](/assets/images/posts/gsb/ida_main_main_graph.png)
*IDA graph view: left block shows reactor cover code (`runtime_rand`, `mapassign_fast64`, `RTYPE_map_main_GridRef_float64`); right block shows the VirtualAlloc call with `ecx = 3000h` and `edi = 40h` — the transition from cover to payload*

`main.main` (2,255 bytes) starts with what looks like a legitimate application — it creates `map[GridRef]float64` lattices, populates them with reactor physics values, and calls `runtime.rand` for simulation seeding. But buried in the middle of this math, at offset `0x4720e0`, it launches the real payload:

```asm
; main.main — the transition from cover to payload
; After ~300 bytes of reactor simulation setup:
0x004720e0  call  sym.main.__6              ; main.讨价还价黄铜道歉 — build payload
0x004720e5  mov   qword [var_298h], rax     ; store payload pointer
0x004720ed  mov   rcx, qword [rax]          ; load payload base address
0x004720f0  mov   ebx, dword [rax + 8]      ; load payload size
0x004720f6  mov   ecx, 0x3000               ; MEM_COMMIT | MEM_RESERVE
0x004720fb  mov   edi, 0x40                 ; PAGE_EXECUTE_READWRITE ← RWX!
0x00472100  call  sym.main.                 ; main.简短平衡战斗 → VirtualAlloc
0x00472105  test  rbx, rbx                  ; check for error
0x00472108  jne   0x47210f                  ; retry on failure
```

`0x3000` is `MEM_COMMIT | MEM_RESERVE`. `0x40` is `PAGE_EXECUTE_READWRITE`. This allocates a writable and executable memory region — the classic preparation for shellcode injection or reflective loading. The payload data comes from `main.讨价还价黄铜道歉` (the 3,973-byte function), which builds the executable payload at runtime.

If the first `VirtualAlloc` call fails, the code retries at `0x472126` with the same parameters — persistence in allocation.

![IDA decompiled VirtualAlloc RWX](/assets/images/posts/gsb/ida_virtualalloc_rwx.png)
*IDA pseudocode after annotation: `main_PayloadBuilder()` returns the payload struct, `main_VirtualAlloc_wrapper()` allocates RWX memory with `PAGE_EXECUTE_READWRITE`. The retry logic and error checking are clearly visible. Variable names mapped to Win32 API conventions via IDAPython.*

### Dynamic API Resolution: LoadLibrary → GetProcAddress

`main.账户男孩酒吧` ("Account Boy Bar," 2,262 bytes at `0x472fc0`) implements the classic malware pattern of resolving APIs at runtime to avoid static import detection:

```asm
; main.账户男孩酒吧 — Dynamic API resolution chain
; Step 1: Load the target DLL
0x004733f5  call  sym.syscall.LoadLibrary    ; LoadLibraryW(dll_name)
0x004733fa  test  rbx, rbx                   ; check error
0x004733fd  jne   0x473456                   ; jump if load failed

; Step 2: Decode the encrypted function name
0x00473529  call  sym.main.__4               ; main.牛肉古代桥 — string decryptor
0x0047352e  mov   rcx, rbx

; Step 3: Resolve the function address
0x00473539  call  sym.syscall.GetProcAddress  ; GetProcAddress(handle, func_name)
0x0047353e  nop
0x00473540  test  rbx, rbx                   ; check error
0x00473543  jne   0x4735af                   ; jump if resolve failed

; Step 4: Execute via direct syscall
0x00473555  call  sym.main.__5               ; main.资产酒吧协助 → SyscallN
```

![IDA decompiled LoadLibrary + GetProcAddress](/assets/images/posts/gsb/ida_loadlibrary_getprocaddr.png)
*IDA pseudocode: `main_StringDecryptor` decrypts the API name, `syscall_LoadLibrary` resolves the DLL handle, then the resolved function is called with the decrypted arguments*

The function name is **not passed as a plaintext string**. It's decoded at runtime by `main.牛肉古代桥` ("Beef Ancient Bridge") — the string decryption helper. This is why the C2 configuration and API names aren't visible in static strings.

### Direct Syscall Execution

`main.资产酒吧协助` ("Asset Bar Assist," 1,750 bytes at `0x4740e0`) bypasses usermode API hooks entirely by calling `syscall.SyscallN` directly:

```asm
; main.资产酒吧协助 — Direct syscall execution
0x00474225  mov   rax, [0x543668]            ; load LazyDLL/Proc pointer
0x00474235  call  sym.syscall._LazyProc_.Find ; resolve the system call
0x0047423a  test  rax, rax                   ; verify success
0x0047423d  jne   0x4742b4                   ; jump if failed

0x00474250  mov   rsi, [rsi + 0x20]          ; get procedure address
0x00474254  mov   rax, [rsi + 0x18]          ; function pointer
0x00474278  mov   ecx, 2                     ; argument count = 2
0x00474280  call  sym.syscall.SyscallN        ; invoke the syscall directly
0x00474285  test  rax, rax                   ; check return value
```

![IDA annotated SyscallN](/assets/images/posts/gsb/ida_syscalln.png)
*IDA ASM view with analyst annotations: `LazyProc.Find` resolves the procedure, `lpProcAddr` and `fnPtr` are extracted from the struct, `nargs = 2` sets the argument count, then `SyscallN` executes the call directly — bypassing any usermode API hooks*

`SyscallN` is Go's mechanism for making arbitrary Windows API calls with a variable number of arguments. Combined with `LazyProc.Find`, this resolves and invokes system calls without going through the normal `kernel32.dll` dispatch — making EDR hook-based detection ineffective.

### The APIs Being Resolved

The binary dynamically loads these DLLs through Go's `syscall` package lazy loading infrastructure:

| Module | Purpose |
|---|---|
| `kernel32.dll` | Memory allocation, process/thread management, file I/O |
| `advapi32.dll` | Privilege management, token manipulation |
| `crypt32.dll` | Cryptographic operations |
| `shell32.dll` | Shell execution |
| `ws2_32.dll` | Network socket operations (Winsock) |
| `ntdll.dll` | Low-level NT API access |

Individual API targets (from import resolution and lazy proc setup):

```
VirtualAlloc, VirtualFree, VirtualQuery
CreateThread, SuspendThread, ResumeThread
SetThreadContext, GetThreadContext
DuplicateHandle, OpenProcess
CreateProcessAsUserW
GetProcessAffinityMask, GetSystemInfo
LoadLibraryW, LoadLibraryExW, GetProcAddress
WriteFile, CreateFileW, DeleteFileW
GetTempPathW, GetCurrentProcessId
```

The `SuspendThread` → `SetThreadContext` → `ResumeThread` pattern combined with `VirtualAlloc(RWX)` is a strong indicator of **thread hijacking injection** — a technique where the malware suspends a thread in a remote process, rewrites its instruction pointer to point at injected shellcode, then resumes it.

---

## Embedded Payload: 227KB Encrypted Blob

Inside `main.main`, the binary allocates a 227,403-byte object and fills it with data from the `.rdata` section:

```c
// From IDA pseudocode — payload construction
p_payload = runtime_newobject(&RTYPE__227403_uint8);      // allocate 227,403 bytes
*p_payload       = 0x6F078DAE4D6FA05F;                    // 8-byte header (mov)
*(p_payload + 8) = 0x7A85BB050C0B66E2;                    // 3 more header bytes
qmemcpy(p_payload + 11, &src_, 0x37840);                  // copy 227,392 bytes of encrypted data
```

The blob lives at file offset `0xAE421` with entropy of **7.73 bits/byte** — firmly in the encrypted/compressed range. The byte frequency distribution is skewed toward values with low nibble `0xA` (0x0A at 2.06%, 0x8A at 2.04%, 0xEA at 1.68%), suggesting a specific encoding scheme on top of encryption.

This data is then processed by `main_map_alloc`, which references `go:rodatafipsstart` — a Go 1.24 **FIPS 140 compliance** section boundary. This means the decryption uses Go's built-in FIPS-certified crypto module (likely AES), not a custom algorithm. The decompiled code shows the output buffer size is **70,096 bytes** (`0x111D0`), which is the actual payload that gets copied to the RWX memory.

I was unable to extract the decrypted shellcode statically — the decryption key is derived at runtime through the Go FIPS crypto chain. To recover the payload, you would need to:
- Break at `0x472100` (the `VirtualAlloc` call) in a debugger and dump the RWX region after the `memcpy`
- Capture a memory dump from a sandbox run at the right execution point
- Emulate the Go runtime's FIPS crypto initialization (non-trivial due to Go's complex startup sequence)

I also attempted runtime extraction via emulation:

- **Speakeasy** (Mandiant's Windows PE emulator): killed by OOM — Go's runtime initialization allocates hundreds of MB before reaching `main.main`
- **Unicorn** (targeted emulation of just the decryption path): same result — Go functions depend on the full runtime being initialized (GC, goroutine scheduler, memory allocator)
- **Brute-force key search**: tried single-byte XOR (0x00–0xFF), multi-byte XOR, ROL/ROR rotation, AES with every plausible key derivation (header bytes, build hash, SHA256 variants, certificate signer). None produced structured output.
- **UnpacMe** (automated unpacking service): processed this sample but [recovered zero children](https://api.unpac.me/api/v1/public/results/3f8f561d-f870-4e10-9b9c-cdcaa20abd46) — confirming the payload can't be extracted without live execution

The absence of standard AES constants (S-box, T-tables) in the binary suggests Go 1.24's FIPS module uses **bitsliced AES** — a constant-time implementation that doesn't use lookup tables, making the algorithm harder to identify statically.

The raw encrypted blob is preserved in the analysis bundle as `embedded_blob_227403.bin` for anyone with a Windows debugger environment to extract the decrypted 70KB payload at runtime.

---

## C2 Configuration

The C2 config is not visible in static strings — it's encrypted and decoded at runtime by the `main.牛肉古代桥` string decryption function. I was unable to crack the encryption statically (it's not simple XOR — likely uses Go's `crypto` packages).

However, [threat.rip's automated dynamic analysis](https://www.threat.rip/file/072533c1d31d83b056a1a9f4174a23763c53597df1c89ad9c545df2c3bb35f5e/config) extracted the config at runtime:

| Field | Value |
|---|---|
| **C2 Host** | `72.61.25.108` |
| **C2 Port** | `6789` |
| **Protocol** | TCP (raw) |
| **ASN** | AS-HOSTINGER |
| **Infrastructure** | Hostinger VPS |

Port 6789 is unusual — not a standard service port, but also not suspicious enough to trigger port-based alerting. The Hostinger ASN is a budget VPS provider frequently used for ephemeral C2 infrastructure.

---

## The Builder Framework: Factory-v3

The build path leaked in the Go binary metadata reveals the framework:

```
Factory-v3/builder/temp/7061c16a7a05b72f2cf8d5e57bdcc1d0/main.go
```

Key observations:

- **`Factory-v3`** — versioned builder framework (implying v1 and v2 exist)
- **`builder/temp/`** — the builder generates temporary source files, compiles them, then cleans up
- **`7061c16a7a05b72f2cf8d5e57bdcc1d0`** — likely an MD5 hash serving as a build ID
- **`-trimpath=true`** in build flags — the developer tried to strip source paths, but `Factory-v3` leaked through the module root

The `-trimpath` flag strips absolute filesystem paths from the binary but doesn't remove the module path. This is a common OPSEC mistake — the builder name survives compilation.

The framework likely provides:
- A builder GUI or CLI that generates customized Go implant source code
- Nuclear reactor type name generation as the obfuscation layer
- CJK function name randomization (garble-style)
- Embedded Authenticode signing with the `www.glass.com` certificate
- Per-build encryption key for the C2 configuration

---

## The Authenticode Certificate

The binary carries a valid Authenticode signature issued to `www.glass.com`. This is significant because:

1. **It passes Windows SmartScreen** — unsigned binaries trigger warnings; signed ones don't
2. **It bypasses some AV heuristics** — several engines reduce alerting on signed PE files
3. **The certificate is from an unknown CA** — `Country Unknown` in the certificate metadata suggests a self-signed or fraudulently obtained cert, but it validates as "valid" in Windows' trust store

The signing happens at the builder level (the `Factory-v3` framework applies it), as evidenced by the overlay containing a 2,176-byte PKCS#7 signature block.

---

## IOC Appendix

### Network Indicators

| Type | Value | Context |
|---|---|---|
| IP | `72.61.25.108` | C2 server |
| Port | `6789/tcp` | C2 port (raw TCP) |
| ASN | AS-HOSTINGER | C2 hosting |

### Host Indicators

| Type | Value | Context |
|---|---|---|
| Build Path | `Factory-v3/builder/temp/` | Builder framework artifact in binary |
| Certificate | `www.glass.com` | Authenticode signer |
| Go Build ID | `vIOXNUGrDWmi7-CT--qK/YkkHv7Jla5AY52C3CNL_/KDTloTCYQHuKnv65BC_L/FSZG-podQva36lp5t6_6` | Unique per-build identifier |
| RWX Allocation | `VirtualAlloc(NULL, size, 0x3000, 0x40)` | Shellcode staging |

### File Hashes

| Hash | Value |
|---|---|
| SHA-256 | `072533c1d31d83b056a1a9f4174a23763c53597df1c89ad9c545df2c3bb35f5e` |
| MD5 | `650c00bed1b3ce7db2e8ddfb949a5576` |
| SHA-1 | `350c7b55675d1cd6903ac8f12dcdceace13f1d43` |

### MITRE ATT&CK Mapping

| ID | Technique | Evidence |
|---|---|---|
| T1027.010 | Obfuscated Files: Command Obfuscation | CJK function names + nuclear decoy types |
| T1055.003 | Process Injection: Thread Execution Hijacking | SuspendThread + SetThreadContext + ResumeThread + VirtualAlloc(RWX) |
| T1106 | Native API | Direct syscall via `SyscallN` bypassing API hooks |
| T1129 | Shared Modules | Runtime `LoadLibrary` + `GetProcAddress` |
| T1140 | Deobfuscate/Decode | `main.牛肉古代桥` runtime string decryption |
| T1553.002 | Subvert Trust Controls: Code Signing | Valid Authenticode cert from `www.glass.com` |
| T1587.001 | Develop Capabilities: Malware | Factory-v3 custom builder framework |

---

## Detection

### YARA

Two rules in `detection/factory_v3_go_implant.yar`:

1. **Factory_v3_Go_Implant_NuclearDecoy** — high-fidelity rule targeting this specific framework (builder path + nuclear types + CJK function names)
2. **Factory_v3_Go_Implant_Generic** — family-level detection matching 5+ nuclear type names in any Go PE binary

### Network (Suricata)

```
alert tcp $HOME_NET any -> $EXTERNAL_NET 6789 (
    msg:"MALWARE Backdoor.Win64.Gsb C2 communication";
    flow:established,to_server;
    dsize:>50;
    detection_filter:type count, track by_src, count 3, seconds 300;
    sid:2026043; rev:1;
)
```

### Certificate-Based Detection

```
alert tls $HOME_NET any -> $EXTERNAL_NET any (
    msg:"MALWARE Gsb backdoor - www.glass.com signed binary";
    tls.cert_subject; content:"www.glass.com";
    sid:2026044; rev:1;
)
```

---

## Reversing Methodology: How to Approach Go Malware

For analysts encountering Go-compiled malware for the first time, here's the workflow that worked for this sample:

1. **Try GoReSym first** — [Mandiant's tool](https://github.com/mandiant/GoReSym) parses the pclntab for function names and metadata. It failed here (pclntab stripped), but it works on ~80% of Go samples.

2. **Fall back to radare2** — `r2 -c 'aaa; afl~main.' sample.exe` recovers function boundaries even without pclntab. The `aang` analysis pass is Go-aware.

3. **Check the `.symtab` section** — even when pclntab is stripped, the `.symtab` often retains symbol names. Use `izz~main.` in radare2 to dump them.

4. **Look for the Go build ID** — `strings sample.exe | grep "Go build ID"` reveals the compiler version and build fingerprint.

5. **Search for the build path** — Go embeds the source path in the binary. Even with `-trimpath`, the module root often leaks (as `Factory-v3` did here).

6. **Map `syscall.*` calls** — Go's standard library wraps Windows API calls through `syscall.LoadLibrary`, `syscall.GetProcAddress`, and `syscall.SyscallN`. Finding these in the disassembly pinpoints the malicious code.

7. **For obfuscated samples**, try [GoResolver](https://www.volexity.com/blog/2025/04/01/goresolver-using-control-flow-graph-similarity-to-deobfuscate-golang-binaries-automatically/) (CFG-based function name recovery) or [GoStringUngarbler](https://cloud.google.com/blog/topics/threat-intelligence/gostringungarbler-deobfuscating-strings-in-garbled-binaries) (garble string decryption).

---

## Conclusion

This sample represents a step up in Go malware craftsmanship from what I usually see in my triage queue. The combination of a custom builder framework (`Factory-v3`), dual-layer obfuscation (nuclear physics cover + CJK garble), valid code signing, and runtime-encrypted configuration achieves a 15.8% VirusTotal detection rate — meaning 84% of AV engines think this is a legitimate application.

The nuclear reactor simulation isn't cosmetic — it's functional code that executes real math, making behavioral analysis harder. The CJK function names break signature engines that expect ASCII patterns. And the dynamic API resolution via `LoadLibrary`/`GetProcAddress` into `SyscallN` bypasses the usermode API hooks that most EDR products rely on.

But the operator made mistakes. The `-trimpath` flag didn't fully strip the `Factory-v3` module path. The `.symtab` section was left intact, exposing all CJK function names. And the Authenticode certificate from `www.glass.com` is a pivotable indicator — any other binary signed by this cert is almost certainly from the same operation.

For defenders: the nuclear type names (`BeamEnvelope`, `ControlDrum`, `FuelRodBundle`, `XenonTransientTable`) are highly specific and unlikely to appear in legitimate software outside of actual nuclear engineering tools. A YARA rule matching 5+ of these names in a Go PE binary is a high-fidelity detection with near-zero false positives.

The GCleaner distribution chain means this backdoor is being sold as a service — the Factory-v3 builder likely has other customers generating variants with different C2 addresses and build IDs. The framework name and certificate are the constants to hunt on.

---

## Appendix: External Intelligence Sources

| Source | URL | Finding |
|---|---|---|
| threat.rip | [File Report](https://www.threat.rip/file/072533c1d31d83b056a1a9f4174a23763c53597df1c89ad9c545df2c3bb35f5e) | Backdoor.Win64.Gsb, score 100/100, C2 config extracted |
| threat.rip | [MalConfig](https://www.threat.rip/file/072533c1d31d83b056a1a9f4174a23763c53597df1c89ad9c545df2c3bb35f5e/config) | C2: `72.61.25.108:6789/tcp` (AS-HOSTINGER) |
| Loader Insight Agency | [Payload View](https://loaderinsight.agency/?p=payload_view&hash=072533c1d31d83b056a1a9f4174a23763c53597df1c89ad9c545df2c3bb35f5e) | Distributed by GCleaner, 5 delivery tasks |
| MalwareBazaar | [Sample](https://bazaar.abuse.ch/sample/072533c1d31d83b056a1a9f4174a23763c53597df1c89ad9c545df2c3bb35f5e) | Tagged `dropped-by-GCleaner`, reporter: Bitsight |

| Scanner | Detection |
|---|---|
| Kaspersky Opentip | Backdoor.Win64.Gsb (dynamic) |
| ReversingLabs | Win64.Malware.Heuristic (ML) |
| VirusTotal | 12/76 (15.8%) |
| ANY.RUN | 100/100, Malicious |
| Hybrid Analysis | 87/100 |
| CyberFortress | 94.9% — #injection #obfusc #crypt |

---

*Tools used: radare2 (disassembly), [GoReSym](https://github.com/mandiant/GoReSym) (attempted symbol recovery), pefile/dnfile (PE metadata), custom Python string extraction. C2 config extracted by [threat.rip](https://www.threat.rip). Kill chain mapped via [Loader Insight Agency](https://loaderinsight.agency). Win32 API analysis referenced from [Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/).*
