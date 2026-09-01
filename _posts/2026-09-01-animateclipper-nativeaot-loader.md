---
title: "AnimateClipper: A NativeAOT Loader That Hides C# From Every .NET Tool You Own"
permalink: /blog/animateclipper-nativeaot-loader/
date: 2026-09-01 00:00:00 +0000
categories: [malware-reversing, threat-intel]
tags: [animateclipper, clipper, clipbanker, nativeaot, dotnet, csharp, process-hollowing, uac-bypass, cmstplua, string-encryption, yara, sigma, suricata, golang, static-analysis, windows]
description: "A NativeAOT stage-1 loader that dnSpy and ILSpy cannot read, taken apart statically: two hand-rolled keystream ciphers over its API name table, a CMSTPLUA elevation-moniker UAC bypass, a self-copy into Startup, and a full manual PE loader that hollows a signed Microsoft binary. Includes the recovered stage-2 cipher, its static 256-bit key and nonce, five YARA rules measured against 2,977 corpus samples, and the retrohunt that pushed the family's first observed build back ten weeks."
image:
  path: /assets/images/social/animateclipper-card.jpg
  alt: "AnimateClipper NativeAOT stage-1 loader"
---

> **Downloads:** every artifact in this post is mirrored at [taogoldi/analysis_data/animateclipper_aug_2026](https://github.com/taogoldi/analysis_data/tree/main/animateclipper_aug_2026). The YARA rules are also mirrored at [taogoldi/YARA/loaders/animateclipper](https://github.com/taogoldi/YARA/tree/main/loaders/animateclipper). A consolidated download index is at [/downloads/animateclipper/]({{ site.baseurl }}/downloads/animateclipper/).

> **On the age of this sample.** The loader analysed here was compiled on 2026-07-11 and reversed on 2026-08-01, so by publication it is roughly seven weeks old, and the family is older still: a retrohunt with the rules below pulled three builds out of our own collection from late April and May. Treat the network indicators as historical unless you re-validate them. The structural signatures have held across four months of builds and are the part worth deploying: the cipher constants, the `.gfx` section, the descriptor layout.

Open this sample in dnSpy and you get nothing. ILSpy, the same. `DIE` calls it a plain x64 C++ binary, our own `.NET` detection returns false, and the import table is 139 unremarkable CRT entries. It is a .NET program, almost certainly written in C#.

The trick is the build mode. AnimateClipper's stage-1 loader is compiled with .NET NativeAOT, which turns C# into native x86-64 ahead of time. No CLR header. No IL stream. No metadata tables for a managed decompiler to walk. Every tool built to read managed .NET walks straight past it, and every tool built for native malware sees an ordinary, if unusually fat, C++ binary.

Strip the wrapper away and the loader underneath is conventional and completely readable: a custom keystream cipher over its API name table, a COM elevation-moniker UAC bypass, a self-copy into Startup, and process hollowing into a signed Microsoft binary. None of that is new. The interesting part is that a 3.9 MB NativeAOT wrapper hid all of it from the tooling that would normally catch it.

What follows is the stage-1 loader end to end: how the family was actually identified, both hand-rolled stream ciphers, the privilege-escalation path, the manual PE loader, and the delivery chain back to a Go dropper. The stage-2 payload is still encrypted, but its cipher, its descriptor, and its 256-bit key are all recovered and documented here, along with three dump points for anyone who wants the payload today.

## Key Findings

- The binary is C# compiled with .NET NativeAOT. There is no CLR header and no IL, so dnSpy, ILSpy and every detector gated on the CLR directory report "not .NET" on a .NET program. `DIE` calls it a plain x64 C++ binary.
- Two hand-rolled stream ciphers protect the strings, both driven by one keystream: `state = ROL32(state ^ 0x9E3779B9, 13) + i * 0x6C078965`, seeded from `seed ^ 0xA7B3C1D5`. Every seed is a 32-bit immediate in the accessor thunk, so all 30 API names come out statically.
- Privilege escalation is the CMSTPLUA elevation moniker (`{3E5FC7F9-9A51-4367-9063-A120244FBEC7}`), UACMe technique 41. Persistence is a byte-identical self-copy into the user's Startup folder.
- The injector is a complete manual PE loader built on `ntdll` exports instead of the kernel32 wrappers: header validation, remote PEB read, `NtUnmapViewOfSection`, preferred-base allocation, a `.reloc` walker, per-section writes, and an entry-register rewrite (`Rcx` on x64, `Eax` on WOW64). Hollow target observed in four sandboxes is the Microsoft-signed `ServiceModelReg.exe`.
- Stage 1 has no network capability at all. The payload rides inside the file in a 2.9 MB `.gfx` section at entropy 7.9999, so blocking the C2 prevents nothing before stage 2.
- Stage 2's cipher is a twelve-round ARX permutation in counter mode, and its 32-byte key and 12-byte nonce are static and present in the binary at `0x1400E4370` and `0x1400E43A8`. Three dump points are documented for anyone who wants the payload.
- Best static anchors: the full instruction encodings of the three cipher constants, the `.gfx` section name paired with an entropy test, and the `Moonshine.Core` assembly name, which survives in all nine known builds where `aethsync` does not.
- Running the finished rules back over 2,977 stored samples surfaced three earlier builds filed under AgentTesla, SnakeKeylogger and Formbook tags, pushing the earliest observed use of this loader back to 2026-04-29.

## Sample Properties

| Property | Value |
|---|---|
| SHA-256 | `21bf44a654a0059f7bb974ffe6252db63e998d5f95937454d45da4d700267471` |
| MD5 | `ca789369076efaafc596f836d928abdd` |
| SHA-1 | `e6d3f4d33263f731a78b914227ee9d12422830e8` |
| Size | 3,890,176 bytes (3.71 MB) |
| Type | PE32+ executable (GUI) x86-64 |
| Machine | `0x8664` (AMD64) |
| Compile timestamp | 2026-07-11 01:53:19 UTC |
| Imphash | `d7a140ad86093e229082e6f8b7493b94` |
| Size of image | 3,944,448 |
| Sections | 7 (`.text .rdata .data .pdata .rsrc .reloc .gfx`) |
| Exports | none |
| Version info | product `aethsync`, original name `aethsync.dll`, version 1.0.0.0 |
| Internal module | `Moonshine.Core.dll` |

## Naming the Thing

The sample surfaced from our platform's daily queue: Intel x64, capa risk 100, flagged for investigation, grouped into a three-member build cluster on shared imphash and rich header.

Pinning the family took three passes, and the disagreement is the whole reason we validate before naming a folder.

| Source | Verdict | What it actually is |
|---|---|---|
| In-house pe_sentinel ML | `asyncrat` | Wrong. No AsyncRAT code path exists in this binary. |
| VirusTotal aggregate | `trojan.clipbanker/dacic` (52/75) | A behaviour category. |
| Kaspersky | `Trojan-Banker.Win32.ClipBanker.ajlr` | Category again. |
| ESET-NOD32 | `Win64/Kryptik.HFJ` | Generic packer verdict. |
| ReversingLabs | `Win64.Infostealer.ClipBanker` | Category. |
| **MalwareBazaar** | **`AnimateClipper`** | The family. |
| **Triage** | **`animateclipper`**, score 10, dedicated `Detects AnimateClipper` signature | The family, independently. |

Five sources say "clipbanker", which describes behaviour shared by dozens of unrelated families. Two independent sources say AnimateClipper, and one of them wrote a signature specifically for it. Going with the majority verdict would have produced a post about a category.

Our own model being wrong is unremarkable, and it was not even confidently wrong: family confidence came out at **35.71**, appropriate doubt for a family it has never seen. The label still landed in the database as `asyncrat`, because the platform writes the family without consulting the confidence attached to it. Less wrong than ignored.

## What Our Model Says Four Weeks Later

The table above is what the classifier said on 2026-08-01. It has been retrained since. It is a LightGBM ensemble over static PE features with separate heads for category, family and packing, plus an anomaly detector and a clustering model that sanity-checks the family verdict. Nothing exotic. Here is the current output on the same file:

| Head | Verdict | Confidence |
| --- | --- | --- |
| Category | `trojan` | 94.67% |
| Family | `zigclipper` | 79.48% |
| Packing | packed | 100% |
| Anomaly | not anomalous (0.0575) | typicality 0.666 |

Category is right. The packing verdict is the kind of error that looks like a result, so it is worth taking apart. Whether it is strictly *wrong* depends on what the training labels mean by `packed`: if the label covers "contains packed or encrypted content", the model answered its own question correctly. It is not telling an analyst that the executable code is packed, which is how the field reads it. Per-section entropy puts `.text` at 6.639, ordinary native code, and `.rdata` at 6.087. Only `.gfx` reaches 8.000, and at 2.9 MB of a 3.89 MB file it drags the whole-file figure to 7.845. The model saw that aggregate and called the binary packed at 100%.

It is an unpacked loader carrying an encrypted payload. Different thing, different consequences: no unpacking stub to run, every byte of the loader sitting in plain view. Whole-file entropy is the feature the model actually has, so "packed" is its only vocabulary for "high entropy", and the 100% is measuring how high the entropy is, not how sure it should be.

The family miss is more interesting. `zigclipper` is another clipper, so the model reached for the nearest thing it knew. AnimateClipper is not one of the 51 families in its vocabulary and never has been. A classifier with a fixed label set cannot say "something I was not taught"; it can only say "the closest label I have". And 79% on the wrong family is a worse failure than 35% on the wrong family. The number went up while the answer stayed wrong.

The fix is not a better model. It is a larger vocabulary, and vocabularies only grow when someone reverses a family and writes the label down.

### The rules did what the model could not

The same file through the platform's YARA corpus returns three hits:

```
AnimateClipper_Composite
AnimateClipper_Loader_GfxSection
AnimateClipper_StringDecryptor_Constants
```

Those are the rules at the bottom of this post, written by hand from constants recovered below. The model guessed a neighbour. The rules named the family. Neither replaces the other, and the pairing is the point: statistical classification generalises to families nobody has documented and degrades into "clipper-shaped"; signatures do not generalise at all and are exact when they fire.

### Turning the rules back on our own corpus

A rule that fires on the sample it was written from proves nothing. All four went across 2,977 stored samples, weighted towards the cases most likely to break them.

No false positives. They also produced three hits that were not supposed to be there, on samples already in the collection under other names. MalwareBazaar has them tagged Formbook, SnakeKeylogger and AgentTesla.

Their loader layer is AnimateClipper regardless of the tags. All three carry the same four instruction encodings in the same counts, and their section layout matches the same loader to within a few kilobytes:

| Sample | Bazaar tag | Compiled | `.text` | Stage 2 |
| --- | --- | --- | --- | --- |
| `3ee1860c` | AgentTesla | 2026-04-29 | 699,392 | overlay |
| `be06aab9` | SnakeKeylogger | 2026-05-01 | 701,440 | overlay |
| `eca1963a` | Formbook | 2026-05-15 | 697,344 | `.gfx` |
| Main sample | -- | 2026-07-11 | 696,320 | `.gfx` |

That pushes the earliest observed use of this loader back roughly ten weeks. It was circulating by the end of April 2026, not mid-July.

The link is structural, at the loader layer, and only there. No C2, mutex, configuration or stage-2 payload ties these builds to the July sample, so this is the same loader in earlier use, not one continuous campaign under one operator. Bazaar tags are submitter and vendor labels, and with stage 2 unrecovered from any of these files, a loader-family label and a payload-family label are not mutually exclusive. A loader can deliver Formbook. The outer layer is this loader, and the outer layer is what these rules were written against.

The April and May builds also answer a question the main sample could not. They have no `.gfx` section: the encrypted stage 2 is appended to the file behind a four-byte magic and a little-endian length. A delivery change between May and July, and the reason there is now a fourth rule keyed on the container rather than the section. Four bytes of magic is far too short to match on alone, so the rule requires the length field to describe exactly the bytes remaining in the file. A chance occurrence of those four bytes will not also be self-consistent with the file size. Across the same corpus it cost nothing, and it catches the overlay builds the section rule structurally cannot see.

None of this came from better analysis of the original sample. It came from writing the rules down and running them over everything already collected, the cheapest hunting available and the most routinely skipped.

### Across the sibling set

The same model over the related samples, as a consistency check:

| Sample | Category | Family | Packed |
| --- | --- | --- | --- |
| Main loader | trojan (94.7%) | zigclipper (79.5%) | yes |
| `sib3.bin` | trojan (95.2%) | zigclipper (78.0%) | yes |
| `sib2.bin` | backdoor (74.8%) | zigclipper (48.5%) | yes |
| `sibling_cdb9558b.bin` | backdoor (75.3%) | zigclipper (37.4%) | yes |
| `dropper_L263919LLL.bin` | trojan (89.9%) | acrstealer (94.3%) | no |

The four loaders cluster together, which is the correct structural read even with the wrong name on it. The Go dropper separates cleanly, also correct, though `acrstealer` at 94.3% is another confident miss.

That miss taught us something. An early rule for the dropper keyed on its garbled `main` package symbols and matched 38 of 1,486 samples: lummastealer, acrstealer and amadey, over and over. Name mangling is a property of the build toolchain, and these families share one, so the rule was identifying a name mangler and calling it a family. We threw it away instead of tuning it. No threshold fixes a signature that measures the wrong thing.

The model appears to be doing the same thing. `acrstealer` at 94.3% is not a random neighbour; it is the label on most of the garbled 32-bit Go binaries in the training data, and the dropper is one of those. Rule and classifier failed identically, which argues the failure sits in the evidence rather than in either method.

## Methodology and Toolchain

Everything below was produced statically. The sample was never executed on my own hardware.

| Tool | Role |
|---|---|
| `pefile` (Python) | Header, section table, entropy, imports, overlay checks |
| radare2 + r2ghidra | Disassembly, function discovery, cross-references, Ghidra-engine decompilation |
| Custom Python | Thunk parsing and the string decryptor reimplementation ([`scripts/decrypt_strings.py`](https://github.com/taogoldi/analysis_data/blob/main/animateclipper_aug_2026/scripts/decrypt_strings.py)) |
| Custom C | Exhaustive 2^32 search, table-driven CRC-32C |
| GoReSym | Go build metadata and symbol recovery on the dropper |
| yara-python | Rule compilation, true-positive checks, corpus false-positive run |
| rizin + graphviz | Control-flow graph figures, rendered on the analysis host |
| IDA + IDAPython | Annotation scripts for all three binaries, so the figures carry real names instead of `sub_1400012C0` |
| Mermaid | Kill chain and hollowing flowcharts, kept as source beside the rendered images |
| The lab's corpus | 220k stored samples, used to hunt the rules and measure their false-positive rate |
| Public sandbox reports | Runtime behaviour |

**How the strings came out.** No emulator, no debugger, no unpacking:

1. Decompile the first 60 functions by address. The loader stub lives there, ahead of the NativeAOT runtime bulk.
2. Score each function for cipher shape by counting XOR operators, shifts and loops in the pseudocode. Two stood out immediately, `0x1400012C0` and `0x1400014C0`.
3. Read the loops by hand and pull out the constants and the output step.
4. Ask radare2 for cross-references to both. Thirty call sites came back, each in its own small thunk on a fixed 0x40-byte stride.
5. Dump the disassembly of the whole thunk range and parse each one with a regular expression for three values: blob pointer, length, seed immediate.
6. Reimplement the keystream in Python, read the ciphertext out of the PE at each pointer, decrypt.

[`decrypt_strings.py`](https://github.com/taogoldi/analysis_data/blob/main/animateclipper_aug_2026/scripts/decrypt_strings.py) recovers all 30 strings in under a second. The rest of the code written for this analysis ships alongside it:

| Path | What it is |
|---|---|
| [`scripts/decrypt_strings.py`](https://github.com/taogoldi/analysis_data/blob/main/animateclipper_aug_2026/scripts/decrypt_strings.py) | Reimplements the keystream, parses the 30 thunks, decrypts in place |
| [`ida/ida_stage1_animateclipper.py`](https://github.com/taogoldi/analysis_data/blob/main/animateclipper_aug_2026/ida/ida_stage1_animateclipper.py) | 3 enums, 5 structs, 25 names with Hex-Rays prototypes, all 30 thunks |
| [`ida/ida_variant2_cdb9558b.py`](https://github.com/taogoldi/analysis_data/blob/main/animateclipper_aug_2026/ida/ida_variant2_cdb9558b.py) | The verified string layer only, for variant 2 |
| [`ida/ida_dropper_goresym.py`](https://github.com/taogoldi/analysis_data/blob/main/animateclipper_aug_2026/ida/ida_dropper_goresym.py) | Replays the 186 GoReSym symbols onto the Go dropper |
| [`detection/*.yar`](https://github.com/taogoldi/analysis_data/tree/main/animateclipper_aug_2026/detection) | The five rules, with the rejected sixth documented in a comment |
| [`reports/disasm/`](https://github.com/taogoldi/analysis_data/tree/main/animateclipper_aug_2026/reports/disasm) | The decompilation and disassembly every argument below is drawn from |
| [`reports/json/`](https://github.com/taogoldi/analysis_data/tree/main/animateclipper_aug_2026/reports/json) | Decoded strings, the GoReSym dump, the raw analysis report |
| [`images/*.mmd`](https://github.com/taogoldi/analysis_data/tree/main/animateclipper_aug_2026/images) | Mermaid source for both flowcharts |

Splitting the IDA scripts into stage-1 and variant-2 versions was a finding, not tidiness. Variant 2 is byte-identical to the main sample across the entire string layer: same section VAs, the same two decryptors at `0x1400012C0` and `0x1400014C0`, the same 30 thunks on the same `0x40` stride, the same 30 seeds. So the stage-1 script *appears* to work on it. Deeper in it is a different binary, with six prologues differing at the same addresses, and running the stage-1 annotations there would stamp confident, wrong names onto functions nobody checked. Hence two scripts, a `.gfx`-size guard in each, and a warning in [`ida/README.md`](https://github.com/taogoldi/analysis_data/blob/main/animateclipper_aug_2026/ida/README.md).

The thunk-to-string mapping was derived, not assumed. Each thunk was re-parsed for its own pointer and seed, and all 30 matched the decrypted output on both fields, in stage 1 and in variant 2.

## First-Pass Static Analysis

The section table gives the shape of the thing immediately.

| Section | Virtual size | Raw size | Entropy |
|---|---|---|---|
| `.text` | 696,264 | 696,320 | 6.64 |
| `.rdata` | 193,872 | 194,048 | 6.09 |
| `.data` | 84,152 | 46,080 | 3.34 |
| `.pdata` | 33,096 | 33,280 | 5.95 |
| `.rsrc` | 2,706 | 3,072 | 4.74 |
| `.reloc` | 6,468 | 6,656 | 5.43 |
| **`.gfx`** | **2,909,337** | **2,909,696** | **7.9999** |

`.gfx` is not a section name any Microsoft toolchain emits. It is 2.9 MB, 75 percent of the file, at 7.9999 entropy across the whole section. Split it into eight equal slices and every slice runs 7.9994 to 7.9996, so the uniformity holds throughout instead of being an average over a mixed blob. All 256 byte values present. Encrypted or compressed end to end, with no lower-entropy header or footer to grab.

The import table is the opposite: 139 imports across 11 DLLs, and almost all of it is CRT plumbing.

```
ADVAPI32.dll   (6)  RegisterEventSourceW, ReportEventW, OpenProcessToken,
                    AdjustTokenPrivileges, LookupPrivilegeValueW
bcrypt.dll     (1)  BCryptGenRandom
KERNEL32.dll   (92) InitializeCriticalSectionEx, EncodePointer, CloseHandle, ...
ole32.dll      (4)  CoUninitialize, CoWaitForMultipleHandles,
                    CoGetApartmentType, CoInitializeEx
api-ms-win-crt-*    (36 across 7 CRT DLLs)
```

Three things jump out. There is no cross-process API at all: no `VirtualAllocEx`, no `WriteProcessMemory`, no `CreateRemoteThread`, and nothing touching the clipboard or the network. Plain `VirtualAlloc` is present, but it belongs to the garbage collector, as the breakdown below shows. `bcrypt.dll` contributes exactly one function, `BCryptGenRandom`, a random number generator, not a decryption primitive. And `ADVAPI32` supplies the token-inspection trio a privilege check needs.

A loader that hollows a process and decrypts a payload while importing none of the APIs to do either is resolving them at runtime. The strings confirm it.

### The runtime is C#

```
System.Private.CoreLib
System.Private.CoreLib.dll
System.Private.Reflection.Execution.dll
System.Private.TypeLoader.dll
$Moonshine.Core.dll
```

`System.Private.TypeLoader` and `System.Private.Reflection.Execution` are NativeAOT runtime components. They appear in neither a normal .NET assembly nor a C++ binary. Beside them sit `SearchValues` internals (`Any2CharPackedIgnoreCaseSearchValues`, `Any3CharPackedSearchValues`), which are .NET 8 or newer.

So: C# source, compiled by NativeAOT to native x64, linked with a trimmed .NET runtime, carrying an encrypted blob in a custom section. `Moonshine.Core` is the developer's own assembly name and survived into the binary. The shipped identity is `aethsync`.

The practical consequence is that the standard triage path for .NET malware fails silently. There is no CLR directory in the optional header, so every tool that gates on it, our own platform included, reports "not .NET" and moves on.

## Why This Is C# Even Though It Looks Native

The reasonable objection at this point: the file has ordinary PE sections, a normal import table, and 92 kernel32 functions. That is what a C++ program looks like. Where is the C#?

All of that is expected, because NativeAOT does not produce an unusual binary. It produces a completely ordinary native PE. The C# is compiled to x86-64 ahead of time, and the parts of the .NET runtime the program needs, the garbage collector, the type system, exception handling, are statically linked in as native code. No CLR to load, so no CLR header. No IL, so nothing for a managed decompiler to read.

The evidence that this is managed code sits inside the binary, in the runtime that got linked in.

**The .NET garbage collector is present, diagnostic strings intact:**

```
GCHeap::Promote: Promote GC Root *%p = %p MT = %pT
IGCHeap::Promote: Promote GC Root *%p = %p MT = %pT
.NET BGC
BGCFLEnableFF   BGCFLEnableKd   BGCFLEnableKi   BGCFLEnableSmooth   BGCFLEnableTBH
```

`BGC` is Background GC and the `BGCFL*` values are its free-list tuning knobs. `MT` in that format string is a MethodTable pointer, the CLR's type descriptor. A C++ program does not contain these.

**CLR type-system and exception types:**

```
MethodTable
AbandonedMutexException   NullReferenceException   IndexOutOfRangeException
InvalidCastException      OutOfMemoryException
```

**NativeAOT-only runtime components:**

```
System.Private.TypeLoader.dll
System.Private.Reflection.Execution.dll
System.Private.CoreLib
```

`System.Private.CoreLib` alone would not settle it, since it also turns up in ordinary single-file .NET bundles. `TypeLoader` and `Reflection.Execution` are strong NativeAOT artifacts in this context. No single item here has to carry the argument.

**And the imports belong to the runtime, not the malware.** All 92 kernel32 entries, categorised:

| Category | Count | Examples |
|---|---|---|
| Threads, TLS, synchronisation | 25 | `InitializeCriticalSectionEx`, `CreateEventExW`, `SetEvent` |
| Exceptions and unwinding | 8 | `RaiseFailFastException`, `RtlVirtualUnwind`, `RtlCaptureContext` |
| Heap and memory | 6 | `VirtualAlloc`, `VirtualQuery`, `GlobalMemoryStatusEx` |
| Module and procedure lookup | 6 | `LoadLibraryExW`, `GetProcAddress`, `GetModuleHandleW` |
| Process and environment | 5 | `EncodePointer`, `GetCurrentProcessorNumberEx` |
| Files, handles, console | 5 | `CloseHandle`, `WriteFile`, `GetStdHandle` |
| Time and performance counters | 3 | `QueryPerformanceCounter` |
| Locale and encoding | 2 | `MultiByteToWideChar` |
| Unclassified (mostly CRT plumbing) | 32 | `FormatMessageW`, `GetLastError`, `LocalFree` |

Sixty percent is unambiguous runtime support and the remainder is CRT plumbing. A garbage collector needs `VirtualAlloc` and `GetSystemInfo`. A managed exception model needs `RtlVirtualUnwind` and `RtlCaptureContext`. Managed strings need the encoding conversions.

Behavioural imports: zero. No process injection, no clipboard, no networking. Every API the malware actually uses is decrypted and resolved at runtime, which is the next section.

One more managed artefact shows up in the accessor thunks: `add rcx, 0x10` before a byte array gets used. In this x64 NativeAOT build, arrays carry a 16-byte header ahead of their payload, a `MethodTable`/`EEType` pointer followed by the length and its padding. The allocation sites make it explicit: `fcn.140048920` takes a type handle and an element count, and its result is immediately offset by `0x10` to reach the data, at `0x140005028` and `0x140005191` among others. Native C++ arrays carry no such header. This is a layout observation about the binary in hand, not a universal rule for every managed runtime.

A native PE, a native import table, native machine code, and a .NET program. Nothing so far is C#-specific, since NativeAOT compiles other .NET languages too. The managed toolchain is proven; C# is a strong inference from that plus the surrounding artifacts.

## String Obfuscation: A Keystream From Two Well-Known Constants

The loader keeps its API names encrypted and decrypts each one on first use. Two decryptors do the work:

| Address | Handles | Output step |
|---|---|---|
| `0x1400012C0` | byte / ASCII strings | `out[i] = in[i] ^ (state >> 16)` |
| `0x1400014C0` | UTF-16 strings | `u16 = in16[i] ^ ((state >> 8) & 0xFFFF)` |

Both share one keystream:

```c
state = seed ^ 0xA7B3C1D5;

for (i = 0; i < count; i++) {
    state = ROL32(state ^ 0x9E3779B9, 13) + i * 0x6C078965;
    /* consume state */
}
```

The whole key schedule is five instructions, and it is easier to believe when you see it:

![The AnimateClipper key schedule in IDA at 0x140001339, with the three cipher constants applied as named enum members](/assets/images/posts/animateclipper/ida_01_decryptor_loop.png)
_The complete key schedule and the byte output step. `SEED_XOR_ANIMCLIP`, `GOLDEN_RATIO` and `MT19937_INIT_MULT` are enum members applied by the annotation script; in a virgin database they are raw hex._

The constants are borrowed, not invented. `0x9E3779B9` is the golden-ratio constant, 2^32 divided by phi, familiar from TEA and XXTEA and a long list of hash functions. `0x6C078965` is 1812433253, the Mersenne Twister initialisation multiplier from `init_genrand`. `0xA7B3C1D5` looks like the only value the author picked themselves.

Mixed this way it is not a standard construction. It is a hand-rolled stream cipher that reads as cryptographic to anyone skimming the disassembly, and it falls apart the moment you have the three constants, because the entire key schedule derives from a 32-bit seed that ships in the instruction stream.

Here is the byte variant as the Ghidra engine decompiles it, via r2ghidra. The variable names are Ghidra's, which matters only so nobody tries to reconcile them against a differently named decompilation of the same function.

```c
uVar7 = arg2 ^ 0xa7b3c1d5;                    /* seed ^ SEED_XOR */
uVar10 = 0;
if (uVar2 != 0) {
    do {
        uVar7 = ((uVar7 ^ 0x9e3779b9) << 0xd | (uVar7 ^ 0x9e3779b9) >> 0x13)
                + uVar10 * 0x6c078965;        /* ROL32(state ^ GOLDEN, 13) + i*MULT */
        arg1_00[uVar10] = *(*arg1 + uVar10) ^ uVar7 >> 0x10;   /* out = in ^ (state >> 16) */
        uVar6 = uVar10 + 1;
        uVar10 = uVar6;
    } while (uVar6 < uVar2);
}
```

`(x << 13) | (x >> 19)` is a 32-bit rotate left by 13. The argument layout is a two-field structure: `*arg1` is the ciphertext pointer, `*(arg1 + 8)` the length, and the 32-bit seed arrives separately in `edx`.

That block is the *fast* path. The decompiler emits the loop twice, and the duplicate is a NativeAOT artifact, not anything the malware author wrote. Condensed, keystream line abbreviated to match the form above:

```c
if (uVar3 < uVar2) {            /* destination shorter than source */
    do {
        uVar7 = ROL32(uVar7 ^ 0x9e3779b9, 13) + uVar6 * 0x6c078965;
        if (uVar3 <= uVar6) {
            fcn.140030580();    /* noreturn throw helper */
            swi(3);             /* int3, unreachable */
        }
        arg1_00[uVar10] = *(*arg1 + uVar10) ^ uVar7 >> 0x10;
        uVar10 = uVar6 + 1;
    } while (uVar6 + 1 < uVar2);
}
else { /* the unguarded loop shown above */ }
```

C# bounds-checks every array write. The compiler proved the check redundant when the destination buffer is at least as long as the source, emitted an unguarded loop for that case, and kept a checked version for the other. `fcn.140030580` is a noreturn throw helper: it allocates an object from a type handle, calls two runtime routines, and ends in `int3`. The exception *type* did not resolve, so it is described here as a throw and nothing more specific.

Checked/unchecked duplication like this is what compiler-generated managed-array bounds checking looks like once NativeAOT's range-check elimination has proved the guard redundant on one path. It corroborates without proving on its own, since C and C++ can produce similar shapes through explicit checks, hardened libraries, sanitisers or range abstractions. Set beside the linked NativeAOT runtime and the managed artifacts above, it is another useful signal, visible without finding a single piece of .NET metadata. Raw decompiler output for both decryptors and for the GC path is in [`reports/disasm/pdg_*.c`](https://github.com/taogoldi/analysis_data/tree/main/animateclipper_aug_2026/reports/disasm).

### Each string gets its own accessor

Every encrypted string is wrapped in a small thunk, laid out on a regular 0x40-byte stride from `0x140001620`. Thirty of them: 27 calling the byte decryptor, 3 calling the UTF-16 one.

![The CopyFileW string accessor thunk at 0x140001660, showing the blob pointer, the 16-byte header skip, the length and the per-string seed](/assets/images/posts/animateclipper/ida_03_accessor_thunk.png)
_One accessor per string, 56 bytes each. This one hands the decryptor a 10-byte blob at `0x1400E4A38` with seed `0x5B2` and gets back `CopyFileW`. The seed is an immediate in the instruction stream, which is why static recovery works._

The first thunk in the table, disassembled, in case the shape is easier to read as text:

```asm
0x140001620  sub  rsp, 0x38
0x14000162b  lea  rcx, [0x1400e4a10]      ; encrypted blob object
0x140001632  add  rcx, 0x10               ; skip the 16-byte object header
0x140001636  mov  qword [var_28h], rcx    ; field 0: data pointer
0x14000163b  mov  dword [var_30h], 0xd    ; field 8: length (13)
0x140001643  lea  rcx, [var_28h]          ; arg1 = &{ptr, len}
0x140001648  mov  edx, 0x4ac              ; arg2 = seed (1196)
0x14000164d  call fcn.1400012c0
```

That `add rcx, 0x10` is the NativeAOT tell again. Managed byte arrays carry a 16-byte header, method table pointer plus length, ahead of the payload, so the loader steps over it to reach the raw bytes.

The layout makes static recovery mechanical: parse each thunk for pointer, length and seed, read the bytes out of the PE, run the keystream. That is all `decrypt_strings.py` does.

### What the strings say

```
CreateMutexW               CopyFileW                  ExpandEnvironmentStringsW
CreateProcessW             ResumeThread               GetModuleFileNameW
GetProcAddress             LoadLibraryW               RtlGetCurrentPeb
OpenProcessToken           GetTokenInformation        RtlAddVectoredExceptionHandler
RtlEnterCriticalSection    RtlLeaveCriticalSection    ole32.dll
CoInitializeEx             CoGetObject

NtUnmapViewOfSection       NtAllocateVirtualMemory    NtFreeVirtualMemory
NtWriteVirtualMemory       NtReadVirtualMemory        NtProtectVirtualMemory
NtGetContextThread         NtSetContextThread
Wow64GetThreadContext      Wow64SetThreadContext

Elevation:Administrator!new:{3E5FC7F9-9A51-4367-9063-A120244FBEC7}
C:\Windows\explorer.exe
explorer.exe
```

The whole loader is in that list. A privilege check, a COM elevation moniker, a self-copy, a mutex, and a complete process-hollowing API set built on `Nt*` calls instead of their kernel32 wrappers.

## Privilege Escalation: The CMSTPLUA Elevation Moniker

```
Elevation:Administrator!new:{3E5FC7F9-9A51-4367-9063-A120244FBEC7}
```

CLSID `{3E5FC7F9-9A51-4367-9063-A120244FBEC7}` is `CMSTPLUA`, which exposes `ICMLuaUtil`. Hand that moniker string to `CoGetObject` and COM returns an auto-elevated instance; `ICMLuaUtil::ShellExec` then runs an arbitrary command as administrator, because the object sits on the auto-elevation allowlist. Whether it happens without a consent prompt depends on the environment: UAC at its default notification level, and a user in the local administrators group running at medium integrity. Set to "always notify", or with a standard user, the moniker does not silently elevate.

UACMe technique 41, old enough to be thoroughly documented. Its continued presence says more about what still works than about the author's creativity.

The supporting strings line up exactly: `ole32.dll`, `CoInitializeEx` and `CoGetObject` to reach COM, plus `OpenProcessToken` and `GetTokenInformation` to decide whether the bypass is needed at all. The two remaining `ADVAPI32` imports, `AdjustTokenPrivileges` and `LookupPrivilegeValueW`, do **not** belong to this logic, however tempting the import list makes that reading. Both are called only from `fcn.140056770`, the NativeAOT GC's large-page path. The full argument is in the ATT&CK section; it is flagged here so nobody reads the import table twice and answers differently each time.

Independent corroboration: a sibling from the same cluster is classified `HEUR:HackTool.Win64.UACme.gen` by Kaspersky, and Triage tags this one `privilege_escalation`.

## Persistence and Single-Instance Control

`GetModuleFileNameW` to find itself, `ExpandEnvironmentStringsW` to resolve the target directory, `CopyFileW` to write the copy. Detonation confirms the destination:

```
%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\<random>.exe
```

The dropped file's SHA-256 matches the original sample exactly, so this is a plain self-copy with no repacking between generations. Observed filenames vary per run: `mml-aloww.exe`, `rdil.exe`, and a set sharing a `yea8hw` prefix (`yea8hwzItXOVhTCV.exe`, `yea8hwQ7LA5e0PML.exe`, `yea8hwMlfzxpBrKu.exe`). A shared prefix across three samples points to a per-build constant with a random suffix, not a fully random name.

`CreateMutexW` provides the single-instance gate, and the name is constant across every sandbox that ran it:

```
Global\MBDCABCFC4EE8E3B7
```

A second mutex, `update-S-2-5-26-24247216-2331352693-3112950123`, appears in two runs. It is shaped like a SID but is not a valid one, since a real SID starts `S-1-`.

## Process Hollowing Into a Signed Microsoft Binary

The decrypted API set covers everything process hollowing requires, and each choice in it trades against a specific defensive control. Note that the names being present is a weaker statement than the calls being made; the orchestrator walk below establishes which of them actually run, and with what arguments.

**Why `Nt*` and not the kernel32 wrappers.** `VirtualAllocEx`, `WriteProcessMemory` and `CreateRemoteThread` are the names static tooling and import-table heuristics key on, and each is a thin shim over an `ntdll` routine. Calling `NtAllocateVirtualMemory` and `NtWriteVirtualMemory` instead removes those names from the binary entirely.

What this does **not** buy the developer gets conflated constantly, so spell it out. It is not a direct-syscall technique. The loader resolves the `Nt*` routines out of `ntdll` with a `GetProcAddress` equivalent and calls the exports normally. No syscall stubs, no system service numbers, no `syscall` instruction. Userland EDR overwhelmingly hooks the `ntdll` exports rather than the kernel32 wrappers, so these calls land **inside** the hooked function, not underneath it. Against a product that hooks `ntdll`, the technique buys nothing at runtime. What it buys is static: a clean import table and no incriminating strings. Real gain against triage tooling, zero gain against behavioural monitoring.

**Why `NtUnmapViewOfSection` carries the load.** When `CreateProcessW` creates a suspended process, the host's legitimate image is already mapped at its preferred base. Unmapping that view frees the address range so the payload can be written where its headers expect to live, which avoids applying relocations at all. There is no benign reason for an application to unmap another process's image. Set beside the rest of the recovered set, which is a complete and ordered hollowing toolkit rather than a few suggestive names, the intent is not seriously ambiguous.

**Why both `NtGetContextThread` and `Wow64GetThreadContext`.** The plain pair operates on a 64-bit thread context, the `Wow64` pair on the 32-bit context of a WOW64 process. Carrying both means the loader is prepared to hollow either a 64-bit or a 32-bit host from this 64-bit binary. Small detail, real implication: the encrypted payload is likely available in both architectures, or the loader picks its host based on what it finds.

**What the context calls actually do.** After the payload is written, the suspended thread still points at the original entry point. The loader reads the register state, rewrites one register to the payload's entry, writes it back and resumes. That step is the difference between "wrote bytes into a process" and "took control of it".

Which register matters, because the two architectures do not use the same one and `fcn.1400056F0` implements both paths, selected by a boolean argument:

| | x64 path (`0x1400057AA`) | WOW64 path (`0x140005722`) |
|---|---|---|
| structure zeroed | `0x4D0` (1232) = `CONTEXT` | `0x2CC` (716) = `WOW64_CONTEXT` |
| 16-byte alignment | `lea r15, [rcx+0xF]` / `and r15, ~0xF` | not required |
| `ContextFlags` | `[r15+0x30] = 0x100002`, `CONTEXT_AMD64 \| CONTEXT_INTEGER` | `[r15+0x00] = 0x10007`, the `CONTEXT_i386` full set |
| register written | `[r15+0x80]` = **`Rcx`** | `[r15+0xB0]` = **`Eax`** |

Both are correct for their architecture. A thread created suspended begins in `RtlUserThreadStart`, which receives the image entry point in `Rcx` on x64 and `Eax` on x86, so overwriting that register before resuming redirects execution without touching the instruction pointer. Nothing in either path writes `Rip` or `Eip`.

The x64 path also requests `CONTEXT_INTEGER` only, not `CONTEXT_FULL`. It needs one general-purpose register and asks for nothing else.

**`RtlAddVectoredExceptionHandler`.** The loader registers a vectored exception handler. A vectored handler runs before any structured handler and before the debugger receives a second-chance exception, which makes it useful both for catching deliberate faults as a control-flow mechanism and for spotting an attached debugger by observing whether an exception gets swallowed. Either fits the evidence, and the NativeAOT runtime is itself a heavy user of exception machinery.

**`RtlGetCurrentPeb`.** Direct access to the current process's PEB, commonly used to walk `Ldr` module lists and resolve exports without touching `GetModuleHandle`, or to read `BeingDebugged`. The import establishes the capability; on this evidence no stealthy resolution path is claimed.

**`BCryptGenRandom`, statically imported.** The only crypto import, and it generates random numbers; it does not decrypt anything. A plausible source for the randomised Startup filename. No CNG decryption function is imported anywhere, so `.gfx` decryption runs in the loader's own managed code instead of being handed to Windows.

The full sequence:

```
CreateProcessW            create the host suspended
NtUnmapViewOfSection      unmap the host's original image
NtAllocateVirtualMemory   allocate at the payload's preferred base
NtWriteVirtualMemory      write headers and sections
NtGetContextThread        read the suspended thread context
NtSetContextThread        write the entry register (Rcx on x64, Eax on WOW64)
ResumeThread              run it

NtProtectVirtualMemory    resolved in the table; placement here is inference
```

That is the order of operations. What it leaves out is what each call is handed and what comes back, which is where most of the technique lives, so here is the same sequence with the arguments filled in from the orchestrator at `0x140005420`:

![Process hollowing call flow, with WinAPI arguments and return values](/assets/images/posts/animateclipper/hollowing.png)
_Solid boxes are statically proven in the binary. The two dashed ones are not: `NtProtectVirtualMemory` is resolved in the table and belongs in the sequence, but no distinct orchestrator step pins to it, and stage 2 is still encrypted. Argument names are the documented prototypes; the values beside them are what this loader supplies._

Two details in that diagram reward a slow read.

The allocation is **conditional on nothing**, but the relocation step is. The loader asks for the payload's preferred base first and only walks `.reloc` if it does not get it. Which is why unmapping the host image matters so much: a successful unmap makes the preferred base available, the relocation pass is skipped, and the payload lands byte-for-byte as it was built.

And the write is **per section, not one blob**. `NtWriteVirtualMemory` runs in a loop over the section table, with `Section.PointerToRawData` on the source side and `alloc_base + Section.VirtualAddress` on the destination. Those two differ whenever file alignment and section alignment differ, which is almost always. A memory dump of the hollowed host will therefore not match the `.gfx` blob on disk, and reconciling the two means undoing that mapping first.

Two hosts were observed. The decrypted strings name `C:\Windows\explorer.exe`, while four independent sandboxes report injection into:

```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\ServiceModelReg.exe
```

`ServiceModelReg.exe` is a legitimate, Microsoft-signed component of the .NET Framework that almost never executes on a normal desktop. Convenient host: signed, present on every Windows install with .NET, unremarkable in a process list to anyone not looking closely. The `explorer.exe` string is probably the fallback, or the target for the elevated relaunch.

## This Is Not a Downloader

Loaders of this shape are usually assumed to fetch their payload. This one does not. Stage 1 has no network capability at all.

- No networking DLL is imported. The full list is `advapi32`, `bcrypt`, `kernel32`, `ole32` and seven CRT stubs. No `wininet`, no `winhttp`, no `ws2_32`, no `urlmon`, no `dnsapi`.
- None of the 30 decrypted strings is a networking API, a URL, or a hostname.
- The only URLs in the binary are Microsoft manifest schema references in `.rsrc`.

The payload travels inside the file, in `.gfx`. Two practical consequences. Blocking the C2 does nothing to prevent initial execution, persistence or privilege escalation, because all of that completes before any network traffic exists. And an air-gapped or network-restricted sandbox still sees the full stage-1 chain, and that is why the sandbox reports agree so closely despite differing network conditions.

The C2 belongs to stage 2. VirusTotal has never recorded a file served from `bsc.blockrazor[.]xyz` (`downloaded_files` is empty), while ten distinct samples are recorded communicating with it. Beacon and exfiltration endpoint, not a payload host.

## The Injector, Function by Function

The decrypted string table tells you which APIs the loader knows about. Following cross-references from each accessor tells you what it does with them, and what it does is a complete manual PE loader.

### Every API is a lazy-resolve stub

Each runtime-imported function gets its own wrapper, all with the same shape:

```c
// fcn.1400052e0, the NtUnmapViewOfSection wrapper
if (cached_ptr == NULL) {
    get_str_NtUnmapViewOfSection(...);      // decrypt the name
    cached_ptr = resolve(ntdll_handle);     // fcn.1400033d0, GetProcAddress equivalent
}
push_pinvoke_frame(&frame);                 // fcn.14004a300
result = (*cached_ptr)(hProcess, base);
pop_pinvoke_frame(&frame);                  // fcn.14004a350
```

The resolver at `0x1400033D0` has 22 cross-references, so 22 APIs come through this path.

The `fcn.14004a300` / `fcn.14004a350` bracket around every native call is a NativeAOT **P/Invoke transition frame**, and it is the single hardest piece of evidence that this binary is compiled C#. Straight from [`reports/disasm/pinvoke_transition_frames.asm`](https://github.com/taogoldi/analysis_data/blob/main/animateclipper_aug_2026/reports/disasm/pinvoke_transition_frames.asm):

```asm
; ---- 0x14004A300: enter native code ----
0x14004a300  44 8b 15 6d 54 ..   mov  r10d, dword [0x1400ef774]  ; TLS index
0x14004a307  65 4c 8b 1c 25 ..   mov  r11,  qword gs:[0x58]      ; TEB -> ThreadLocalStoragePointer
0x14004a310  4f 8b 1c d3         mov  r11,  qword [r11 + r10*8]  ; thread-local structure
0x14004a314  41 ba 30 00 00 00   mov  r10d, 0x30
0x14004a31a  4d 03 d3            add  r10,  r11                  ; -> Thread object
0x14004a31d  4c 8b 1c 24         mov  r11,  qword [rsp]          ; return address
0x14004a321  4c 89 51 10         mov  qword [rcx + 0x10], r10    ; frame->m_pThread
0x14004a325  48 89 69 08         mov  qword [rcx + 8],    rbp    ; frame->m_FramePointer
0x14004a329  4c 89 19            mov  qword [rcx],        r11    ; frame->m_RIP
0x14004a32c  4c 8d 5c 24 08      lea  r11,  [rsp + 8]
0x14004a331  c7 41 18 00 80 ..   mov  dword [rcx + 0x18], 0x8000 ; frame->m_Flags
0x14004a338  4c 89 59 20         mov  qword [rcx + 0x20], r11    ; frame->m_PreservedRegs
0x14004a33c  49 89 4a 48         mov  qword [r10 + 0x48], rcx    ; Thread->m_pTransitionFrame = frame
0x14004a340  c3                  ret

; ---- 0x14004A350: return to managed code ----
0x14004a350  48 8b 51 10         mov  rdx, qword [rcx + 0x10]    ; frame->m_pThread
0x14004a354  48 c7 42 48 00 ..   mov  qword [rdx + 0x48], 0      ; clear m_pTransitionFrame
0x14004a35c  83 3d 25 f0 09 ..   cmp  dword [0x1400e9388], 0     ; GC pending?
0x14004a363  75 01               jne  0x14004a366
0x14004a365  c3                  ret
0x14004a366  e9 75 da ff ff      jmp  0x140047de0                ; slow path: rendezvous with the collector
```

Before leaving managed code the runtime publishes a frame describing the last managed state, return address, frame pointer, stack pointer, into the thread object. On the way back it clears the frame and polls a global GC flag. That is how a precise garbage collector suspends a thread currently sitting inside a Win32 call. A C++ program has no reason to do any of it.

A separate initialiser at `0x1400032B0` resolves seven `ntdll` functions into a table, guarded by an init flag at `0x1400E5030`, in a fixed order: `NtWriteVirtualMemory`, `NtReadVirtualMemory`, `NtAllocateVirtualMemory`, `NtProtectVirtualMemory`, `NtGetContextThread`, `NtSetContextThread`, `NtFreeVirtualMemory`.

Not every allocation is remote. `fcn.140002D60` calls `NtAllocateVirtualMemory` with a process handle of `0xFFFFFFFFFFFFFFFF`, the pseudo-handle for the current process, to allocate `MEM_COMMIT | MEM_RESERVE` (`0x3000`) `PAGE_READWRITE` (`4`) pages and copy a UTF-16 string into them. That is the loader allocating its own string buffers through `ntdll` instead of the heap. Worth remembering when triaging: a hit on `NtAllocateVirtualMemory` is not automatically injection, and the process handle argument is what separates the two cases.

### The orchestrator at `0x140005420`

| Step | Address | Call | What it does |
|---|---|---|---|
| 1 | `0x140005420` | `fcn.1400034C0` | Resolve the API table |
| 2 | `+0x5E` | `fcn.140005880` | Prepare the payload context |
| 3 | inline | header check | `MZ` at 0, `PE\0\0` at `e_lfanew`, optional-header magic `0x20B` |
| 4 | `+0x7E` | `fcn.140005940` | `CreateProcessW`, host created suspended |
| 5 | `+0x9A` | `fcn.140005B20` | Read the remote PEB to get the host's image base |
| 6 | `+0xC0` | `fcn.1400052E0` | `NtUnmapViewOfSection` on the host image |
| 7 | `+0xE6` | `fcn.140005D40` | `NtAllocateVirtualMemory` at the payload's preferred base, falling back to any base |
| 8 | `+0x10D` | `fcn.140005F40` | Apply base relocations |
| 9 | `+0x11C` | `fcn.140005910` | Patch `ImageBase` in the payload's own header |
| 10 | loop | `fcn.140005DC0` | `NtWriteVirtualMemory` per section |
| 11 | `+0x1C0` | `fcn.140005110` | Allocate the working buffers, including a `0x1000` `PAGE_READWRITE` region |
| 12 | `fcn.1400056F0` | `fcn.140005380` | Get context, write the entry register, set context, `ResumeThread` |

Step 11 is named for what it does: `fcn.140005110` allocates buffers and returns a descriptor struct. No `alloc_base + AddressOfEntryPoint` arithmetic, no context manipulation. All of that lives in `fcn.1400056F0`.

Two details matter to anyone trying to recover the payload.

**The payload is a full PE, not shellcode.** Step 3 validates `MZ`, `PE\0\0` and the optional-header magic before anything else happens, and step 10 walks a section table copying section by section. A shellcode loader would do none of that. Whatever comes out of `.gfx` is a complete executable image.

**The loader relocates it properly.** `fcn.140005F40` is a textbook `.reloc` walker:

```c
delta = new_base - original_base;
for each relocation block {
    page_rva    = block[0];
    block_size  = block[1];
    if (block_size < 8) return;
    for each 16-bit entry after the 8-byte block header {
        type   = entry >> 12;
        offset = entry & 0xFFF;
        if (type == 10 || type == 3)              // DIR64 or HIGHLOW
            *(image + page_rva + offset) += delta;
    }
}
```

Type 10 is `IMAGE_REL_BASED_DIR64`, type 3 is `IMAGE_REL_BASED_HIGHLOW`, so 64-bit and 32-bit payloads are both supported. `fcn.140005910` then writes the new base into the payload's optional header, choosing offset `0x18` for PE32+ and `0x1C` for PE32, correct in each case. Between that and the `Wow64` context APIs, the loader is ready to carry either architecture.

### The stage-2 cipher

The `.gfx` blob is not decrypted with the string keystream. It has its own cipher, and both halves of it sit in the binary.

`fcn.140006380` is a bitwise CRC-32C step. The constant `0x82F63B78` is the Castagnoli polynomial in reversed form:

```c
uint32_t crc32c_step(uint32_t a, uint32_t b) {
    uint32_t v = a ^ b;
    for (int i = 0; i < 32; i++)
        v = (v >> 1) ^ (-(v & 1) & 0x82F63B78);
    return v;
}
```

`fcn.140006340` is the decryptor built on it:

```c
state = crc32c_step(seed_a, seed_b);
for (i = 0; i < len; i++) {
    state  = crc32c_step(state, i);
    buf[i] ^= (uint8_t)state;          // low byte only
}
```

A CRC-32C chain, one round per output byte, the same shape as the string decryptor with a different primitive. Two hand-rolled stream ciphers in one loader, neither of them standard.

That routine handles the small descriptor fields. The payload itself goes through `fcn.1400063e0`, which takes a **32-byte key and a 12-byte nonce**. Both pieces of key material are static and sit in the file, stored as NativeAOT byte arrays with the same 16-byte object header as the encrypted strings:

```
key   @ 0x1400E4370  (0x20 bytes)
      05 26 11 89 B7 6A A2 42 23 A1 88 36 C2 6C 15 F0
      56 4D 76 6B 92 31 9A D5 C2 04 42 3B 61 9C D5 AF

nonce @ 0x1400E43A8  (0x0C bytes)
      B1 40 6C 4A 3F 24 42 19 1B 7E E3 BC
```

Nothing here derives from the environment. Stage 2 is a **static** recovery problem.

`fcn.1400063e0` is the loader's third hand-rolled cipher. Fingerprinting the whole binary finds no ChaCha constants, no AES S-box and no AES-NI instructions in the function, and the instruction mix is ARX. The core is a custom 64-bit ARX permutation over four words, twelve rounds, in counter mode, whose state layout and mixing resemble SipHash. It is not SipHash, and calling it that would overstate what has been read: the rotation and xor constants for the remaining rounds are still unrecovered, so the round function has not been reimplemented and no equivalence is demonstrated.

```asm
; per output block, rbx = block counter
v0 = ( key[0..8]  ^ nonce[0..8]  ) + counter
v1 =   key[8..16] ^ nonce[8..16]
v2 =  ~nonce[0..8]  ^ key[16..24]
v3 = (~nonce[8..16] ^ key[24..32]) ^ counter

0x140006520  add rsi, rdi      ; v0 += v1
0x140006523  rol rdi, 0x1f     ; v1 = ROTL64(v1, 31)
0x140006527  xor rdi, rsi      ; v1 ^= v0
0x14000652a  add rbp, r14      ; v2 += v3   ...
```

The `not` applied to the nonce words during setup echoes SipHash's initialisation, with nonce material where SipHash uses its published constants. A lead for whoever finishes the reimplementation, not an identification.

Decryption is nested, which is why the descriptor first looked self-contradictory. The outer call unlocks a container; offsets and sizes inside it are unmasked with CRC-32C-derived values (`crc32c(crc32c(x,1), x ^ 0x6C62272E)` for the offset, `...,2` for the size); two small structures are then unwrapped with the CRC keystream under the ASCII tags `0x70617273` (`"pars"`) and `0x75616362` (`"uacb"`); and a **second** `fcn.1400063e0` call, keyed from `container+0x24` with a nonce from `container+0x14`, unlocks the payload proper. In the locator at `0x140035200` the seed derivation is `crc32c_step(x, rva ^ 0x6C62272E)`, where `0x6C62272E` is the top word of the FNV-1a 128-bit offset basis and `rva` comes from the descriptor.

### The payload descriptor

The descriptor sits at `0x1400E4400` and is tagged in plain ASCII:

```
0x1400E4420   "GFX0INFO"   rva = 0x000FC000   size = 0x002C6499
0x1400E4560   "HOLW"       0xCAFE0000 sentinel, ImageBase 0x140000000, entry fields
0x1400E4590   "PERMINF0"   section count = 9, table follows at 0x1400E45A4
```

`GFX0INFO` matches the `.gfx` section's RVA and virtual size exactly. The `0xCAFE0000` family of sentinels appears in the locator as an "unbuilt template" check (`!= 0xCAFE0001 && != 0xCAFE0002`), so these fields are placeholders a builder patches per campaign.

The section table `PERMINF0` points at is the same one the hollowing loop walks, 12 bytes per entry as RVA, size, and a permission word:

| # | RVA | Size | Perm |
|---|---|---|---|
| 0 | `0x00001000` | 1,026,609 | `0x20` |
| 1 | `0x000FC000` | 1,275,064 | `0x02` |
| 2 | `0x00234000` | 369,576 | `0x04` |
| 3 | `0x0028F000` | 22,284 | `0x02` |
| ... | | | |

One consequence is worth spelling out, because the obvious version of the argument is not valid. "No section at RVA 0" proves nothing on its own; that is true of every normal PE, whose headers occupy RVA 0 through `SizeOfHeaders` while sections start at `0x1000`. What does the work is that the container stores **section bodies only**, not the image. The declared sizes sum to 2,878,373 against a `.gfx` virtual size of 2,909,337, the descriptor carries the metadata needed to rebuild the image around them, and section 0 sits at RVA `0x1000`. Offset 0 of the decrypted blob is the first byte of section 0's code, so an `MZ` there was never possible under any key.

Anyone finishing the ARX permutation gets a strong oracle out of that: `PERMINF0` marks section 0 executable at RVA `0x1000`, so a correct key must produce plausible x86-64 at the start of that slice.

### Getting stage 2 out today

Three dump points, best first:

1. **At `0x140005420` entry**, the payload pointer sits at `[arg1 + 0x18]`, decrypted and not yet relocated. Best option: file-aligned image with its original `ImageBase`.
2. **At the resolved `NtWriteVirtualMemory`**, catching each section as it is written. Section-aligned and already relocated, so it needs realignment and the relocation delta backed out.
3. **From the hollowed host after `ResumeThread`**, the messiest.

Context structure offsets: `+0x18` payload image, `+0x20` size, `+0x40` entry RVA, `+0x4C` section count, `+0x50` host process handle, `+0x58` host thread handle.

Emulating stage 1 to reach that point is unattractive. A NativeAOT binary initialises a garbage collector and type system before any of the malware's own code runs, and emulators built for conventional PE malware rarely survive it. One breakpoint is the shorter path. Do it on a VM with no network, and do not let execution run past `ResumeThread` on anything routable; that hands control to the clipper.

## Campaign Context

The platform grouped this sample with two siblings on shared imphash and rich header, meaning the same import profile and the same build environment. VirusTotal's similarity set extends that to six binaries, every one carrying the `aethsync.dll` identity:

| SHA-256 (truncated) | VT detections |
|---|---|
| `99dc1ea286648ec882d71ab5071e3072c702e51707708431` | 56 |
| `21bf44a654a0059f7bb974ffe6252db63e998d5f95937454` (this sample) | 52 |
| `cdb9558b47af57c3f433ddb40b44686a71a12d0ee523add5` | 49 |
| `985db456011618574cc7ec6fed5e2be3bd43ceb50d6f24e6` | 49 |
| `38060481b1e545de7f4cce80fb9ec20be10d83b9796977c8` | 38 |
| `a6b5ae508afafcda6d59864b8795a3b2532b56b67ee989e5` | 27 |

A detection spread from 27 to 56 across a single build family is useful on its own. Same code, wrapped the same way, landing anywhere between "clearly malicious" and "half the industry misses it" depending on which build a victim receives.

One sibling was retrieved and compared directly:

| | This sample | Sibling `cdb9558b` |
|---|---|---|
| Compiled | 2026-07-11 | 2026-07-16 |
| Imphash | `d7a140ad86093e229082e6f8b7493b94` | `5036645afc7501c7a590454c4f954725` |
| `.gfx` size | 2,909,696 | 2,262,528 |
| `.gfx` entropy | 7.9999 | 7.9999 |
| Sections | 7, identical layout | 7, identical layout |
| Cipher constants | present | present |

Five days apart, different payload, different import profile, structurally and cryptographically identical. The builder is being re-run per campaign, not rewritten.

### The dropper is a Go binary

The execution parent, `L263919LLL.exe` (`43edee1eabae3c4ebd3bb2d21f6c24d0984b38f51dbeb74b425ccd53f2a71399`, 43 detections), was pulled and examined. A 32-bit PE built with **Go 1.25.4**, carrying `.symtab`, `Go build ID`, `main.main` and the usual `runtime.*` symbol set. Its timestamp field is zeroed, normal for Go.

GoReSym recovers the build metadata and symbol table:

```
GoVersion : go1.25.4          GOARCH : 386        GOOS : windows
Module    : SIRDCU (devel)    CGO_ENABLED : 0     GO386 : sse2
-trimpath : true              Deps : none
```

Three things stand out. `-trimpath` is set, so the developer deliberately stripped build paths. The module is named `SIRDCU` with version `devel`, meaning it was never published. And of the 186 recovered functions, the 16 in `main` carry randomised names:

```
main.pzqsdfo              main.dolcydxfzhlgouroumgtc   main.okmlmlaommafkebvvn
main.tupdburunbgweozgrwzu main.bfirvnblmdhmyvcivmx     main.lvjptwawiprvpqalpccan
main.ujvpwyeqojwxkkkzfjma main.Yzblvtaxhhkgrghfikj     main.Zygjbqpuxfbwcoe
main.iqhfmzbusjznmhu       main.oulvpmkxmgtm            main.azzplsuqapfghpvhen
main.zjijrdecfutnvpxy      main.main
```

Randomised identifiers plus `-trimpath` is consistent with a Go source obfuscator such as garble, though the naming alone does not identify which one and a determined developer could do the same by hand. Contrast that with stage 1, where the developer left `Moonshine.Core` and `aethsync` in place. Different hands, or different discipline.

Its import and string set is broader than the loader's: `crypto/tls`, `crypto/x509`, `http2client` and `http2server` for network transport, plus `LogonUserW`, `DuplicateTokenEx`, `NetUserAdd`, `NetUserDel`, `NetShareAdd`, `NetShareDel`, `LookupAccountSidW`, `CreateNamedPipeW`, `WSASocketW` and `Process32FirstW`. Account creation, share manipulation and token duplication are a materially different capability set from the clipper it delivers.

No embedded PE hides inside it: per-section entropy runs 3.87 to 6.91, highest in `.rdata`, with no high-entropy blob anywhere. The dropper fetches its payload; it does not carry it.

One string is worth flagging without over-reading it: `predmetov=%d`, a Latin transliteration of a Russian word for "of items". A single token is not attribution, but it is a language artefact in a binary that otherwise has none.

The delivery chain is three languages deep: a Go dropper, a C# NativeAOT loader, and an encrypted stage-2 clipper.

MalwareBazaar tags the sample `web_download`. First submission was 2026-07-13, two days after the compile timestamp, and Kaspersky's telemetry shows activity through 2026-07-30, so the campaign was live for at least three weeks around this build.

## Kill Chain

![Kill chain flowchart](/assets/images/posts/animateclipper/killchain.png)

1. A separate dropper (`L263919LLL.exe`) delivers and runs the loader.
2. The loader decrypts its API name table with the keystream cipher at `0x1400012C0` and `0x1400014C0`.
3. APIs are resolved at runtime via `LoadLibraryW` and `GetProcAddress`, keeping the import table clean.
4. `OpenProcessToken` and `GetTokenInformation` test the current integrity level.
5. If not elevated, `CoGetObject` on the `CMSTPLUA` elevation moniker obtains an auto-elevated COM object and relaunches with administrator rights.
6. `CreateMutexW` creates `Global\MBDCABCFC4EE8E3B7` to enforce a single instance.
7. `GetModuleFileNameW`, `ExpandEnvironmentStringsW` and `CopyFileW` place a byte-identical copy in the user's Startup folder.
8. The `.gfx` section is decrypted in memory with the twelve-round ARX cipher, keyed from the static 32-byte key and 12-byte nonce in the binary.
9. A host process is created suspended and hollowed via the `Nt*` sequence, then resumed.
10. Stage 2 runs inside the signed host and performs the clipper activity, resolving `bsc.blockrazor[.]xyz`.

## Anti-Analysis: Chosen Versus Inherited

Worth separating what this developer chose to do from what their toolchain did for them, because the two get conflated whenever NativeAOT malware is written up, including in the framing of this post's own title.

**Deliberate.** Each of these costs the developer effort and serves no purpose except defeating analysis:

- **Encrypted API name table.** No hollowing or COM API appears as a plaintext string or as an import. Thirty strings, each with its own seed and its own accessor thunk, is work someone chose to do.
- **`Nt*` layer instead of kernel32 wrappers.** Resolving `NtUnmapViewOfSection` and friends from an encrypted name table at runtime, instead of importing `VirtualAllocEx`, empties the import table of anything incriminating. Note this is runtime name resolution, not API hashing: the plaintext name is reconstructed and passed to a `GetProcAddress` equivalent, so a memory-resident analyst still sees the real string.
- **Vectored exception handler** installed via `RtlAddVectoredExceptionHandler`, useful both for catching analysis probes and for regaining control after a deliberate fault.
- **A separate 256-bit cipher over the payload.** Strings and payload use different ciphers, so recovering the string keystream, which is most of this post, gets a defender no closer to stage 2. The layout helps too: `PERMINF0` declares no section at RVA 0 and the headers live in the descriptor rather than in `.gfx`. The measure is real, though the key ships in the binary, so it raises the effort without preventing recovery.

**Inherited.** Analysis-resistant, but explained by the build mode and not by intent:

- **NativeAOT compilation.** In practice the single most effective measure here, and it may not have been an anti-analysis decision at all. NativeAOT is a supported Microsoft build mode chosen routinely for startup time, single-file deployment, and not shipping a runtime dependency. Losing the CLR header and IL is a consequence of ahead-of-time compilation, not a feature someone bolted on. Nothing in the binary settles the motive, so the claim worth making is about outcome: whatever the reason it was chosen, it defeats every managed-analysis workflow, and it does so without a packer, an obfuscator licence, or an unpacking stub to detect. High effectiveness with zero attribution signal is what makes it interesting.
- **3.9 MB of statically linked runtime.** The garbage collector and type system inflate the binary and bury 700 KB of loader logic in runtime bulk, which raises the cost of finding the malicious code. A property of static linking, not a choice.
- **`VirtualAlloc` in the import table.** Present because the GC needs it. Reading it as an injection indicator would be a mistake, and it is a neat example of NativeAOT breaking import-based heuristics in both directions.

**Present in the build set, though not in this sample:**

- **Backdated sibling.** A related sample in the queue carried a 2017-09-12 compile timestamp while its rich header showed build IDs in the 33145 to 35726 range, far too recent for a 2017 binary. This sample's own timestamp (2026-07-11) is consistent with its rich header and appears genuine, but the trick is present in the wider set and defeats any triage rule that filters on timestamp alone.

Note what is **absent**: no anti-VM check, no timing check, no debugger-presence test beyond the VEH, no self-modifying code, nothing derived from the environment. Every key in this binary, including the 256-bit one, is static and shipped in the file. For a loader whose whole job is to survive analysis long enough to hollow a process, that is a thin set, and it reinforces the reading that NativeAOT was doing most of the work by accident.

## Observations and Attribution Notes

The developer's assembly name, `Moonshine.Core`, survived into the shipped binary, as did the product identity `aethsync`. Neither is obfuscated. A build pipeline sophisticated enough to use NativeAOT and careless enough to leave the project name in the metadata reads as a competent developer on a stock toolchain, not a mature malware-development operation with a hardened build process.

The cipher constants point the same way. Using the golden-ratio constant and the Mersenne Twister multiplier together is the work of someone assembling something that looks strong from recognisable pieces instead of reaching for AES, which the platform already links against for other purposes.

No PDB path, no signing certificate, and one Russian-language token in the dropper. Not enough to support an attribution claim beyond "commodity crimeware".

## Code Weaknesses

1. **The keystream depends only on a 32-bit seed that ships in the instruction stream.** Every string is statically recoverable without running the sample.
2. **The three cipher constants are hardcoded in `.text`** as little-endian literals, which makes a high-fidelity byte-pattern rule trivial to write.
3. **The mutex name `Global\MBDCABCFC4EE8E3B7` is a build-time constant**, identical across every observed execution. Detection opportunity and vaccination opportunity both.
4. **The self-copy is byte-identical to the parent.** One hash covers the delivered file and the persisted file.
5. **The `.gfx` section name is not emitted by any Microsoft toolchain**, and combining it with an entropy test yields a strong structural signature.
6. **The developer's assembly name `Moonshine.Core` is retained**, giving a durable string pivot across builds.
7. **The shipped identity `aethsync` is present in eight of the nine known builds**, which is how the similarity cluster was assembled in the first place.
8. **The UAC bypass is a decade-old public technique** with well-known detection guidance, so any environment already watching `CMSTPLUA` elevation will see it.
9. **The `yea8hw` filename prefix repeats across builds**, weakening the randomised-filename persistence.
10. **The second mutex is a malformed SID** (`update-S-2-5-26-...` rather than `S-1-...`), a distinctive typo that survives as an indicator.

## IOC Appendix

Network and host indicators below come from public sandbox detonations, not from the binary, corroborated across multiple independent sandboxes. Everything in the YARA section comes from the file itself.

### Network

| Indicator | Context |
|---|---|
| `bsc.blockrazor[.]xyz` | Stage-2 C2, resolved in two independent sandboxes, 12 VT detections. The `bsc` label invites a Binance Smart Chain reading, but three letters in a hostname are not evidence: no wallet regex, address list or stage-2 traffic supports it. Speculative. |

**Observed during detonation, not indicators.** Listed so nobody re-derives them and blocks them: `1.1.1[.]1:53` and `162.159.36[.]2:53` are Cloudflare DNS resolvers, and `assets.adobedtm[.]com` appeared in one sandbox as benign telemetry from the analysis environment. None is attacker-controlled.

### File / Registry / Host

| Indicator | Context |
|---|---|
| `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\<random>.exe` | Persistence, byte-identical self-copy |
| `Global\MBDCABCFC4EE8E3B7` | Single-instance mutex, constant across builds |
| `update-S-2-5-26-24247216-2331352693-3112950123` | Secondary mutex, malformed SID form |
| `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\ServiceModelReg.exe` | Hollowing host observed in four sandboxes |
| `C:\Windows\explorer.exe` | Hunting artifact. Present as a decrypted string; no sandbox showed it used as the hollow target. |
| `HKCU\...\SystemCertificates\Root\Certificates\0174E68C97DDF1E0EEEA415EA336A163D2B61AFD\Blob` | Root certificate installed during detonation |
| `aethsync.exe`, `aethsync.dll` | Shipped file identity |
| `%TEMP%\d3d9.<digits>.` | Dropped INI, 0 detections |

### Hashes

| SHA-256 | Role |
|---|---|
| `21bf44a654a0059f7bb974ffe6252db63e998d5f95937454d45da4d700267471` | This sample, stage-1 loader |
| `99dc1ea286648ec882d71ab5071e3072c702e5170770843177807179c63f4593` | Sibling build, imphash `d7a140ad...`, `.gfx` 2,909,696 |
| `985db456011618574cc7ec6fed5e2be3bd43ceb50d6f24e6dcf2579942730da3` | Sibling build, imphash `d7a140ad...`, `.gfx` 2,909,696 |
| `38060481b1e545de7f4cce80fb9ec20be10d83b9796977c82c984c03a173b442` | Sibling build, imphash `d7a140ad...`, `.gfx` 2,909,696 |
| `a6b5ae508afafcda6d59864b8795a3b2532b56b67ee989e52552005240c0a34e` | Sibling build, imphash `d7a140ad...`, `.gfx` 2,909,696 |
| `cdb9558b47af57c3f433ddb40b44686a71a12d0ee523add5fb1ec28588209945` | Variant 2, imphash `5036645a...`, `.gfx` 2,262,528 |
| `43edee1eabae3c4ebd3bb2d21f6c24d0984b38f51dbeb74b425ccd53f2a71399` | Execution parent, `L263919LLL.exe`, Go dropper |

All six loaders match all three loader rules below. The dropper matches none of them, correctly, since it is a Go binary sharing no code with the loader.

## MITRE ATT&CK Mapping

Split by how each mapping is supported. Stage 2 is still encrypted, so anything describing clipper behaviour is inherited from family reporting, not observed in the binary.

**Statically proven in this binary**

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| Defense Evasion | Obfuscated Files or Information | T1027 | Encrypted API name table, keystream at `0x1400012C0` |
| Defense Evasion | Encrypted/Encoded File | T1027.013 | 2.9 MB encrypted `.gfx` payload, entropy 7.9999 |
| Defense Evasion | Process Injection: Process Hollowing | T1055.012 | `NtUnmapViewOfSection` to `NtSetContextThread` to `ResumeThread`, decrypted and ordered |
| Defense Evasion | Abuse Elevation Control Mechanism: Bypass UAC | T1548.002 | `Elevation:Administrator!new:{3E5FC7F9-...}` CMSTPLUA moniker |
| Defense Evasion | Masquerading | T1036 | `aethsync` product identity; hollow target is a signed Microsoft binary |
| Persistence | Boot or Logon Autostart: Startup Folder | T1547.001 | Self-copy via `GetModuleFileNameW` / `CopyFileW` into Startup |
| Execution | Native API | T1106 | `Nt*` routines resolved from an encrypted name table, absent from the import table |
| Execution | Inter-Process Communication: COM | T1559.001 | `CoGetObject` against the elevation moniker |

**Dynamically observed only, in public sandbox reports**

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| Defense Evasion | Subvert Trust Controls: Install Root Certificate | T1553.004 | Root certificate blob written under `HKCU\...\SystemCertificates\Root`. Not reachable in stage-1 code, so plausibly stage-2 behaviour. |

**Family-attributed**

| Tactic | Technique | ID | Basis |
|---|---|---|---|
| Impact | Financial Theft | T1657 | AnimateClipper is a clipper by family definition. No clipboard code exists in stage 1; the payload that would contain it is still encrypted. The `bsc` in the C2 hostname suggests Binance Smart Chain but is not evidence of it. |

### Two mappings that do not survive contact with the binary

**T1134 Access Token Manipulation** is the obvious mapping to reach for, on the strength of `OpenProcessToken`, `LookupPrivilegeValueW` and `AdjustTokenPrivileges` in the import table. It is wrong, and so is the obvious version of the argument against it.

The imported copies are not malware code. All three are called only from `fcn.140056770`, which requests `SeLockMemoryPrivilege` and then calls `GetLargePageMinimum`. That is the NativeAOT garbage collector's large-page allocation path, straight out of [`reports/disasm/gc_largepage_not_t1134.asm`](https://github.com/taogoldi/analysis_data/blob/main/animateclipper_aug_2026/reports/disasm/gc_largepage_not_t1134.asm):

```asm
0x1400567a5  lea  rdx, str.SeLockMemoryPrivilege     ; "SeLockMemoryPrivilege"
0x1400567ac  call [ADVAPI32.dll_LookupPrivilegeValueW]
0x1400567c4  mov  dword [NewState], 1                ; PrivilegeCount = 1
0x1400567cc  mov  dword [var_4ch], 2                 ; SE_PRIVILEGE_ENABLED
0x1400567d4  call [KERNEL32.dll_GetCurrentProcess]
0x1400567df  mov  edx, 0x20                          ; TOKEN_ADJUST_PRIVILEGES
0x1400567e7  call [ADVAPI32.dll_OpenProcessToken]
0x14005680c  call [ADVAPI32.dll_AdjustTokenPrivileges]
0x140056821  call [KERNEL32.dll_CloseHandle]
;   ... falls through to GetLargePageMinimum
```

Same trap as `VirtualAlloc` being present because the GC needs it. On a statically linked binary the import table describes the runtime far more than it describes the program.

The loader **does** touch tokens, just not through those imports. `OpenProcessToken` and `GetTokenInformation` both appear in the decrypted name table and are resolved at runtime, and that is how the elevation check works. So the mapping fails on the technique rather than on the evidence: reading a token to discover whether the process is already elevated is not access token *manipulation*. No `DuplicateTokenEx`, no `ImpersonateLoggedOnUser`, no `SetThreadToken`, and the only `AdjustTokenPrivileges` in the binary belongs to the GC. The check is a precondition for the UAC bypass and is covered by **T1548.002**.

Two different mistakes were available here and they point opposite ways: mapping T1134 from the imports (wrong, they are runtime), and concluding from that discovery that the loader never touches tokens at all (also wrong, it resolves them dynamically). On a NativeAOT target the import table and the decrypted string table are separate universes.

**T1082 System Information Discovery** rests on `RtlGetCurrentPeb`, which the runtime calls constantly and which supports no discovery conclusion on its own.

**T1027.002 Software Packing** belongs as **T1027.013** instead. Stage 1 is not packed: `.text` entropy is 6.64 and the code disassembles directly with no unpacking stub. What is encrypted is an embedded payload, a different technique.

## Detection

Five rules, all in [`detection/`](https://github.com/taogoldi/analysis_data/tree/main/animateclipper_aug_2026/detection) and mirrored at [taogoldi/YARA/loaders/animateclipper](https://github.com/taogoldi/YARA/tree/main/loaders/animateclipper).

| Rule | Signal | Fidelity |
|---|---|---|
| [`AnimateClipper_StringDecryptor_Constants`](https://github.com/taogoldi/YARA/blob/main/loaders/animateclipper/animateclipper.yar) | The keystream constants together in a PE | Medium, see the measured FP rate below |
| [`AnimateClipper_Loader_GfxSection`](https://github.com/taogoldi/YARA/blob/main/loaders/animateclipper/animateclipper.yar) | NativeAOT markers plus a high-entropy `.gfx` section | Medium |
| [`AnimateClipper_Composite`](https://github.com/taogoldi/YARA/blob/main/loaders/animateclipper/animateclipper.yar) | Constants plus NativeAOT and the `aethsync` / `Moonshine.Core` identity, x64 only | High |
| [`AnimateClipper_PayloadContainer`](https://github.com/taogoldi/YARA/blob/main/loaders/animateclipper/animateclipper.yar) | Overlay stage-2 container: magic, self-consistent length, high entropy | Medium |
| [`AnimateClipper_GoDropper_SIRDCU`](https://github.com/taogoldi/YARA/blob/main/loaders/animateclipper/animateclipper_dropper.yar) | The dropper's unpublished Go module name in its buildinfo blob | High |

All five compile under yara-python 4.x and were validated against the nine loader builds available here. Five siblings came from VirusTotal; the three April and May builds were recovered from our own collection by running these rules over it:

| Build | Stage 2 | Rules matched |
|---|---|---|
| `21bf44a6...` (this sample) | `.gfx` | Constants, GfxSection, Composite |
| `cdb9558b...` | `.gfx` | Constants, GfxSection, Composite |
| `985db456...` | `.gfx` | Constants, GfxSection, Composite |
| `38060481...` | `.gfx` | Constants, GfxSection, Composite |
| `a6b5ae50...` | `.gfx` | Constants, GfxSection, Composite |
| `99dc1ea2...` | `.gfx` | Constants, GfxSection, Composite |
| `eca1963a...` (filed as "Formbook") | `.gfx` | Constants, GfxSection, Composite |
| `be06aab9...` (filed as "SnakeKeylogger") | overlay | Constants, Composite, PayloadContainer |
| `3ee1860c...` (filed as "AgentTesla") | overlay | Constants, Composite, PayloadContainer |
| Go dropper | n/a | GoDropper_SIRDCU only |

Nine of nine loaders, with the dropper matched by its own rule and by none of the loader rules.

### The false-positive numbers

True positives are the easy half. Matching every known build proves sensitivity and says nothing about specificity, so the constants were tested against a random, deterministically ordered sample of **2,000 PE files** drawn from an unrelated 20,607-sample corpus:

| Constant | Samples containing it | Rate |
|---|---|---|
| `0x9E3779B9` (golden ratio) | 193 | 9.65% |
| `0x6C078965` (Mersenne Twister multiplier) | 99 | 4.95% |
| `0xA7B3C1D5` (this family's seed XOR) | 7 | 0.35% |
| Golden ratio **and** MT multiplier | 17 | 0.85% |
| **All three together** | **4** | **0.20%** |

The first two numbers are the point. `0x9E3779B9` turns up in roughly one PE in ten because it is the golden-ratio constant used by TEA, XXTEA, `boost::hash_combine` and a long list of ordinary hash functions. `0x6C078965` appears in one in twenty because it initialises MT19937, so every binary statically linking a C++ `std::mt19937` carries it. Neither is malicious and neither is rare.

Of the four samples matching all three, one is `99dc1ea2...`, a known build of this family, which our model incidentally labels `asyncrat` for the same reason it mislabelled this sample. Two more carry NativeAOT markers without a `.gfx` section and are plausible unreported members worth a look. But `74164a66...` is 665 KB with **no NativeAOT markers and no `.gfx` section**, so it cannot be this family. A true false positive.

Hence the Medium rating on the constants-only rule. A 0.20% rate projects to roughly 40 false hits across the 20,607 PE samples available here: fine for retrohunting, not fine for blocking. Specificity comes from the conjunction. Gating the constants on NativeAOT markers rejects the confirmed false positive outright, and that is why `AnimateClipper_Composite` is structured the way it is.

The whole set was then run across **2,977 unrelated corpus samples**, 900 of them Go binaries chosen specifically to attack the dropper rule. **Zero false positives observed.** Zero observed is not a measured rate of zero: with no events in 2,977 trials the one-sided 95% upper bound is about 0.10%, and that is the honest way to state it. An earlier dropper rule keyed on garbled symbol names instead of the module name scored 38 and was discarded; the comment in [`animateclipper_dropper.yar`](https://github.com/taogoldi/YARA/blob/main/loaders/animateclipper/animateclipper_dropper.yar) records why.

### Durability across builds

Variant 2 is the useful test, because it is not a copy. Its imphash is `5036645afc7501c7a590454c4f954725` against this sample's `d7a140ad86093e229082e6f8b7493b94`, its `.gfx` payload is 2,262,528 bytes against 2,909,696, and it was compiled five days later.

Compare the two builds byte for byte and very little changed. The loader stub at `0x140001000..0x140002000` is **95.2% byte-identical**, the byte decryptor at `0x1400012C0` is 94.1% identical, and the cipher core sits at the *same virtual address* (`0x140001339`) with the same instruction bytes in both:

```asm
; variant 2, cdb9558b47af57c3..., at the same VA as the main sample
0x140001339  81 f3 d5 c1 b3 a7   xor  ebx, 0xa7b3c1d5
0x14000134e  81 f3 b9 79 37 9e   xor  ebx, 0x9e3779b9
0x140001354  c1 c3 0d            rol  ebx, 0xd
0x140001357  44 69 c1 65 89 ..   imul r8d, ecx, 0x6c078965
0x14000135e  41 03 d8            add  ebx, r8d
```

Different imports, different payload, the same loader and the same thirty seeds. An imphash rule misses this build. The constants do not. Renaming `aethsync` or `Moonshine.Core` costs the developer nothing; changing the cipher constants means touching the decryptor and every seed in all 30 accessor thunks.

The string layer is shared between the two builds and the hollowing code is not: six prologues differ at the same addresses, and stage 1's orchestrator prologue does not appear anywhere in variant 2. That half of the loader was rebuilt, not moved, and that is why the [IDA scripts](https://github.com/taogoldi/analysis_data/tree/main/animateclipper_aug_2026/ida) refuse to run on the wrong sample.

One more result from widening the set: `aethsync` is **not** invariant. The 2026-04-29 build does not contain it, in either ASCII or UTF-16. `Moonshine.Core` appears in all nine. The composite rule requires `1 of` the two rather than both, which is the only reason it caught the earliest build.

### YARA

```text
import "pe"
import "math"

rule AnimateClipper_Composite
{
    meta:
        author      = "taogoldi"
        date        = "2026-08-01"
        version     = 1
        description = "AnimateClipper stage-1: keystream constants + NativeAOT + aethsync identity"
        hash        = "21bf44a654a0059f7bb974ffe6252db63e998d5f95937454d45da4d700267471"
        tlp         = "TLP:WHITE"

    strings:
        $seed_xor  = { 81 F3 D5 C1 B3 A7 }       // xor ebx, 0A7B3C1D5h
        $golden    = { 81 F3 B9 79 37 9E }       // xor ebx, 09E3779B9h
        $rol13     = { C1 C3 0D }                // rol ebx, 13
        $mt_imul   = { 69 C1 65 89 07 6C }       // imul r8d, ecx, 6C078965h
        $aeth      = "aethsync" ascii wide
        $moon      = "Moonshine.Core" ascii

    condition:
        uint16(0) == 0x5A4D and
        pe.machine == pe.MACHINE_AMD64 and
        all of ($seed_xor, $golden, $rol13, $mt_imul) and
        1 of ($aeth, $moon)
}
```

Matching the full instruction encodings, not the bare four-byte constants, is deliberate. `{ B9 79 37 9E }` on its own also fires on any binary that happens to store the golden-ratio constant as data; `{ 81 F3 B9 79 37 9E }` requires it to be the immediate of an `xor ebx` in the key schedule.

The overlay builds need a different anchor, since they have no `.gfx` section for the rule above to look at:

```text
rule AnimateClipper_PayloadContainer
{
    strings:
        $magic = { 42 EE FF C0 }

    condition:
        uint16(0) == 0x5A4D and
        for any i in (1 .. #magic) : (
            uint32(@magic[i] + 4) == filesize - @magic[i] - 8 and
            uint32(@magic[i] + 4) > 65536 and
            math.entropy(@magic[i] + 8, uint32(@magic[i] + 4)) > 7.9
        )
}
```

And the Go dropper, which shares no code at all with the loader:

```text
rule AnimateClipper_GoDropper_SIRDCU
{
    strings:
        $mod_path  = "path\tSIRDCU"
        $mod_devel = "mod\tSIRDCU\t(devel)"
        $buildinf  = "\xff Go buildinf:"

    condition:
        uint16(0) == 0x5A4D and
        $buildinf and
        any of ($mod_path, $mod_devel)
}
```

`SIRDCU` is not a published Go module. It exists only in the actor's source tree, the compiler writes it into the buildinfo blob verbatim, and unlike the symbol names it survives a rebuild.

### Sigma (behavioural)

```text
title: ServiceModelReg.exe launched from a Startup-resident parent
status: experimental
author: taogoldi
logsource:
    category: process_creation
    product: windows
detection:
    hollow_host:
        Image|endswith: '\Microsoft.NET\Framework64\v4.0.30319\ServiceModelReg.exe'
    unusual_parent:
        ParentImage|contains:
            - '\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\'
    condition: hollow_host and unusual_parent
falsepositives:
    - Legitimate .NET Framework servicing operations, which do not run from Startup
level: high
```

Two caveats, because this rule is weaker than it looks. Process-creation telemetry does not detect hollowing; nothing here observes the unmap, the write or the context change. What it detects is an anomalous launch of a process this campaign happens to hollow, which is why the title says that instead of naming the technique. And `ParentImage` assumes the Startup-resident copy is the *direct* parent of `ServiceModelReg.exe`. If the UAC bypass path relaunches through an intermediate, the parent is that intermediate and the rule stays quiet.

The Startup parent is also only true on *re-execution after persistence*. On first run the parent is whatever dropped the loader, `L263919LLL.exe` in the observed chain. A defender relying on this rule alone sees the infection on reboot and never sees patient zero. The hollow target is build-specific too: `explorer.exe` sits in the decrypted strings, so a build that hollows explorer evades the `Image|endswith` clause completely.

High confidence, low coverage. For coverage, drop the parent condition and alert on `ServiceModelReg.exe` process creation on any workstation, accepting the volume, or pair it with an image-load or memory-write rule that does not care which host the build chose. The version above is the one to page on. The broader one is the one to hunt with.

### Suricata (network)

A single C2 domain is the least durable indicator in this post and will be dead the moment the operator rotates infrastructure. It is here because it was correct at analysis time.

```text
alert dns $HOME_NET any -> any any (msg:"AnimateClipper C2 DNS lookup bsc.blockrazor.xyz";
    dns.query; content:"bsc.blockrazor.xyz"; nocase; bsize:18;
    classtype:trojan-activity; sid:4200001; rev:1;)
```

Suricata 6 and later normalise `dns.query` to the name without a trailing dot, so `bsize:18` pins the match to exactly that name. The obvious version of this rule uses `endswith` instead, and it should not: `endswith` on a suffix also matches `evilbsc.blockrazor[.]xyz`, which an attacker registering a lookalike gets for free. For subdomain coverage use `dotprefix; content:".blockrazor.xyz"; endswith;`, which anchors on the label boundary.

## Conclusion

AnimateClipper's stage-1 loader is not technically ambitious. A keystream cipher assembled from two public constants, a UAC bypass documented for years, a self-copy into Startup, standard process hollowing. A C++ author could encrypt and dynamically resolve exactly the same APIs.

The wrapper is what makes it worth writing up. Compiling with NativeAOT removed the CLR metadata and IL that conventional managed-code analysis depends on, and it did so using a supported Microsoft build mode and not a packer. The interesting property is not that NativeAOT hides anything a packer could not. It is that it makes tools expecting CLR metadata misclassify the file outright, buries the malware in megabytes of runtime bulk, and still leaves every ordinary native obfuscation technique available on top. It defeats dnSpy and ILSpy completely, and it defeated our own .NET detection, which correctly reported "not .NET" because there is genuinely no CLR header to find. Meanwhile the native tooling that does work on it sees a 3.9 MB binary that is mostly runtime.

The problem for defenders is narrow and specific. A .NET detection strategy gated on the CLR header will miss NativeAOT malware completely, and NativeAOT is not a corner case: it is a first-class Microsoft build target that any C# developer turns on with one project property. Read "not .NET" from a header check as "not a .NET assembly", never as "not written in C#".

The three cipher constants are the most durable signal available, though durability and specificity are different properties. They survive the renaming of every string in the binary and cost the author real work to change, but two of the three appear in ordinary software, and measured against 2,000 unrelated PE files the triplet still produced a false positive. Hunt on them, gate them on NativeAOT markers, do not block on them alone.

Read the whole thing as a competently packaged commodity clipper loader that got a genuinely effective anti-analysis property almost for free. None of its individual techniques are new, none of them point to a sophisticated actor, and the developer left their own project name in the binary.

## References

**Windows internals**

- `CONTEXT` structure, x64 layout and `CONTEXT_*` flag values: Microsoft, *WinNT.h* / Windows SDK headers, and [`ns-winnt-context`](https://learn.microsoft.com/windows/win32/api/winnt/ns-winnt-context)
- [`WOW64_CONTEXT` structure and the 32-bit register offsets](https://learn.microsoft.com/windows/win32/api/winnt/ns-winnt-wow64_context)
- [`Wow64GetThreadContext` / `Wow64SetThreadContext`](https://learn.microsoft.com/windows/win32/api/wow64apiset/)
- [`CreateProcessW` and `CREATE_SUSPENDED`](https://learn.microsoft.com/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw)
- `NtUnmapViewOfSection`, `NtAllocateVirtualMemory`, `NtProtectVirtualMemory`, `NtWriteVirtualMemory`: Microsoft Windows Driver Kit reference and the documented `ZwXxx` equivalents
- [PE format](https://learn.microsoft.com/windows/win32/debug/pe-format): `IMAGE_OPTIONAL_HEADER.ImageBase`, `SizeOfHeaders`, section alignment, `IMAGE_REL_BASED_DIR64` / `IMAGE_REL_BASED_HIGHLOW`

**.NET and NativeAOT**

- [Native AOT deployment overview](https://learn.microsoft.com/dotnet/core/deploying/native-aot/)
- [`dotnet/runtime`](https://github.com/dotnet/runtime), NativeAOT runtime sources under `src/coreclr/nativeaot`, including `System.Private.TypeLoader` and `System.Private.Reflection.Execution`
- Object and array layout, `MethodTable`/`EEType` and array length placement: `src/coreclr/nativeaot/Runtime/inc/MethodTable.h` and the `Array` layout in `System.Private.CoreLib`
- P/Invoke transition frames and GC thread-state transitions: `src/coreclr/nativeaot/Runtime/thread.h` and `PInvokeTransitionFrame`
- Range-check elimination in RyuJIT / NativeAOT codegen: `dotnet/runtime` JIT documentation

**Techniques and detection**

- [UACMe](https://github.com/hfiref0x/UACME) technique 41, `ucmCMLuaUtilShellExecMethod`, CMSTPLUA `ICMLuaUtil` elevation
- [MITRE ATT&CK](https://attack.mitre.org): T1055.012, T1548.002, T1547.001, T1027.013, T1657, and T1134 / T1082 for the mappings discussed above
- YARA [`pe`](https://yara.readthedocs.io/en/stable/modules/pe.html) and [`math`](https://yara.readthedocs.io/en/stable/modules/math.html) module reference
- [Sigma specification](https://github.com/SigmaHQ/sigma-specification)
- [Suricata DNS keywords](https://docs.suricata.io/en/latest/rules/dns-keywords.html): `dns.query`, `dotprefix`, `bsize`
- [GoReSym](https://github.com/mandiant/GoReSym)

**Constants**

- CRC-32C, Castagnoli polynomial, reversed form `0x82F63B78`: RFC 3720 appendix B
- Mersenne Twister `init_genrand` multiplier 1812433253 (`0x6C078965`): Matsumoto and Nishimura, MT19937 reference implementation
- Golden-ratio constant `0x9E3779B9` as used in TEA and XXTEA: Wheeler and Needham, *TEA, a Tiny Encryption Algorithm*
- SipHash, for the structural comparison only: Aumasson and Bernstein, *SipHash: a fast short-input PRF*
