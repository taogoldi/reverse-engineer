---
layout: post
title: "Stage1 (22.exe) Loader Reversing: Stage Decryption, Evasion, and Attribution"
permalink: /blog/22exe-loader-analysis/
date: 2026-02-24 00:00:00 +0000
toc: true
categories: [malware-reversing, threat-intel]
tags: [loader, amsi-bypass, etw-patch, aes, stage2, yara, attribution, vidar]
image:
  path: /assets/images/social/22exe-vidar-future-clean.jpg
  alt: "Stage1 22.exe loader reverse-engineering analysis"
---

**Sample acquisition source:** `hXXps://cloudaxis[.]cc/gsmft/yueu/fkvqld/tvqqwh/ushu/22.exe`

I built this write-up as a reproducible analyst notebook-to-blog handoff for `22.exe` (treated as **Stage1** in this analysis): what it does, how we extracted the next stage safely, where the anti-analysis logic lives, and what we can and cannot claim yet.

## Summary

What is confirmed in this sample set:
- staged payload decryption from an embedded encrypted blob,
- in-memory AMSI and ETW patching before stage handoff,
- anti-sandbox/anti-analysis checks,
- reflective loading of a decrypted Stage2 PE,
- and working YARA coverage for stage1 and stage2 artifacts.

Attribution status:
- Stage2 is classified as Vidar by multiple commercial AV detections in sandbox telemetry, so this write-up refers to it as a **VIDAR variant** for now,
- confidence is **medium** until Stage2 config and command handling are fully decoded.

## Quick Primer

- `AMSI` is a Windows scanning interface used by security products to inspect scripts/content before execution.
- `ETW` is a Windows telemetry pipeline used to log behavior (process/runtime events).
- A `patch` here means overwriting a few bytes in memory so a security-related function returns immediately.
- `Reflective loading` means loading a PE from memory directly instead of writing a normal file to disk and launching it.

Plain-English translation: this loader appears to reduce security visibility first, then unpack and run the next stage in memory.

## Stage Flow

![22.exe stage workflow diagram](/assets/images/posts/22exe/22exe_stage_flowchart_clean.png)

## Sample Scope

| Artifact | SHA-256 |
|---|---|
| `22.exe` (Stage1 sample) | `0cb5a2e3c8aa7c80c8bbfb3a5f737c75807aa0e689dd4ad0a0466d113d8a6b9d` |
| `stage2_dec_unpadded.bin` (Decrypted Stage2) | `5fa52aa9046334c86da1e9746dfe9d7bb23ec69a8b2ab77d98efd2cb1af012f3` |

## Downloads

Public analysis bundle:
- [analysis_data / vidar_feb_2026](https://github.com/taogoldi/analysis_data/tree/main/vidar_feb_2026)
- [scripts](https://github.com/taogoldi/analysis_data/tree/main/vidar_feb_2026/scripts)
- [notebooks (output-cleared)](https://github.com/taogoldi/analysis_data/tree/main/vidar_feb_2026/notebooks)
- [IDA helpers](https://github.com/taogoldi/analysis_data/tree/main/vidar_feb_2026/ida)
- [reports and evidence artifacts](https://github.com/taogoldi/analysis_data/tree/main/vidar_feb_2026/reports)
- [workflow flowchart files](https://github.com/taogoldi/analysis_data/tree/main/vidar_feb_2026/docs)

YARA rules:
- [YARA repository](https://github.com/taogoldi/YARA)
- [VIDAR folder](https://github.com/taogoldi/YARA/tree/main/stealers/vidar)
- [Stage1 high-fidelity](https://github.com/taogoldi/YARA/blob/main/stealers/vidar/vidar_like_22_stage1_highfidelity.yar)
- [Stage2 high-fidelity](https://github.com/taogoldi/YARA/blob/main/stealers/vidar/vidar_like_22_stage2_highfidelity.yar)
- [Stage1 variant heuristic](https://github.com/taogoldi/YARA/blob/main/stealers/vidar/vidar_like_22_stage1_variant_heuristic.yar)
- [Stage2 variant heuristic](https://github.com/taogoldi/YARA/blob/main/stealers/vidar/vidar_like_22_stage2_variant_heuristic.yar)

## Stage1 Technical Findings

### AMSI and ETW Patch Path

The loader uses dedicated routines to patch telemetry/scanning APIs in memory:
- AMSI patch bytes: `B8 57 00 07 80 C3` (`mov eax, 0x80070057 ; ret`)
- ETW patch bytes (primary): `31 C0 C3` (`xor eax, eax ; ret`)
- ETW patch bytes (fallback): `C2 14 00` (`ret 0x14`)

Relevant functions:
- `sub_140002EA0` for AMSI target selection (`AmsiScanBuffer`, fallback `AmsiOpenSession`)
- `sub_140002F00` for ETW target selection (`EtwEventWrite`, `EtwEventWriteTransfer`, `NtTraceEvent`)
- patch helper logic around memory-protection change + write + instruction cache handling

#### AMSI path

First, the dispatcher logic shows the AMSI targets and fallback behavior in a compact C-style view.

![AMSI dispatcher C view at 0x140002EA0](/assets/images/posts/22exe/c_22exe_amsi_dispatch_0x140002EA0.png)

Under that dispatcher, the patch primitive performs memory-protection change and byte overwrite on the resolved export.

![AMSI patch primitive around VirtualProtect at 0x1400041A0](/assets/images/posts/22exe/asm_22exe_amsi_patch_primitive_0x1400041A0.png)

#### ETW path

The ETW dispatcher follows the same pattern, but fans out across multiple trace APIs (`EtwEventWrite`, `EtwEventWriteTransfer`, `NtTraceEvent`) and keeps a fallback branch.

![ETW dispatcher at 0x140002F00](/assets/images/posts/22exe/asm_22exe_etw_dispatch_0x140002F00.png)

Decompiler view of the same function confirms the call ordering and fallback composition clearly.

![ETW dispatcher C view at 0x140002F00](/assets/images/posts/22exe/c_22exe_etw_dispatch_0x140002F00.png)

Finally, the data view shows the exact patch byte payloads used by the ETW routine.

![ETW patch bytes at 0x1400A3570 and 0x1400A3580](/assets/images/posts/22exe/hex_22exe_etw_patch_bytes_0x1400A3570_0x1400A3580.png)

Why this matters operationally:
- **Why AMSI bypass is used:** AMSI is often where decoded script/content gets inspected before execution. Short-circuiting these calls reduces that inspection window.
- **Why ETW patching is used:** ETW is heavily used by EDR/telemetry pipelines. Returning early from ETW writers reduces behavioral event visibility during the critical unpack/execute period.
- **Why both together:** one weakens in-line content scanning and the other weakens runtime logging. Used together, they increase the chance that the next stage runs with less detection pressure.

### Anti-Analysis / Anti-Sandbox Logic

Observed markers include:
- `\\.\pipe\cuckoo`
- `cuckoomon.dll`
- `SbieDll.dll`
- `SOFTWARE\Wine`
- Sandboxie uninstall key path
- user/host/process markers such as `joe sandbox`, `SANDBOX`, `maltest`, `ProcessHacker.exe`, `injector.exe`

This is not one single "if sandbox then quit" check. It looks more like a collection of environment checks that feed gating decisions.

## Stage2 Decryption

### Offsets used in this sample (sample-specific)

- encrypted blob VA: `0x140005140`
- encrypted blob size VA: `0x1400A3560` (observed `0x9E410`)
- AES IV VA: `0x1400A3590`
- AES key VA: `0x1400A35A0`

![Encrypted stage2 blob region at 0x140005140](/assets/images/posts/22exe/hex_22exe_stage2_blob_key_iv_offsets.png)

### Decrypt wrapper path

The wrapper at `sub_140002FF0` allocates memory, copies encrypted bytes, expands key material, decrypts, and trims PKCS#7 padding before handoff.

![Stage2 decrypt wrapper at 0x140002FF0](/assets/images/posts/22exe/asm_22exe_stage2_decrypt_wrapper_0x140002FF0.png)

### Why AES is a defensible conclusion

I am not calling this AES because of naming alone. The disassembly behavior matches AES-256-CBC traits:
- key schedule routine (`sub_140002D00`) operates on a 32-byte key, uses lookup tables in AES-like expansion style, and runs expansion rounds to 60 words (AES-256 schedule shape).
- IV is handled as a separate 16-byte input and stored with context.
- decrypt core (`sub_140002820`) processes 16-byte blocks and contains GF(2^8)-style arithmetic patterns (including `0x1B` reduction behavior typical in AES round math) plus block chaining behavior.
- wrapper applies PKCS#7 unpadding semantics from the final plaintext byte.

![Key expansion routine at 0x140002D00](/assets/images/posts/22exe/asm_22exe_aes_key_expansion_0x140002D00.png)

![AES-CBC decrypt core callsite at 0x140002820 path](/assets/images/posts/22exe/asm_22exe_aes_cbc_core_0x140002820.png)

Plain-English translation: the code is doing modern block-cipher style decrypt with a 32-byte key and IV, not a simple XOR/rolling key obfuscator.

## Stage2 Findings (Current State)

Stage2 was recovered consistently through both script and notebook workflows.

Notable strings/import context observed:
- `ChromeBuildTools`
- `\\Network\\Cookies`
- long `%DOWNLOADS%` token-like string
- imports such as `CreateDesktopA`, `OpenDesktopA`, `EnumDisplayDevicesA`, `GetCurrentHwProfileA`

![Stage2 strings with collection-oriented indicators](/assets/images/posts/22exe/strings_stage2_vidar_like_indicators.png)

These are consistent with a credential/data collection stage, but by themselves they are not enough to claim final family certainty without decoding full config + command handling.

External telemetry pivot:
- a sandbox-derived Suricata alert links this cluster to an SSLBL certificate fingerprint associated with Vidar C2 activity: `c8:28:9f:1d:bf:34:11:94:43:a3:07:7f:d8:79:c3:43:35:06:f3:58` ([SSLBL entry](https://sslbl.abuse.ch/ssl-certificates/sha1/c8289f1dbf34119443a3077fd879c3433506f358/)).
- that fingerprint is useful for network-side hunting (TLS cert pivoting), but it is **not** present as a direct static literal inside this decrypted Stage2 blob.

## Notebook and Script Guide

### Notebook

- `notebooks/spectralviper_deobfuscation_walkthrough.ipynb`
- What it does:
  - lays out the stage flow and constants,
  - extracts and decrypts Stage2,
  - supports decrypt-from-hex for extracted stage/key material,
  - surfaces AMSI/ETW patch evidence,
  - pulls anti-sandbox indicators and Stage2 triage output.

Why this matters: it gives you one repeatable path from raw sample to evidence artifacts without hand-clicking every step in IDA.

### Python scripts

- `scripts/extract_stage2_from_22.py`
  - deterministic extractor/decryptor using fixed sample offsets.
  - outputs decrypt artifacts and `stage2_extract_report.json`.
- `scripts/analyze_stage1_evasion.py`
  - extracts AMSI/ETW patch bytes and anti-sandbox evidence from IDA sqlite.
  - outputs `stage1_evasion_report.json`.
- `scripts/hunt_stage2_iocs.py`
  - Stage2 import/string triage for fast IOC surfacing.
  - outputs `stage2_ioc_report.json`.
- `scripts/assess_spectralviper_similarity.py`
  - compares behavioral/string overlap against expected marker sets.
  - outputs `spectralviper_similarity_report.json`.
- `scripts/sv_analysis_lib.py`
  - shared parsing/decrypt/util functions used across the other scripts and notebook.

## IDA Python Helpers

### `ida_python/sv_stage_decrypt_annotator.py`

What it attempts to do on Stage1 (`22.exe`):
- rename core stage/decrypt/evasion functions,
- rename key globals (encrypted blob, key, IV, patch byte buffers),
- apply comments/types/frame var names,
- apply Hex-Rays local variable names where API support exists.

Net effect: faster orientation for the Stage1 to Stage2 handoff path.

### `ida_python/sv_stage2_hunt_annotator.py`

What it attempts to do on decrypted Stage2:
- heuristic tagging of possible PEB-walk and API-hash style routines,
- suspicious string tagging,
- likely config blob/data candidate tagging by xref density,
- best-effort renaming/comments/struct+enum setup.

Important note: Stage2 tagging is heuristic, not ground truth. It should be treated as a triage accelerator, then validated manually function-by-function.

## Detection Engineering

Prepared ruleset:
- `VIDAR_LIKE_22_STAGE1_HighFidelity`
- `VIDAR_LIKE_22_STAGE2_HighFidelity`
- `VIDAR_LIKE_22_STAGE1_Variant_Heuristic`
- `VIDAR_LIKE_22_STAGE2_Variant_Heuristic`

Public rule location:
- `https://github.com/taogoldi/YARA/tree/main/stealers/vidar`

Rule set note:
- this post includes all four rules (two high-fidelity and two broader heuristic hunting rules).

Validation snapshot:
- stage1 rule matches `22.exe`
- stage2 rule matches decrypted Stage2 outputs
- encrypted blob does not match (expected)

## Attribution Status

### Threat assessment
Current working assessment is **VIDAR variant** (medium confidence), based on multi-vendor Stage2 classification plus staged decryption, in-memory security patching, and Stage2 collection-oriented indicators.

## YARA Rules

### Rule 1: Stage1 high-fidelity

<div markdown="1" style="border:1px solid #274060;border-radius:8px;padding:12px;margin:1rem 0;background:#0b1220;">

```yara
rule VIDAR_LIKE_22_STAGE1_HighFidelity
{
  meta:
    author = "taogoldi"
    date = "2026-02-24"
    description = "High-fidelity rule for 22.exe-like stage1 loader/decryptor with AMSI+ETW patching"
    sample_sha256 = "0cb5a2e3c8aa7c80c8bbfb3a5f737c75807aa0e689dd4ad0a0466d113d8a6b9d"
    confidence = "high"

  strings:
    // API patch targets
    $api1 = "AmsiScanBuffer" ascii wide
    $api2 = "AmsiOpenSession" ascii wide
    $api3 = "EtwEventWrite" ascii wide
    $api4 = "EtwEventWriteTransfer" ascii wide
    $api5 = "NtTraceEvent" ascii wide

    // Anti-analysis cluster in this family/build
    $anti1 = "\\\\.\\pipe\\cuckoo" ascii wide
    $anti2 = "cuckoomon.dll" ascii wide
    $anti3 = "SbieDll.dll" ascii wide
    $anti4 = "SOFTWARE\\Wine" ascii wide
    $anti5 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Sandboxie" ascii wide
    $anti6 = "ProcessHacker.exe" ascii wide
    $anti7 = "injector.exe" ascii wide

    // Patch bytes used by stage1 routines
    $patch_amsi = { B8 57 00 07 80 C3 }
    $patch_etw1 = { 31 C0 C3 }
    $patch_etw2 = { C2 14 00 }

    // Orchestrator / decrypt wrapper / reflective handoff chains
    $sig_orchestrator = {
      53 48 83 EC 40 E8 ?? ?? ?? ??
      C7 44 24 34 00 00 00 00
      48 C7 44 24 38 00 00 00 00
      E8 ?? ?? ?? ?? 85 C0 89 C3 75 ?? 31 DB
    }

    $sig_stage_decrypt_wrapper = {
      41 B8 00 30 00 00
      41 B9 04 00 00 00
      FF 15 ?? ?? ?? ??
      31 D2 48 85 C0 48 89 06 74 ??
      41 89 D8 48 89 FA 48 89 C1 E8 ?? ?? ?? ??
      48 8D 7C 24 20
      4C 8D 05 ?? ?? ?? ??
      48 89 F9
      48 8D 15 ?? ?? ?? ??
      E8 ?? ?? ?? ??
      48 8B 16 41 89 D8 48 89 F9 E8 ?? ?? ?? ??
    }

    $sig_reflective_handoff = {
      E8 ?? ?? ?? ?? 85 C0 74 ??
      48 8B 4C 24 38
      8B 54 24 34
      48 89 4C 24 28
      E8 ?? ?? ?? ??
      31 D2
      48 8B 4C 24 28
      41 B8 00 80 00 00
    }

  condition:
    uint16(0) == 0x5A4D and
    pe.number_of_sections >= 6 and
    all of ($api*) and
    4 of ($anti*) and
    $patch_amsi and $patch_etw1 and $patch_etw2 and
    $sig_orchestrator and $sig_stage_decrypt_wrapper and $sig_reflective_handoff
}
```

</div>

### Rule 2: Stage2 high-fidelity

<div markdown="1" style="border:1px solid #274060;border-radius:8px;padding:12px;margin:1rem 0;background:#0b1220;">

```yara
rule VIDAR_LIKE_22_STAGE2_HighFidelity
{
  meta:
    author = "taogoldi"
    date = "2026-02-24"
    description = "High-fidelity rule for decrypted stage2 from 22.exe"
    stage2_sha256 = "5fa52aa9046334c86da1e9746dfe9d7bb23ec69a8b2ab77d98efd2cb1af012f3"
    confidence = "high"

  strings:
    $s1 = "ChromeBuildTools" ascii wide
    $s2 = "\\Network\\Cookies" ascii wide
    $s3 = "11111111111111111111111111111111111111111111111111111%DOWNLOADS%" ascii wide

  condition:
    uint16(0) == 0x5A4D and
    pe.number_of_sections == 5 and
    pe.imports("USER32.dll", "CreateDesktopA") and
    pe.imports("USER32.dll", "OpenDesktopA") and
    pe.imports("ADVAPI32.dll", "GetCurrentHwProfileA") and
    pe.imports("USER32.dll", "EnumDisplayDevicesA") and
    all of ($s*)
}
```

</div>


### Rule 3: Stage1 variant heuristic

<div markdown="1" style="border:1px solid #274060;border-radius:8px;padding:12px;margin:1rem 0;background:#0b1220;">

```yara
import "pe"

rule VIDAR_LIKE_22_STAGE1_Variant_Heuristic
{
  meta:
    author = "taogoldi"
    date = "2026-02-24"
    description = "Variant-oriented stage1 heuristic for this cluster (less strict than high-fidelity)"
    confidence = "medium"

  strings:
    $api1 = "AmsiScanBuffer" ascii wide
    $api2 = "AmsiOpenSession" ascii wide
    $api3 = "EtwEventWrite" ascii wide
    $api4 = "EtwEventWriteTransfer" ascii wide
    $api5 = "NtTraceEvent" ascii wide

    $anti1 = "\\\\.\\pipe\\cuckoo" ascii wide
    $anti2 = "cuckoomon.dll" ascii wide
    $anti3 = "SbieDll.dll" ascii wide
    $anti4 = "SOFTWARE\\Wine" ascii wide
    $anti5 = "ProcessHacker.exe" ascii wide
    $anti6 = "injector.exe" ascii wide

    $sig_kexp = {
      41 0F B6 4B 1F
      41 B8 08 00 00 00
      41 0F B6 6B 1E
      48 8D 35 ?? ?? ?? ??
      45 0F B6 53 1D
      48 8D 3D ?? ?? ?? ??
      41 0F B6 53 1C
    }

    $sig_stage_decrypt_wrapper = {
      41 B8 00 30 00 00
      41 B9 04 00 00 00
      FF 15 ?? ?? ?? ??
      31 D2 48 85 C0 48 89 06 74 ??
      48 8D 7C 24 20
      4C 8D 05 ?? ?? ?? ??
      48 8D 15 ?? ?? ?? ??
      E8 ?? ?? ?? ??
      48 8B 16 41 89 D8 48 89 F9 E8 ?? ?? ?? ??
      48 8B 16 8D 43 FF 0F B6 04 02
    }

    $patch_amsi = { B8 57 00 07 80 C3 }
    $patch_etw1 = { 31 C0 C3 }

  condition:
    uint16(0) == 0x5A4D and
    4 of ($api*) and
    2 of ($anti*) and
    ($sig_kexp or $sig_stage_decrypt_wrapper) and
    ($patch_amsi or $patch_etw1)
}
```

</div>

### Rule 4: Stage2 variant heuristic

<div markdown="1" style="border:1px solid #274060;border-radius:8px;padding:12px;margin:1rem 0;background:#0b1220;">

```yara
import "pe"

rule VIDAR_LIKE_22_STAGE2_Variant_Heuristic
{
  meta:
    author = "taogoldi"
    date = "2026-02-24"
    description = "Variant-oriented stage2 heuristic from this cluster"
    confidence = "medium"

  strings:
    $s1 = "ChromeBuildTools" ascii wide
    $s2 = "\\Network\\Cookies" ascii wide
    $s3 = "%DOWNLOADS%" ascii wide

  condition:
    uint16(0) == 0x5A4D and
    pe.imports("USER32.dll", "CreateDesktopA") and
    pe.imports("USER32.dll", "OpenDesktopA") and
    pe.imports("ADVAPI32.dll", "GetCurrentHwProfileA") and
    2 of ($s*)
}
```

</div>
