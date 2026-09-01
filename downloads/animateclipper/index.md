---
layout: page
title: "AnimateClipper -- Downloads"
permalink: /downloads/animateclipper/
---

All artifacts for the [AnimateClipper NativeAOT loader analysis post](/reverse-engineer/blog/animateclipper-nativeaot-loader/).

Everything below lives in [taogoldi/analysis_data/animateclipper_aug_2026](https://github.com/taogoldi/analysis_data/tree/main/animateclipper_aug_2026).

## Detection

| File | Description |
|---|---|
| [animateclipper.yar](https://github.com/taogoldi/YARA/tree/main/loaders/animateclipper/animateclipper.yar) | Four loader rules: keystream key-schedule constants, NativeAOT + `.gfx` section, composite (constants gated on NativeAOT markers), and the overlay stage-2 container |
| [animateclipper_dropper.yar](https://github.com/taogoldi/YARA/tree/main/loaders/animateclipper/animateclipper_dropper.yar) | Go dropper, keyed on the unpublished `SIRDCU` module name in the buildinfo blob. The rejected symbol-name rule and why it was thrown away are kept as a comment |

Hunt on the constants rule, block on the composite. Measured false-positive rates for each constant are in the post.

## Scripts

| File | Description |
|---|---|
| [decrypt_strings.py](https://github.com/taogoldi/analysis_data/tree/main/animateclipper_aug_2026/scripts/decrypt_strings.py) | Standalone reimplementation of the keystream cipher. Parses all 30 accessor thunks out of the PE and recovers every encrypted API name in under a second, with no emulation or debugging |
| [ida_stage1_animateclipper.py](https://github.com/taogoldi/analysis_data/tree/main/animateclipper_aug_2026/ida/ida_stage1_animateclipper.py) | IDAPython annotation pass for stage 1: 3 enums, 5 structs, 25 names with Hex-Rays prototypes, all 30 thunks |
| [ida_variant2_cdb9558b.py](https://github.com/taogoldi/analysis_data/tree/main/animateclipper_aug_2026/ida/ida_variant2_cdb9558b.py) | Variant 2, verified string layer only. Read [ida/README.md](https://github.com/taogoldi/analysis_data/tree/main/animateclipper_aug_2026/ida/README.md) first: the stage-1 script must not be run on this binary, and both guard on `.gfx` size to enforce it |
| [ida_dropper_goresym.py](https://github.com/taogoldi/analysis_data/tree/main/animateclipper_aug_2026/ida/ida_dropper_goresym.py) | Replays the 186 GoReSym symbols onto the Go dropper |

## Reports

| File | Description |
|---|---|
| [decoded_strings.json](https://github.com/taogoldi/analysis_data/tree/main/animateclipper_aug_2026/reports/json/decoded_strings.json) | All 30 recovered API names with their thunk addresses and per-string seeds |
| [animateclipper_analysis_report.json](https://github.com/taogoldi/analysis_data/tree/main/animateclipper_aug_2026/reports/json/animateclipper_analysis_report.json) | pefile static analysis report: headers, sections, per-section entropy, imports |
| [dropper_goresym.json](https://github.com/taogoldi/analysis_data/tree/main/animateclipper_aug_2026/reports/json/dropper_goresym.json) | GoReSym build metadata and full symbol table for the dropper |
| [reports/disasm/](https://github.com/taogoldi/analysis_data/tree/main/animateclipper_aug_2026/reports/disasm) | r2ghidra pseudocode and raw disassembly: both string decryptors, the P/Invoke transition frames, the GC large-page path behind the removed T1134 mapping, an example accessor thunk, variant 2's cipher core |

## Figures

| File | Description |
|---|---|
| [killchain.png / .mmd](https://github.com/taogoldi/analysis_data/tree/main/animateclipper_aug_2026/images) | Kill chain flowchart with Mermaid source |
| [hollowing.png / .mmd](https://github.com/taogoldi/analysis_data/tree/main/animateclipper_aug_2026/images) | Process-hollowing call flow with WinAPI arguments and return values |
| [images/rizin/](https://github.com/taogoldi/analysis_data/tree/main/animateclipper_aug_2026/images/rizin) | Control-flow graphs: both decryptors, the hollowing orchestrator, the GC large-page path, variant 2's decryptor |

## Samples

**Binaries are not redistributed.** Reference by SHA-256 and pull from [MalwareBazaar](https://bazaar.abuse.ch/) or VirusTotal:

```
21bf44a654a0059f7bb974ffe6252db63e998d5f95937454d45da4d700267471  stage-1 loader (this analysis)
cdb9558b47af57c3f433ddb40b44686a71a12d0ee523add5fb1ec28588209945  variant 2
99dc1ea286648ec882d71ab5071e3072c702e5170770843177807179c63f4593  sibling build
985db456011618574cc7ec6fed5e2be3bd43ceb50d6f24e6dcf2579942730da3  sibling build
38060481b1e545de7f4cce80fb9ec20be10d83b9796977c82c984c03a173b442  sibling build
a6b5ae508afafcda6d59864b8795a3b2532b56b67ee989e52552005240c0a34e  sibling build
43edee1eabae3c4ebd3bb2d21f6c24d0984b38f51dbeb74b425ccd53f2a71399  Go dropper, L263919LLL.exe
```

---

*taogoldi -- TLP:CLEAR -- 2026-09-01*
