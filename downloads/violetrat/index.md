---
layout: page
title: "VioletRAT v6 -- Downloads"
permalink: /downloads/violetrat/
---

All artifacts for the [VioletRAT v6 analysis post](/reverse-engineer/blog/violetrat-v6-winrar-vbnet-rat/).

## Detection

| File | Description |
|---|---|
| [violetrat.yar](https://github.com/taogoldi/YARA/tree/main/rats/violetrat/violetrat.yar) | YARA rules (4 rules: strings, WinRAR masquerade, command protocol, AMSI bypass) |

## Scripts

| File | Description |
|---|---|
| [decoder.py](https://github.com/taogoldi/analysis_data/tree/main/violetrat_june_2026/scripts/decoder.py) | Offline re-implementation of both crypto layers (Base64+XOR strings, AES-128-ECB packets) plus dispatcher command recovery |
| [c2_capture.py](https://github.com/taogoldi/analysis_data/tree/main/violetrat_june_2026/scripts/c2_capture.py) | Capture-only C2 client: registers a fake bot and stores pushed frames, never executes a command or loads an assembly |
| [dnspy_symbol_map.json](https://github.com/taogoldi/analysis_data/tree/main/violetrat_june_2026/scripts/dnspy_symbol_map.json) | Obfuscated-identifier to meaning map for dnSpy/ILSpy annotation |

## Reports

| File | Description |
|---|---|
| [decoded_strings.json](https://github.com/taogoldi/analysis_data/tree/main/violetrat_june_2026/reports/decoded_strings.json) | Full deobfuscated string + 110-command dump |
| [violetrat_analysis_report.json](https://github.com/taogoldi/analysis_data/tree/main/violetrat_june_2026/reports/violetrat_analysis_report.json) | pefile / static analysis report incl. live-probe timeline |
| [async.decompiled.cs](https://github.com/taogoldi/analysis_data/tree/main/violetrat_june_2026/reports/async.decompiled.cs) | ilspycmd decompilation of the sample |

## Sample

**Do not share the binary.** Reference by SHA-256 only:

```
2bf04b9a583e6f1efa661a43d357bc8ea143bcb53fa87f81081347ee2feb80eb
```

Pull from [MalwareBazaar](https://bazaar.abuse.ch/) or VirusTotal using the hash.

---

*taogoldi -- TLP:CLEAR -- 2026-06-25*
