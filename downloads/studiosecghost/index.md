---
layout: page
title: "StudioSecGhost -- Downloads"
permalink: /downloads/studiosecghost/
---

All artifacts for the [StudioSecGhost analysis post](/reverse-engineer/blog/studiosecghost-hvnc-browser-piggyback/).

## Detection

| File | Description |
|---|---|
| [studiosecghost.yar](https://github.com/taogoldi/YARA/tree/main/hvnc/studiosecghost/studiosecghost.yar) | YARA rules (2 rules: agent + bounce HTML) |
| [studiosecghost.rules](https://github.com/taogoldi/analysis_data/tree/main/studiosecghost_may_2026/detection/studiosecghost.rules) | Suricata rules (4 sids: 9300101--9300104) |

## Scripts

| File | Description |
|---|---|
| [recon.py](https://github.com/taogoldi/analysis_data/tree/main/studiosecghost_may_2026/scripts/recon.py) | pefile + capstone packing/obfuscation indicator pass |
| [extract_config.py](https://github.com/taogoldi/analysis_data/tree/main/studiosecghost_may_2026/scripts/extract_config.py) | Sample-agnostic UTF-16LE config lifter |
| [deep_disasm.py](https://github.com/taogoldi/analysis_data/tree/main/studiosecghost_may_2026/scripts/deep_disasm.py) | Targeted function reversing with string xref + IAT annotation |
| [ida_rename_studiosecghost.py](https://github.com/taogoldi/analysis_data/tree/main/studiosecghost_may_2026/scripts/ida_rename_studiosecghost.py) | IDA function-rename pass (26 anchors) |

## Reports

| File | Description |
|---|---|
| [extracted_config.json](https://github.com/taogoldi/analysis_data/tree/main/studiosecghost_may_2026/reports/extracted_config.json) | Full static config lifted from .rdata |
| [studiosecghost_analysis_report.json](https://github.com/taogoldi/analysis_data/tree/main/studiosecghost_may_2026/reports/studiosecghost_analysis_report.json) | pefile PE analysis report |
| [deep_disasm.txt](https://github.com/taogoldi/analysis_data/tree/main/studiosecghost_may_2026/reports/deep_disasm.txt) | Full disassembly snapshot |

## Sample

**Do not share the binary.** Reference by SHA-256 only:

```
5940c41ab003399680a04d726587eed242e4ad8969abe4b5617d712ff190a852
```

Pull from [MalwareBazaar](https://bazaar.abuse.ch/) or VirusTotal using the hash.

---

*taogoldi -- TLP:CLEAR -- 2026-05-19*
