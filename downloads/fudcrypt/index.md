---
layout: single
title: "FUD Crypt / VerShadow Downloads"
permalink: /downloads/fudcrypt/
---

Download bundle index for the FUD Crypt VerShadow VERSION.dll carrier write-up.

Primary public artefact repository:
- [taogoldi/analysis_data/fudcrypt_vershadow_apr_2026](https://github.com/taogoldi/analysis_data/tree/main/fudcrypt_vershadow_apr_2026)

Direct folders:
- [scripts/](https://github.com/taogoldi/analysis_data/tree/main/fudcrypt_vershadow_apr_2026/scripts) `decrypt_stage2.py` (RC4 + 32-byte rolling SUB+XOR pipeline)
- [detection/](https://github.com/taogoldi/analysis_data/tree/main/fudcrypt_vershadow_apr_2026/detection) YARA rules (also mirrored at [YARA/loaders/fudcrypt/](https://github.com/taogoldi/YARA/tree/main/loaders/fudcrypt))
- [reports/json/](https://github.com/taogoldi/analysis_data/tree/main/fudcrypt_vershadow_apr_2026/reports/json) structured static + dynamic + cross-reference report
- [images/](https://github.com/taogoldi/analysis_data/tree/main/fudcrypt_vershadow_apr_2026/images) Mermaid sources and rendered diagrams (kill chain, CLR sequence, DLL search order)
- [docs/](https://github.com/taogoldi/analysis_data/tree/main/fudcrypt_vershadow_apr_2026/docs) blog source markdown

Key external references:
- [Hybrid Analysis: loader full sandbox report](https://www.hybrid-analysis.com/sample/c73947cf188f442bed228f62a3ba5611009fdc2f1878aaed7065db95ede05521/69e6b42079aaeb902a08ac15)
- [Hybrid Analysis: stage-2 .NET payload](https://www.hybrid-analysis.com/sample/86e9024c21478f7fa59bf95aef8e7bfb869ed872e8a92e7ca19118df0f74f457)
- [Ctrl-Alt-Intel: Dissecting FudCrypt](https://ctrlaltintel.com/research/FudCrypt-analysis-1/)
- [Splunk: Windows Hijack Execution Flow Version Dll Side Load](https://research.splunk.com/endpoint/8351340b-ac0e-41ec-8b07-dd01bf32d6ea/)

The carrier executable, the encrypted catbox blob, and the decrypted .NET assembly are not redistributed in this bundle. Analysts who want them can pull from the upstream sources above.
