---
layout: single
title: "Amadey cred64.dll Downloads"
permalink: /downloads/amadey-cred64/
---

Download bundle index for the Amadey 5.78 `cred64.dll` plugin write-up.

Primary public artefact repository:
- [taogoldi/analysis_data/amadey_cred64_may_2026](https://github.com/taogoldi/analysis_data/tree/main/amadey_cred64_may_2026)

Direct folders:
- [scripts/](https://github.com/taogoldi/analysis_data/tree/main/amadey_cred64_may_2026/scripts) `decoder.py` (Vigenère + Base64 reproduction), `ida_rename_amadey.py` (idempotent IDApython annotation pass)
- [detection/](https://github.com/taogoldi/analysis_data/tree/main/amadey_cred64_may_2026/detection) seven YARA rules (also mirrored at [YARA/stealers/amadey/](https://github.com/taogoldi/YARA/tree/main/stealers/amadey))
- [reports/json/](https://github.com/taogoldi/analysis_data/tree/main/amadey_cred64_may_2026/reports/json) decoded strings table and structured static + cross-reference + C2-probe report
- [images/](https://github.com/taogoldi/analysis_data/tree/main/amadey_cred64_may_2026/images) Mermaid sources, rendered diagrams (kill chain, decode pipeline), IDA screenshots
- [docs/](https://github.com/taogoldi/analysis_data/tree/main/amadey_cred64_may_2026/docs) blog source markdown
- [c2_probe/](https://github.com/taogoldi/analysis_data/tree/main/amadey_cred64_may_2026/c2_probe) panel artefacts captured during the live C2 probe

Key external references:
- [Tria.ge sandbox report `260426-nq42gsaw9r`](https://tria.ge/260426-nq42gsaw9r)
- [MalwareBazaar entry](https://bazaar.abuse.ch/sample/3bdcb32460e5a613c35b14205e4a98ad50a03a1d7d17f4c30f2935c6f6d5db69/)
- [VirusTotal community page](https://www.virustotal.com/gui/file/3bdcb32460e5a613c35b14205e4a98ad50a03a1d7d17f4c30f2935c6f6d5db69/community)
- [0x0d4y: Amadey targeted analysis](https://0x0d4y.blog/amadey-targeted-analysis/)
- [Morado: Amadey Loader Analysis](https://www.morado.io/blog-posts/amadey-loader-analysis)
- [VMRay: Amadey new encoding with old tricks](https://www.vmray.com/amadey-new-encoding-with-old-tricks/)

The bot binary itself (`cred64.dll`, `cred.dll`) is not redistributed in this bundle. Analysts who want the raw samples can pull them from the upstream sources above.
