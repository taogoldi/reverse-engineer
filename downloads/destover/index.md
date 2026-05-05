---
layout: single
title: "Destover Downloads"
permalink: /downloads/destover/
---

Download bundle index for the Destover (Sony-Signed Backdoor) write-up.

Primary public artefact repository:
- [taogoldi/analysis_data/destover_apr_2026](https://github.com/taogoldi/analysis_data/tree/main/destover_apr_2026)

Direct folders:
- [scripts/](https://github.com/taogoldi/analysis_data/tree/main/destover_apr_2026/scripts) `destover_config_extractor.py` (pulls C2 IPs, decoded API list, version-info masquerade, and Authenticode signer in one static pass)
- [detection/](https://github.com/taogoldi/analysis_data/tree/main/destover_apr_2026/detection) two paired YARA rules: a behavior-and-fingerprint match on the binary and a stolen-certificate match on any PE still carrying the revoked SPE Authenticode chain. Also mirrored at [YARA/backdoors/destover/](https://github.com/taogoldi/YARA/tree/main/backdoors/destover).
- [reports/json/](https://github.com/taogoldi/analysis_data/tree/main/destover_apr_2026/reports/json) structured static + cross-reference report
- [images/](https://github.com/taogoldi/analysis_data/tree/main/destover_apr_2026/images) Mermaid sources and rendered diagrams (kill chain, dot-space API obfuscation, C2 state machine)
- [docs/](https://github.com/taogoldi/analysis_data/tree/main/destover_apr_2026/docs) blog source markdown

Key external references:
- [Securelist: Destover malware now digitally signed by Sony certificates](https://securelist.com/destover-malware-now-digitally-signed-by-sony-certificates/68073/)
- [Securelist: Sony/Destover, mystery North Korean actor's destructive and past network activity](https://securelist.com/destover/67985/)
- [SecurityAffairs: Damballa revealed the secrets behind the Destover malware](https://securityaffairs.com/42194/malware/destover-malware-analysis.html)
- [ThreatPost: Details Emerge on Sony Wiper Malware Destover](https://threatpost.com/details-emerge-on-sony-wiper-malware-destover/109727/)
- [APTnotes: From Seoul to Sony](https://github.com/kbandla/APTnotes/issues/260)

The Destover binary itself (SHA-256 `4c2efe2f1253b94f16a1cab032f36c7883e4f6c8d9fc17d0ee553b5afb16330c`) is not redistributed in this bundle. Analysts who want it can pull it from MalwareBazaar or VirusTotal.
