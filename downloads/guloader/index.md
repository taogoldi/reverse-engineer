---
layout: single
title: "GuLoader (NSIS) Downloads"
permalink: /downloads/guloader/
---

Download bundle index for the GuLoader NSIS-stage shellcode loader write-up.

Primary public artefact repository:
- [taogoldi/analysis_data/guloader_apr_2026](https://github.com/taogoldi/analysis_data/tree/main/guloader_apr_2026)

Direct folders:
- [scripts/](https://github.com/taogoldi/analysis_data/tree/main/guloader_apr_2026/scripts) `nsis_disasm.py` (NSIS-3 Unicode bytecode disassembler), `nsis_emulator.py` (NSIS opcode emulator capturing `System::Call`), `decode_piasaba.py` (4-byte XOR + 0xAC pad strip), `build_rainbow.py` (custom-hash rainbow table), `emulate_shellcode.py` (Unicorn shellcode emulator), three IDAPython annotation scripts.
- [detection/](https://github.com/taogoldi/analysis_data/tree/main/guloader_apr_2026/detection) four YARA rules (outer NSIS dropper, dropped-script artifacts, decoy padding, generic family). Also mirrored at [YARA/loaders/guloader/](https://github.com/taogoldi/YARA/tree/main/loaders/guloader).
- [reports/json/](https://github.com/taogoldi/analysis_data/tree/main/guloader_apr_2026/reports/json) structured static + cross-reference analysis report, full NSIS opcode dump
- [images/](https://github.com/taogoldi/analysis_data/tree/main/guloader_apr_2026/images) Mermaid sources and rendered diagrams (kill chain, dropped files, NSIS obfuscation flow)
- [docs/](https://github.com/taogoldi/analysis_data/tree/main/guloader_apr_2026/docs) blog source markdown

Key external references:
- [MalwareBazaar entry (uploader `threatcat_ch`)](https://bazaar.abuse.ch/sample/39c0135a0e8d46053fbcaa4efe6cbc83d33cf8e7be43efbca1622b2f77c7b9c6/)
- [VirusTotal community](https://www.virustotal.com/gui/file/39c0135a0e8d46053fbcaa4efe6cbc83d33cf8e7be43efbca1622b2f77c7b9c6/community)
- [Hatching Triage `260427-a4q5wsdw6k`](https://tria.ge/260427-a4q5wsdw6k)
- [Joe Sandbox 1904872](https://www.joesandbox.com/analysis/1904872/0/html)
- [NeikiAnalytics / threat.rip](https://www.threat.rip/file/39c0135a0e8d46053fbcaa4efe6cbc83d33cf8e7be43efbca1622b2f77c7b9c6)
- [ANY.RUN sandbox task](https://app.any.run/tasks/8a8f7467-7381-44ca-936a-4e23663358a9)
- [VMRay analysis](https://www.vmray.com/analyses/_vt/39c0135a0e8d/report/overview.html)

The NSIS dropper binary, the encrypted `piasaba` and `Toolers` blobs, and the staged Remcos PE are not redistributed in this bundle. Pull from MalwareBazaar by SHA-256 (`39c0135a0e8d46053fbcaa4efe6cbc83d33cf8e7be43efbca1622b2f77c7b9c6`).
