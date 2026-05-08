---
layout: single
title: "PoolParty Downloads"
permalink: /downloads/poolparty/
---

Download bundle index for the PoolParty thread-pool process injection write-up.

Primary public artifact repository:
- [taogoldi/analysis_data/poolparty_may_2026](https://github.com/taogoldi/analysis_data/tree/main/poolparty_may_2026)

Direct folders:
- [scripts/](https://github.com/taogoldi/analysis_data/tree/main/poolparty_may_2026/scripts) `api_hash_reverser.py` (CRC32-IEEE-802.3 reverser for the Sample C `pe_to_shellcode` wrapper, with built-in dictionary), `verify_sample_text_identity.py` (byte-level proof Sample C is wrapped Sample B), `poolparty_rename_sample_b.py` (IDAPython annotation pass for Sample B).
- [detection/](https://github.com/taogoldi/analysis_data/tree/main/poolparty_may_2026/detection) cross-variant `poolparty.yar` (one rule, four detection paths) plus five draft capa nursery candidates under `detection/capa/`. The YARA rule is also mirrored at [YARA/injectors/poolparty/](https://github.com/taogoldi/YARA/tree/main/injectors/poolparty).
- [docs/](https://github.com/taogoldi/analysis_data/tree/main/poolparty_may_2026/docs) blog source markdown
- [images/](https://github.com/taogoldi/analysis_data/tree/main/poolparty_may_2026/images) IDA screenshots referenced in the post (Sample B variant 7 trigger, variant 6 ALPC entry, OpenProcess call site)
- [sample/](https://github.com/taogoldi/analysis_data/tree/main/poolparty_may_2026/sample) corpus identification and acquisition notes (no binaries)

Key external references:
- [SafeBreach blog (original technique disclosure)](https://www.safebreach.com/blog/process-injection-using-windows-thread-pools/)
- [BlackHat EU 2023 paper (Alon Leviev)](https://i.blackhat.com/EU-23/Presentations/EU-23-Leviev-The-Pool-Party-You-Will-Never-Forget.pdf)
- [SafeBreach-Labs/PoolParty source repository](https://github.com/SafeBreach-Labs/PoolParty)
- [hasherezade/pe_to_shellcode](https://github.com/hasherezade/pe_to_shellcode)
- [LevelBlue/Stroz SharpParty](https://levelblue.com/blogs/security-essentials/sharpparty)
- [MWDB CERT-PL Sample C](https://mwdb.cert.pl/file/849e64db81b5bebe1d0b6fb82dd66a1fd8bb4094a016beff6e501bcbbf36e72c)
- [Hatching Triage replay (Sample C)](https://tria.ge/260301-mqyc9scz6g)

The three sample binaries are not redistributed in this bundle. Pull them from VirusTotal, MalwareBazaar, MWDB CERT-PL, or the upstream SafeBreach repository by SHA-256:

- Sample A: `24c141656d4a9f75513d167f0a4664a8bfe63ecd93e27b5e5b150b0e89b0e8b7`
- Sample B: `4cfc8ee7f76a8c7aca96fa783a8d90e915fc1f720062a8241f0c2a0247a382c5`
- Sample C: `849e64db81b5bebe1d0b6fb82dd66a1fd8bb4094a016beff6e501bcbbf36e72c`
