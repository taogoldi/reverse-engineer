---
icon: fas fa-info-circle
order: 4
---

# About Me

I'm a security professional with a focus on malware analysis, reverse engineering, and operating system internals. My work centers on taking apart real-world threats, understanding how they operate at the binary level, and producing analysis that other researchers can reproduce and build on.

This blog documents my reversing workflow across Windows PE, Linux ELF, and Go-compiled malware. Every post includes decompiled source code, extracted configurations, detection rules, and downloadable analysis artifacts. If I claim something in a write-up, there's a script or a disassembly slice to back it up.

## What I Cover

- **.NET malware reversing** (ILSpy decompilation, config extraction, crypter teardowns)
- **Native binary analysis** (IDA Pro, radare2, Ghidra)
- **Go malware** (GoReSym, symbol recovery, CJK obfuscation analysis)
- **Detection engineering** (YARA rules, Suricata signatures, IOC extraction)
- **Cryptographic analysis** (AES, PBKDF2, RC4 config decryption with Python tooling)
- **Threat intelligence** (C2 infrastructure mapping, campaign tracking, attribution analysis)

## Repositories

| Repo | What's Inside |
|---|---|
| [reverse-engineer](https://github.com/taogoldi/reverse-engineer) | This blog. Source markdown, diagrams, and IDA screenshots |
| [analysis_data](https://github.com/taogoldi/analysis_data) | Scripts, decompiled source code, extraction tools, and reports for every analyzed sample |
| [YARA](https://github.com/taogoldi/YARA) | Detection rules organized by malware family (stealers, RATs, botnets, backdoors) |

## Published Analyses

| Family | Type | Key Findings |
|---|---|---|
| [Chrysalis]({{ "/blog/chrysalis-offline-unpacking/" | relative_url }}) | .NET backdoor | Multi-stage unpacking, Unicorn emulation, RC4 config recovery |
| [22.exe / Vidar]({{ "/blog/22exe-loader-analysis/" | relative_url }}) | Staged loader | AMSI/ETW bypass, AES-256-CBC decryption, Vidar attribution |
| [Mirai]({{ "/blog/mirai-elf-stage1-analysis/" | relative_url }}) | Linux botnet | Trust gate, 7-method command dispatch, cross-variant validation |
| [Kaiji]({{ "/blog/kaiji-stage1-offline-analysis/" | relative_url }}) | Linux botnet | Go ELF, systemd/cron persistence, Ares module mapping |
| [Pulsar RAT]({{ "/blog/pulsar-rat-dotnet-reversing/" | relative_url }}) | .NET RAT | ConfuserEx deobfuscation, C2 protocol reversal, DPAPI credential theft |
| [njRAT]({{ "/blog/njrat-im523-hacked-campaign/" | relative_url }}) | .NET RAT | Full decompilation, 30+ command dispatch, Win32 API deep dives |
| [Gsb Backdoor]({{ "/blog/gsb-backdoor-go-nuclear-decoy/" | relative_url }}) | Go backdoor | Nuclear reactor decoy obfuscation, CJK garble, Factory-v3 builder |
| [XWorm]({{ "/blog/xworm-crypter-bootkit-rootkit/" | relative_url }}) | .NET crypter + RAT | UEFI bootkit, r77 rootkit, CVE-2026-20817, dual payload extraction |
| [DcRAT]({{ "/blog/dcrat-48kb-config-crack/" | relative_url }}) | .NET RAT | PBKDF2/AES config cracking, fileless plugin architecture |
| [Quasar Loader]({{ "/blog/quasar-loader-custom-cipher/" | relative_url }}) | x64 loader + Quasar RAT | Custom byte-level cipher from raw disassembly, 3.2MB Quasar extraction, PBKDF2/AES-256 config crack |
| [Chaos/Ares]({{ "/blog/chaos-ares-go-botnet/" | relative_url }}) | Go Linux botnet | 12 DDoS vectors, DNS-based C2 with AES/DES, 11 persistence mechanisms including SELinux bypass |
| [NanoCore RAT]({{ "/blog/nanocore-rat-v1220-analysis/" | relative_url }}) | .NET RAT | v1.2.2.0 decompilation, plugin architecture, commercial-trojan persistence |
| [ZyreC2]({{ "/blog/zyrec2-gaming-mirai-ddos/" | relative_url }}) | Linux DDoS botnet | Mirai fork, 9-method Minecraft flooder, Discord attack module, unstripped debug symbols |
| [Pony / Fareit]({{ "/blog/pony-fareit-credential-machine/" | relative_url }}) | x86 credential stealer | 60+ FTP clients, GetTickCount-mod-7 anti-emulation gate, MD5 vs API-hashing identification |
| [Discord RAT 2.0]({{ "/blog/discord-rat-2-chat-server-c2/" | relative_url }}) | .NET Discord-gateway RAT | 50-command WebSocket C2, one-byte fake ransomware, r77 rootkit + BlackNET stealer supply chain, operator snowflake timeline |

## Contact

Find me on GitHub: [github.com/taogoldi](https://github.com/taogoldi)
