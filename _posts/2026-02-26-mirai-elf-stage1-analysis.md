---
layout: post
title: "Mirai-like ELF Reversing, Part I: Stage1 Trust Gate, Command Dispatch, and Killer Loop"
permalink: /blog/mirai-elf-stage1-analysis/
date: 2026-02-26 00:00:00 +0000
toc: true
image:
  path: /assets/images/posts/mirai/mirai_stage1_header.png
categories: [malware-reversing, threat-intel]
tags: [mirai, elf, linux-malware, ddos, botnet, yara, static-analysis, ida-pro]
---

This post walks through what we extracted from one Linux ELF sample and how we extracted it, without hand-wavy claims.

For less technical readers: this malware is a bot. It connects to a control server, checks that the server is the one it expects, receives commands, and launches network flood routines. At the same time it runs a cleanup loop to remove or kill other tools/processes on the same device.

For technical readers: all findings below are tied to reproducible scripts, offsets, and disassembly slices in the local workspace.

## Sample and Scope

| Artifact | SHA-256 |
| --- | --- |
| `d40cf9c95dcedf4f19e4a5f5bb744c8e98af87eb5703c850e6fda3b613668c28.elf` (Stage1 sample) | `d40cf9c95dcedf4f19e4a5f5bb744c8e98af87eb5703c850e6fda3b613668c28` |

Acquisition source (defanged): `http://144[.]172[.]108[.]230/bins/mynode.x86_64`

**Working assessment:** Mirai-like Stage1 loader/bot, high confidence.

## Executive Workflow

![Mirai Stage1 Workflow](/assets/images/posts/mirai/mirai_stage1_workflow.svg)

### Stage map (sample-specific)

- `main` at `0x4002a0`: command/control loop and method dispatch.
- `verify_server_ip` at `0x4001c0`: trust gate for connected peer.
- `killer_thread_func` at `0x400730`: endless anti-competition loop.
- `disable_infection_tools` at `0x400a10`: downloader/tool disruption.
- `scan_and_kill` at `0x400d60`: `/proc` scan and process termination.

## What the Malware Does

### 1) Connects and verifies who it is talking to

The sample contains a hardcoded server IP string at `0x41498a`: `144.172.108.230`.

`main` establishes a connection, then calls `verify_server_ip`. If the connected peer IP does not match the hardcoded value, the command path is rejected.

Plain language: this is a trust check so the bot listens only to its expected controller.

![Hardcoded authorized C2 IP in `.rodata`](/assets/images/posts/mirai/hex_mirai_authorized_ip_0x41498A.png)

`verify_server_ip` in assembly:

![`verify_server_ip` assembly (`0x4001c0`)](/assets/images/posts/mirai/asm_mirai_verify_server_ip_0x4001C0.png)

`verify_server_ip` in pseudocode:

![`verify_server_ip` pseudocode (`0x4001c0`)](/assets/images/posts/mirai/c_mirai_verify_server_ip_0x4001C0.png)

### 2) Parses command lines and dispatches attack methods

The parser in `main` routes method tokens to dedicated handlers.

| Command | Callsite in `main` | Handler |
| --- | --- | --- |
| `udp` | `0x4004f1` | `method_udp` (`0x401380`) |
| `syn` | `0x40052e` | `method_syn` (`0x4027b0`) |
| `ack` | `0x4005b3` | `method_ack` (`0x4026d0`) |
| `udpslam` | `0x400667` | `method_udpslam` (`0x401280`) |
| `junk` | `0x4006c6` | `method_junk` (`0x401190`) |
| `raknet` | `0x40063e` | `method_raknet` (`0x4010a0`) |
| `udpburst` | `0x400703` | `method_udpburst` (`0x400f60`) |

Observed control tokens include `!SIGKILL` and `!hello`.

Plain language: the bot has a menu of traffic attacks, and the server chooses which one to run.

Method tokens in `.rodata`:

![Method tokens (`udp/syn/ack/raknet/udpslam/junk/udpburst`) at `0x4149e7`](/assets/images/posts/mirai/hex_mirai_method_tokens_0x4149E7.png)

Main dispatch assembly excerpt from `main` (`0x400412` to `0x400703`):

```asm
400412: cld
400413: mov ecx, 0x9
400418: mov rsi, r15
40041b: mov edi, 0x4149c6
400420: rep cmpsb
400422: je  0x4005bd <force_sigkill path>
...
4004ce: rep cmpsb                    ; "udp"
4004f1: call 0x401380 <method_udp>
...
40050b: rep cmpsb                    ; "syn"
40052e: call 0x4027b0 <method_syn>
...
400590: rep cmpsb                    ; "ack"
4005b3: call 0x4026d0 <method_ack>
...
400617: rep cmpsb                    ; "raknet"
40063e: call 0x4010a0 <method_raknet>
...
400667: call 0x401280 <method_udpslam>
...
4006c6: call 0x401190 <method_junk>
...
4006e0: rep cmpsb                    ; "udpburst"
400703: call 0x400f60 <method_udpburst>
```

This excerpt is from `/Users/yakovgoldberg/Projects/Malware/Mirai/reports/disasm/main.asm` and matches the dispatch table above.

### 3) Runs anti-competition logic in parallel

`killer_thread_func` repeatedly calls:

1. `disable_infection_tools`
2. `scan_and_kill`
3. sleep
4. repeat

Referenced binary/tool paths include:

- `/usr/bin/wget`
- `/usr/bin/curl`
- `/usr/bin/tftp`
- `/usr/bin/ftp`
- `/usr/bin/scp`
- `/usr/bin/nc`
- `/usr/bin/netcat`
- `/usr/bin/ncat`
- `/bin/busybox`

Plain language: once installed, it tries to keep control by removing competitors and useful admin tooling.

`killer_thread_func` loop:

![`killer_thread_func` assembly (`0x400730`)](/assets/images/posts/mirai/asm_mirai_killer_thread_0x400730.png)

`disable_infection_tools` routine:

![`disable_infection_tools` assembly (`0x400a10`)](/assets/images/posts/mirai/asm_mirai_disable_infection_tools_0x400A10.png)

`scan_and_kill` routine:

![`scan_and_kill` assembly (`0x400d60`)](/assets/images/posts/mirai/asm_mirai_scan_and_kill_0x400D60.png)

### 4) Carries multiple flood payload templates

`.rodata` contains traffic templates and markers including:

- `M-SEARCH * HTTP/1.1`
- `Via: SIP/2.0/UDP 192.168.1.1:5060`

This aligns with multi-method DDoS behavior and protocol-specific packet crafting.

## Subroutines of Interest (What each one does)

| Function | VA (sample-specific) | Role |
| --- | --- | --- |
| `main` | `0x4002a0` | Core bot loop: connect, verify peer, parse command, dispatch method handler. |
| `verify_server_ip` | `0x4001c0` | Compares connected peer IP against hardcoded trusted server IP. |
| `killer_thread_func` | `0x400730` | Long-running worker that repeatedly applies anti-competition logic. |
| `disable_infection_tools` | `0x400a10` | Targets downloader/admin tools to reduce competing access paths. |
| `scan_and_kill` | `0x400d60` | Walks `/proc` and kills processes matching internal checks. |
| `__dns_lookup` | `0x41312c` | Builds DNS query, sends/receives UDP DNS data, validates response flow. |
| `__decode_header` | `0x414034` | Parses DNS header bytes into decoded fields (`id`, flags, section counts). |
| `method_udpburst` | `0x400f60` | One concrete flood method implementation reachable from command parser. |

For less technical readers: these are the key “jobs” inside the bot. Together they explain command intake, trust control, attack execution, and persistence behavior.

## Why the DNS decode subroutine matters

The routine identified as `__decode_header` parses a DNS wire header into decoded fields (`id`, `flags`, `qdcount`, `ancount`, etc.).

That routine itself is not a unique “family signature” in isolation. It is significant because:

- it sits in the resolver path used by `__dns_lookup`,
- it shapes response validation behavior,
- and its byte sequence overlaps an Elastic rule motif (`Linux_Trojan_Gafgyt_d0c57a2e`), which supports lineage overlap.

Practical analyst takeaway: treat this as shared protocol/lineage evidence, not sole attribution evidence.

`__dns_lookup` and resolver path:

![`__dns_lookup` assembly (`0x41312c`)](/assets/images/posts/mirai/asm_mirai_dns_lookup_0x41312C.png)

`__decode_header` assembly:

![`__decode_header` assembly (`0x414034`)](/assets/images/posts/mirai/asm_mirai_decode_header_0x414034.png)

`__decode_header` pseudocode:

![`__decode_header` pseudocode (`0x414034`)](/assets/images/posts/mirai/c_mirai_decode_header_0x414034.png)

## Comparison with Fortinet Gayfemboy Campaign

I compared this sample against Fortinet's campaign write-up and figure-level indicators.

Reference: [Fortinet IoT malware Gayfemboy Mirai campaign](https://www.fortinet.com/blog/threat-research/iot-malware-gayfemboy-mirai-based-botnet-campaign)

### What overlaps

- Mirai-style resolver/decoder behavior.
- Process-killer/anti-tooling patterns.
- Shared DDoS template style.

### What does not overlap

- No campaign-specific domain strings shown in that report.
- No reported process-killer keywords (`twinks :3`, `meowmeow`, `whattheflip`, `^kill^`).
- No watchdog control marker `47272` in extracted strings.

Conservative conclusion: Mirai-lineage overlap, but not enough to claim same campaign cluster.

## Reproducible Data-Extraction Workflow

All outputs below are generated from scripts in `malware/Mirai`.

### End-to-end run

```bash
python3 scripts/run_full_analysis.py
```

### Step-by-step scripts

```bash
python3 scripts/triage_mirai_elf.py
python3 scripts/extract_mirai_rodata_artifacts.py
python3 scripts/extract_command_dispatch.py
python3 scripts/export_disasm_slices.py
python3 scripts/compare_fortinet_gayfemboy.py
python3 scripts/parse_helper_capa_summary.py
```

### Artifacts produced

- `reports/json/triage_report.json`
- `reports/json/rodata_artifacts.json`
- `reports/json/command_dispatch_map.json`
- `reports/json/fortinet_gayfemboy_overlap.json`
- `reports/json/helper_capa_summary.json`
- `reports/disasm/*.asm`
- `reports/static/*.txt`

## Notebook and IDA Scripts

### Notebook

- `notebooks/mirai_stage1_analysis.ipynb`

What it does:

- runs the pipeline,
- loads JSON artifacts,
- summarizes key IOCs/offsets for reporting.

### IDA scripts

- `ida_python/mirai_stage1_annotator.py`
  - Renames core functions/data symbols.
  - Adds comments for C2 trust gate, dispatch points, and killer loop.

- `ida_python/mirai_string_hunt_annotator.py`
  - Finds high-signal strings and tags xrefs for fast triage.

- `ida_python/mirai_dns_resolver_pattern_annotator.py`
  - Variant-agnostic byte-pattern search for DNS decode logic.
  - Renames/types resolver functions and injects decode comments without hardcoded addresses.

- `ida_python/mirai_dns_resolver_annotator.py`
  - Sample-specific resolver annotations (address-driven convenience script).

## YARA Rules

Rules file: `detection/mirai_like_d40cf9_rules.yar`

```yara
rule MIRAI_LIKE_D40CF9_STAGE1_HighFidelity
{
  meta:
    author = "taogoldi"
    date = "2026-02-26"
    version = "1"
    sha256 = "d40cf9c95dcedf4f19e4a5f5bb744c8e98af87eb5703c850e6fda3b613668c28"
    description = "High-fidelity rule for the analyzed Mirai-like ELF sample"

  strings:
    $s1 = "[*] Connected to authorized server (%s)" ascii
    $s2 = "[!!!] SECURITY ALERT: Command from unauthorized IP: %s (expected: %s)" ascii
    $s3 = "144.172.108.230" ascii
    $s4 = "!SIGKILL" ascii
    $s5 = "1337SoraLOADER" ascii
    $s6 = "method_udpburst" ascii
    $s7 = "[*] Killer thread started." ascii

  condition:
    uint32(0) == 0x464c457f and 5 of ($s*)
}

rule MIRAI_LIKE_D40CF9_STAGE1_VariantHeuristic
{
  meta:
    author = "taogoldi"
    date = "2026-02-26"
    version = "1"
    sha256 = "d40cf9c95dcedf4f19e4a5f5bb744c8e98af87eb5703c850e6fda3b613668c28"
    description = "Heuristic Mirai-like detector for this cluster family"

  strings:
    $m1 = "udpslam" ascii
    $m2 = "udpburst" ascii
    $m3 = "raknet" ascii
    $m4 = "M-SEARCH * HTTP/1.1" ascii
    $m5 = "Via: SIP/2.0/UDP 192.168.1.1:5060" ascii
    $m6 = "/proc/%s/cmdline" ascii
    $m7 = "/proc/%s/maps" ascii
    $m8 = "/bin/busybox" ascii
    $m9 = "disable_infection_tools" ascii
    $m10 = "scan_and_kill" ascii

  condition:
    uint32(0) == 0x464c457f and
    7 of ($m*)
}
```

## Closing Notes

This is Part I (Stage1). The core behavior is clear and reproducible: trust-gated C2 command intake, explicit method dispatch, and continuous anti-competition hardening.

Part II should focus on richer runtime-backed behavior profiling and broader clustering across additional Mirai-like samples.
