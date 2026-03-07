---
title: "Kaiji-Like Linux ELF Reversing: Persistence, C2 Token Recovery, and Ares Module Mapping"
permalink: /blog/kaiji-stage1-offline-analysis/
date: 2026-03-07 00:00:00 +0000
categories: [malware-reversing, threat-intel]
tags: [kaiji, ares, linux-malware, elf, botnet, static-analysis, yara, ida-pro]
image: /assets/images/social/kaiji-stage1-card.png
description: "Offline static analysis of a Kaiji-like Linux ELF sample: persistence, decoded C2 token, Ares module mapping, and reproducible analyst artifacts."
---

This post documents a reproducible static workflow for one Linux ELF sample (`linux_amd64`, SHA-256 `0a70d7699c8e0629597dcc03b1aef0beebec03ae0580f2c070fb2bfd2fd89a71`) downloaded from:

- `hxxp://144[.]172[.]108[.]230/bins/mynode.x86_64`

Scope: persistence behavior, embedded C2-like token extraction, attack-module mapping, and reusable tooling. No live C2 interaction is used in this phase.

## Sample Scope

| Artifact | SHA-256 |
| --- | --- |
| `linux_amd64` | `0a70d7699c8e0629597dcc03b1aef0beebec03ae0580f2c070fb2bfd2fd89a71` |

## Downloads

- Analysis bundle: [analysis_data/kaiji_mar_2026](https://github.com/taogoldi/analysis_data/tree/main/kaiji_mar_2026)
- Scripts: [scripts/](https://github.com/taogoldi/analysis_data/tree/main/kaiji_mar_2026/scripts)
- Notebook: [notebooks/](https://github.com/taogoldi/analysis_data/tree/main/kaiji_mar_2026/notebooks)
- IDA helpers: [ida/](https://github.com/taogoldi/analysis_data/tree/main/kaiji_mar_2026/ida)
- Reports: [reports/](https://github.com/taogoldi/analysis_data/tree/main/kaiji_mar_2026/reports)
- YARA: [botnets/kaiji/kaiji_like_0a70_rules.yar](https://github.com/taogoldi/YARA/blob/main/botnets/kaiji/kaiji_like_0a70_rules.yar)

## Stage Flow

![Kaiji stage flow](/assets/images/posts/kaiji/kaiji_stage_flow.png)

## Findings

### 1) Persistence and host-masquerade indicators

Observed strings include:

- `/usr/lib/systemd/system/quotaoff.service`
- `echo "*/1 * * * * root /.mod " >> /etc/crontab`
- `ExecStart=/boot/System.mod`
- `ExecReload=/boot/System.mod`
- `ExecStop=/boot/System.mod`
- `/usr/sbin/ifconfig.cfg`

These indicators align with systemd + cron persistence and dropped-path masquerading.

![Systemd path callsite](/assets/images/posts/kaiji/asm_kaiji_systemd_path_quotaoff.png)

![Cron persistence callsite](/assets/images/posts/kaiji/asm_kaiji_cron_persist_cmd.png)

![Service template execution lines](/assets/images/posts/kaiji/asm_kaiji_service_exec_lines.png)

![systemctl chain callsite](/assets/images/posts/kaiji/asm_kaiji_systemctl_chain.png)

### 2) Embedded C2-like token recovery

Embedded Base64 token:

- `YWlyLnhlbS5sYXQ6MjUxOTR8KG9kaykvKi0=`

Decoded token:

- `air.xem.lat:25194|(odk)/*-`

Analyst-supplied IOC context for pivoting during validation:

- `air.duffy.baby:888`

![Base64 decode callsite](/assets/images/posts/kaiji/asm_kaiji_b64_c2_xref.png)

![Base64 token raw bytes](/assets/images/posts/kaiji/hex_kaiji_b64_c2_token_0x11A593.png)

Decompiler view of the decode caller path:

![Decompiler C2 decode caller](/assets/images/posts/kaiji/c_kaiji_c2_decode_caller.png)

### 3) Ares-style attack module naming and dispatch context

Recovered symbol cluster includes:

- `main.Ares_Tcp`
- `main.Ares_L3_Udp`
- `main.Ares_ipspoof`
- `main.Killcpu`
- `main.watchdog`

This naming is consistent with Kaiji/Ares-style flooding and watchdog behavior.

![Ares/Killcpu symbol cluster](/assets/images/posts/kaiji/strings_kaiji_ares_family_cluster.png)

Decompiler views from persistence callers:

![Decompiler service persistence caller](/assets/images/posts/kaiji/c_kaiji_persist_service_caller.png)

![Decompiler cron caller](/assets/images/posts/kaiji/c_kaiji_cron_caller.png)

## IDA Python Helpers

- `kaiji_stage1_annotator.py`
  - Tags core behavior callsites (persistence strings, embedded token decode, suspicious helper pivots) and applies targeted rename/comment passes.
- `kaiji_pattern_annotator.py`
  - Signature-based locator for key byte/string patterns when exact addresses differ between variants.
- `kaiji_go_function_renamer.py`
  - Normalizes recovered Go symbol names into analyst-readable labels for faster triage.
- `kaiji_xref_callsite_mapper.py`
  - Exports address-to-caller mappings into `*_callsite_map.csv` and `*_callsite_map.json` for reproducible pivots.

Example output lines captured during runs:

```text
[kaiji_annotator] kaiji_embedded_b64_c2: 1 hit(s)
[kaiji_pattern] embedded_base64_c2: <N> hit(s)
[kaiji_callsite_mapper] rows=<N>
[kaiji_callsite_mapper] csv=<sample>_callsite_map.csv
```

## Reproducible Workflow Files

### Scripts

- `scripts/run_full_analysis.py`
- `scripts/triage_kaiji_elf.py`
- `scripts/extract_kaiji_config.py`
- `scripts/extract_rodata_artifacts.py`
- `scripts/extract_persistence_script_blocks.py`
- `scripts/go_symbol_capability_matrix.py`
- `scripts/build_ioc_report.py`
- `scripts/decode_embedded_base64.py`

### Notebook

- `notebooks/kaiji_stage1_analysis.ipynb`

### IDA

- `ida/kaiji_stage1_annotator.py`
- `ida/kaiji_pattern_annotator.py`
- `ida/kaiji_go_function_renamer.py`
- `ida/kaiji_xref_callsite_mapper.py`

## Detection (YARA)

Rules are maintained in:

- `detection/kaiji_like_0a70_rules.yar`
- [YARA repo path](https://github.com/taogoldi/YARA/blob/main/botnets/kaiji/kaiji_like_0a70_rules.yar)

```yara
import "elf"

rule Linux_KaijiLike_Persist_C2_0a70 {
  meta:
    author = "taogoldi"
    family = "kaiji-like"
    version = "1"
    sha256 = "0a70d7699c8e0629597dcc03b1aef0beebec03ae0580f2c070fb2bfd2fd89a71"
    scope = "file"
    description = "Kaiji-like Go ELF with embedded base64 C2 token and quotaoff persistence"

  strings:
    $b64_c2 = "YWlyLnhlbS5sYXQ6MjUxOTR8KG9kaykvKi0=" ascii
    $persist_service = "/usr/lib/systemd/system/quotaoff.service" ascii
    $persist_cron = "echo \"*/1 * * * * root /.mod \" >> /etc/crontab" ascii
    $persist_exec = "ExecStart=/boot/System.mod" ascii
    $drop_path = "/usr/sbin/ifconfig.cfg" ascii
    $module_tag = "[a=r=e=s]]" ascii

  condition:
    elf.type == elf.ET_EXEC and
    filesize < 5MB and
    4 of ($b64_c2, $persist_service, $persist_cron, $persist_exec, $drop_path, $module_tag)
}

rule Linux_KaijiLike_AresModuleSet_0a70 {
  meta:
    author = "taogoldi"
    family = "kaiji-like"
    version = "1"
    sha256 = "0a70d7699c8e0629597dcc03b1aef0beebec03ae0580f2c070fb2bfd2fd89a71"
    scope = "file"
    description = "Kaiji/Ares attack module namespace and source path indicators"

  strings:
    $fn1 = "main.Ares_ipspoof" ascii
    $fn2 = "main.Ares_L3_Udp" ascii
    $fn3 = "main.Ares_Tcp_Keep" ascii
    $fn4 = "main.Killcpu" ascii
    $src1 = "C:/src/client/linux/ares_tcp.go" ascii
    $src2 = "C:/src/client/linux/ares_udp.go" ascii
    $src3 = "C:/src/client/linux/ares_spoof.go" ascii
    $src4 = "C:/src/client/linux/killcpu.go" ascii

  condition:
    elf.type == elf.ET_EXEC and
    filesize < 5MB and
    6 of them
}
```

## Confidence and limits

Current assessment: Kaiji-like/Ares-like Linux bot component, high confidence for persistence behavior and attack-module intent based on static artifacts.

Not claimed in this write-up:

- live C2 protocol validation
- runtime command execution telemetry
- execution-side environmental branching
