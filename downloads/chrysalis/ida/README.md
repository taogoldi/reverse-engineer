# IDA Scripts README

This folder contains IDAPython scripts for annotation, triage, and decompiler reconstruction.

## Prerequisites

- IDA Pro / IDA Home with Python.
- Hex-Rays decompiler is required for scripts that modify pseudocode views.
- Open the target file in IDA and allow analysis to finish before running scripts.

## How To Run

### GUI mode

1. Open target binary in IDA.
2. `File -> Script file...`
3. Select a script from `ida/`.

### Headless mode (Step 1)

- Windows:
  - `idat64.exe -A -Sida\\ida_rebuild_logwrite.py <target_binary>`
- macOS/Linux:
  - `idat64 -A -Sida/ida_rebuild_logwrite.py <target_binary>`

Use the same pattern for any script in this folder.

## Notes

- Scripts are defensive about imports so opening them outside IDA will not hard-crash.
- Most scripts add comments, enums, and optional CSV/JSON outputs.
- Re-running is generally safe; existing comments/enums may be updated.

## Script Index

### `ida/ida_rebuild_logwrite.py`
- Purpose: Rebuild and normalize `LogWrite` + related decompiler view in `log.dll`.
- Actions:
  - Applies function/type names and local typedefs.
  - Improves variable naming in `LogWrite` and `mw_decrypt`.
  - Adds comments around `VirtualProtect` call and stage-arg layout.
- Typical target: `input/log.dll`.

### `ida/ida_chrysalis_api_hash_resolver.py`
- Purpose: Build/apply loader-hash rainbow mapping directly inside IDA.
- Actions:
  - Builds hash table from system DLL exports.
  - Resolves immediate constants at resolver call sites.
  - Annotates matches as likely `dll!export`.
- Typical target: `input/log.dll`.

### `ida/ida_hash_table_apply.py`
- Purpose: Apply an existing nested JSON rainbow table to immediate constants.
- Actions:
  - Loads `{dll: {hash: export}}` JSON.
  - Creates enum symbols.
  - Replaces renderings/comments in disassembly/decompiler where possible.
- Typical target: `input/log.dll` or patched main module.

### `ida/ida_main_module_triage.py`
- Purpose: Fast triage for patched main module artifacts.
- Actions:
  - Applies C2 command-tag enums (`4T..4d` family).
  - Annotates matching constants in code.
  - Optionally imports changed-range JSON from PE diff step.
- Typical target: `output/main_module_patched.exe`, `output/main_module_mem.bin`.

### `ida/ida_c2_dispatch_lifter.py`
- Purpose: Lift and rank command-dispatch logic from C2 tag usage.
- Actions:
  - Finds references to command constants.
  - Scores candidate dispatcher functions by tag coverage.
  - Optional CSV export for reporting.
- Typical target: patched main module artifacts.

### `ida/ida_config_path_mapper.py`
- Purpose: Locate likely config extraction/decryption paths.
- Actions:
  - Searches markers (`0x980`, `0x30808`) in code/data.
  - Lifts xrefs into code and annotates likely functions.
  - Optional CSV export.
- Typical target: patched main module artifacts.
