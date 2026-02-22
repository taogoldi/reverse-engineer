# Scripts Reference

Run commands from repo root: `/Users/yakovgoldberg/Downloads/Chrysalis`.

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Primary Entry Point

Run full unpacking + DB diff + CFG visualization workflow:

```bash
python3 scripts/run_chrysalis_pipeline.py
```

Force full rebuild:

```bash
python3 scripts/run_chrysalis_pipeline.py --force
```

## Key Scripts

### `scripts/run_chrysalis_pipeline.py`
Orchestrates stage1 extraction, stage2 materialization, config decryption, PE diff, DB diff reports, and CFG HTML rendering.

### `scripts/sqlite_diff_report.py`
Generates DB-diff CSV reports directly from sqlite databases (no notebook required).

### `scripts/render_cfg_diff_html.py`
Renders side-by-side static-SVG CFG HTML reports.
Default output: `notebooks/visuals/cfg_html`.

### `scripts/emulate_logwrite_dump_shellcode.py`
Unicorn-based stage1 extraction from `log.dll!LogWrite` path.

### `scripts/offline_extract_stage2.py`
Offline stage2/main-module reconstruction and decrypt transform application.

### `scripts/decrypt_btservice_config.py`
RC4 config decryptor for `input/encrypted_shellcode.bin`.

### `scripts/diff_patched_pe.py`
Diffs original vs patched PE and exports changed ranges with RVA/VA mapping.

### `scripts/pe_find.py`
Searches PE bytes/values and maps file offsets to RVA/VA.

### `scripts/render_flowchart.py`
Renders `docs/pipeline_flowchart.dot` to PNG (Graphviz `dot` required).

### `scripts/chrysalis_notebook_lib.py`
Shared helper library used by notebooks.

## Output Paths

- Binary outputs: `output/`
- DB diff reports: `notebooks/tables/db_diff_reports/`
- CFG HTML: `notebooks/visuals/cfg_html/`
