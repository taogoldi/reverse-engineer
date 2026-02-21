#!/usr/bin/env python3
"""
Orchestrate the full Chrysalis workflow:
1) Stage1 extraction (Unicorn)
2) Stage2/main-module materialization (patched PE + memory image)
3) RC4 config decryption
4) Patched PE diff report
5) SQLite DB diff CSV reports
6) CFG HTML diff reports
"""

from __future__ import annotations

import argparse
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Sequence

DEFAULT_ARG_STRUCT = (
    "0x116A7 0x5 0x1000 0x24000 0x2D000 0x30000 0x31000 0x0 0x0 "
    "0x23000 0x8E00 0xC00 0x200 0x1C00 0x0 0x0 0x400000 0x0 "
    "0x31000 0x2C5D0 0x30001000 0x100014C0 0x100014D0 0x30000000 0x0"
)


def find_repo_root(start: Path) -> Path:
    start = start.resolve()
    for d in [start, *start.parents]:
        if (d / "scripts").is_dir() and (d / "input").is_dir() and (d / "databases").is_dir():
            return d
    return start


def run_cmd(cmd: Sequence[str], cwd: Path) -> None:
    print(f"[+] $ {' '.join(shlex.quote(x) for x in cmd)}", flush=True)
    subprocess.run(cmd, cwd=str(cwd), check=True)


def should_run(output_paths: Sequence[Path], force: bool) -> bool:
    if force:
        return True
    return not all(p.exists() for p in output_paths)


def default_python(root: Path) -> str:
    venv_py = root / ".venv" / "bin" / "python"
    if venv_py.exists():
        return str(venv_py)
    return sys.executable


def main(argv: Sequence[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Run end-to-end Chrysalis unpacking + diff visualization workflow")
    ap.add_argument("--python", default=None, help="Python interpreter to use for child scripts")
    ap.add_argument("--arg-struct", default=DEFAULT_ARG_STRUCT, help="25-dword arg struct passed to offline_extract_stage2.py")

    ap.add_argument("--skip-stage1", action="store_true", help="Skip stage1 extraction")
    ap.add_argument("--skip-stage2", action="store_true", help="Skip stage2 materialization")
    ap.add_argument("--skip-config", action="store_true", help="Skip RC4 config decryption")
    ap.add_argument("--skip-pe-diff", action="store_true", help="Skip patched PE diff report")
    ap.add_argument("--skip-db-diff", action="store_true", help="Skip sqlite DB diff report generation")
    ap.add_argument("--skip-cfg", action="store_true", help="Skip CFG HTML rendering")

    ap.add_argument("--force", action="store_true", help="Re-run steps even if expected outputs already exist")

    ap.add_argument("--db-report-dir", default="notebooks/tables/db_diff_reports", help="DB diff CSV output directory")
    ap.add_argument("--cfg-out-dir", default="notebooks/visuals/cfg_html", help="CFG HTML output directory")
    ap.add_argument("--cfg-top", type=int, default=12, help="Top N patched functions for CFG rendering")
    ap.add_argument("--cfg-min-inst-delta", type=float, default=150.0, help="Min inst_delta for CFG target selection")
    ap.add_argument("--cfg-max-lines", type=int, default=12, help="Max assembly lines per CFG block label")

    args = ap.parse_args(argv)

    root = find_repo_root(Path.cwd())
    print(f"[+] Repo root: {root}", flush=True)

    py_arg = args.python if args.python else default_python(root)
    py = str(Path(py_arg)) if Path(py_arg).exists() else py_arg

    shellcode = root / "output/shellcode.bin"
    shellcode_full = root / "output/shellcode_full.bin"
    patched_pe = root / "output/main_module_patched.exe"
    mem_img = root / "output/main_module_mem.bin"
    config_out = root / "output/config_decrypted.bin"
    diff_txt = root / "output/patched_diff.txt"
    diff_json = root / "output/patched_diff.json"
    db_report_dir = (root / args.db_report_dir).resolve() if not Path(args.db_report_dir).is_absolute() else Path(args.db_report_dir)
    cfg_out_dir = (root / args.cfg_out_dir).resolve() if not Path(args.cfg_out_dir).is_absolute() else Path(args.cfg_out_dir)

    if not args.skip_stage1:
        if should_run([shellcode, shellcode_full], args.force):
            run_cmd(
                [
                    py,
                    "scripts/emulate_logwrite_dump_shellcode.py",
                    "input/log.dll",
                    "--payload",
                    "input/encrypted_shellcode.bin",
                    "--mode",
                    "logwrite",
                    "--stdout-log",
                    "output/logwrite_run.log",
                ],
                root,
            )
        else:
            print("[+] stage1: outputs exist, skipping (use --force to rebuild)")

    if not args.skip_stage2:
        if should_run([patched_pe], args.force):
            run_cmd(
                [
                    py,
                    "scripts/offline_extract_stage2.py",
                    "--image",
                    "input/BluetoothService.exe",
                    "--stage1",
                    "output/shellcode_full.bin",
                    "--arg-struct",
                    args.arg_struct,
                    "--out",
                    "output/main_module_patched.exe",
                ],
                root,
            )
        else:
            print("[+] stage2 patched PE: output exists, skipping (use --force to rebuild)")

        if should_run([mem_img], args.force):
            run_cmd(
                [
                    py,
                    "scripts/offline_extract_stage2.py",
                    "--container-pe",
                    "input/BluetoothService.exe",
                    "--stage1",
                    "output/shellcode_full.bin",
                    "--arg-struct",
                    args.arg_struct,
                    "--strategy",
                    "sections_from_stage1",
                    "--out",
                    "output/main_module_mem.bin",
                ],
                root,
            )
        else:
            print("[+] stage2 mem image: output exists, skipping (use --force to rebuild)")

    if not args.skip_config:
        if should_run([config_out], args.force):
            run_cmd(
                [
                    py,
                    "scripts/decrypt_btservice_config.py",
                    "--in",
                    "input/encrypted_shellcode.bin",
                    "--out",
                    "output/config_decrypted.bin",
                ],
                root,
            )
        else:
            print("[+] config decrypt: output exists, skipping (use --force to rebuild)")

    if not args.skip_pe_diff:
        if should_run([diff_txt, diff_json], args.force):
            run_cmd(
                [
                    py,
                    "scripts/diff_patched_pe.py",
                    "--orig",
                    "input/BluetoothService.exe",
                    "--patched",
                    "output/main_module_patched.exe",
                    "--out-prefix",
                    "output/patched_diff",
                ],
                root,
            )
        else:
            print("[+] patched PE diff: outputs exist, skipping (use --force to rebuild)")

    if not args.skip_db_diff:
        patched_csv = db_report_dir / "patched_functions.csv"
        if should_run([patched_csv], args.force):
            run_cmd(
                [
                    py,
                    "scripts/sqlite_diff_report.py",
                    "--db-dir",
                    "databases",
                    "--out-dir",
                    str(db_report_dir),
                    "--top-asm",
                    "3",
                    "--min-asm-inst-delta",
                    str(int(args.cfg_min_inst_delta)),
                ],
                root,
            )
        else:
            print("[+] sqlite DB diff: reports exist, skipping (use --force to rebuild)")

    if not args.skip_cfg:
        run_cmd(
            [
                py,
                "scripts/render_cfg_diff_html.py",
                "--primary-db",
                "databases/BluetoothService.exe.sqlite",
                "--secondary-db",
                "databases/main_module_patched.exe.sqlite",
                "--patched-csv",
                str(db_report_dir / "patched_functions.csv"),
                "--top",
                str(args.cfg_top),
                "--min-inst-delta",
                str(args.cfg_min_inst_delta),
                "--max-lines",
                str(args.cfg_max_lines),
                "--out-dir",
                str(cfg_out_dir),
            ],
            root,
        )

    print("[+] Pipeline completed")
    print(f"[+] DB reports: {db_report_dir}")
    print(f"[+] CFG HTML:   {cfg_out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
