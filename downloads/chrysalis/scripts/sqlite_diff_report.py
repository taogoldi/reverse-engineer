#!/usr/bin/env python3
"""
Generate DB diff reports between two BinDiff/Diaphora-style sqlite databases.

Outputs CSV reports under notebooks/tables/db_diff_reports by default:
- summary.csv
- all_functions_classified.csv
- same_functions.csv
- added_in_patched.csv
- removed_from_patched.csv
- patched_functions.csv
- patched_preview_mnemonics.csv
- asm_side_by_side_0xXXXXXXXX.csv (optional, top patched funcs)
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple


@dataclass(frozen=True)
class FnDigest:
    func_id: int
    address: int
    name: str
    size: int
    nodes: int
    edges: int
    inst_count: int
    mnemonic_sha1: str
    disasm_sha1: str
    mnemonic_preview: str


def find_repo_root(start: Path) -> Path:
    start = start.resolve()
    for d in [start, *start.parents]:
        if (d / "databases").is_dir() and (d / "scripts").is_dir():
            return d
    return start


def parse_intish(value: object) -> int:
    if value is None:
        return 0
    if isinstance(value, int):
        return value
    s = str(value).strip()
    if not s:
        return 0
    try:
        return int(s, 0)
    except Exception:
        try:
            return int(float(s))
        except Exception:
            return 0


def choose_db_pair(db_dir: Path, legit_db: Optional[str], patched_db: Optional[str]) -> Tuple[Path, Path]:
    if legit_db and patched_db:
        return (Path(legit_db), Path(patched_db))

    dbs = sorted(db_dir.glob("*.sqlite"))
    if len(dbs) < 2:
        raise SystemExit(f"Need at least 2 sqlite DBs in {db_dir}")

    legit = Path(legit_db) if legit_db else None
    patched = Path(patched_db) if patched_db else None

    for p in dbs:
        n = p.name.lower()
        if legit is None and "bluetoothservice" in n:
            legit = p
        if patched is None and ("patched" in n or "main_module" in n):
            patched = p

    if legit and patched:
        return legit, patched

    return dbs[0], dbs[1]


def load_function_meta(conn: sqlite3.Connection) -> Dict[int, dict]:
    q = """
    SELECT id, COALESCE(name,''), COALESCE(address,0), COALESCE(size,0), COALESCE(nodes,0), COALESCE(edges,0)
    FROM functions
    """
    out: Dict[int, dict] = {}
    for fid, name, addr, size, nodes, edges in conn.execute(q):
        out[int(fid)] = {
            "func_id": int(fid),
            "name": str(name),
            "address": int(addr),
            "size": int(size),
            "nodes": int(nodes),
            "edges": int(edges),
        }
    return out


def build_digests(db_path: Path) -> Dict[int, FnDigest]:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        meta = load_function_meta(conn)
        cur = conn.cursor()
        cur.execute(
            """
            SELECT func_id, COALESCE(address,0) AS address, COALESCE(mnemonic,'') AS mnemonic, COALESCE(disasm,'') AS disasm
            FROM instructions
            ORDER BY func_id, address
            """
        )

        # Track per-function aggregations.
        aggs: Dict[int, dict] = {
            fid: {
                "m_hasher": hashlib.sha1(),
                "d_hasher": hashlib.sha1(),
                "inst_count": 0,
                "preview": [],
            }
            for fid in meta
        }

        for row in cur:
            fid = int(row["func_id"])
            if fid not in aggs:
                continue
            m_tok = str(row["mnemonic"])
            d_tok = str(row["disasm"])
            ag = aggs[fid]
            ag["m_hasher"].update(m_tok.encode("utf-8", errors="ignore"))
            ag["m_hasher"].update(b"\n")
            ag["d_hasher"].update(d_tok.encode("utf-8", errors="ignore"))
            ag["d_hasher"].update(b"\n")
            ag["inst_count"] += 1
            if len(ag["preview"]) < 80:
                ag["preview"].append(m_tok.strip())

        by_addr: Dict[int, FnDigest] = {}
        for fid, m in meta.items():
            ag = aggs[fid]
            digest = FnDigest(
                func_id=fid,
                address=int(m["address"]),
                name=str(m["name"]),
                size=int(m["size"]),
                nodes=int(m["nodes"]),
                edges=int(m["edges"]),
                inst_count=int(ag["inst_count"]),
                mnemonic_sha1=ag["m_hasher"].hexdigest(),
                disasm_sha1=ag["d_hasher"].hexdigest(),
                mnemonic_preview=" ".join(tok for tok in ag["preview"] if tok),
            )
            prev = by_addr.get(digest.address)
            # Keep the richer entry when duplicate addresses appear.
            if prev is None or digest.inst_count > prev.inst_count:
                by_addr[digest.address] = digest

        return by_addr
    finally:
        conn.close()


def classify_row(row: dict) -> str:
    merge_tag = row["_merge"]
    if merge_tag == "left_only":
        return "removed_from_patched"
    if merge_tag == "right_only":
        return "added_in_patched"
    if (
        row["mnemonic_sha1_legit"] == row["mnemonic_sha1_patched"]
        and row["disasm_sha1_legit"] == row["disasm_sha1_patched"]
    ):
        return "same"
    return "patched"


def merge_digests(legit: Dict[int, FnDigest], patched: Dict[int, FnDigest]) -> List[dict]:
    rows: List[dict] = []
    for address in sorted(set(legit.keys()) | set(patched.keys())):
        l = legit.get(address)
        p = patched.get(address)

        row = {
            "address": int(address),
            "name_legit": l.name if l else "",
            "name_patched": p.name if p else "",
            "size_legit": l.size if l else "",
            "size_patched": p.size if p else "",
            "nodes_legit": l.nodes if l else "",
            "nodes_patched": p.nodes if p else "",
            "edges_legit": l.edges if l else "",
            "edges_patched": p.edges if p else "",
            "inst_count_legit": l.inst_count if l else "",
            "inst_count_patched": p.inst_count if p else "",
            "mnemonic_sha1_legit": l.mnemonic_sha1 if l else "",
            "mnemonic_sha1_patched": p.mnemonic_sha1 if p else "",
            "disasm_sha1_legit": l.disasm_sha1 if l else "",
            "disasm_sha1_patched": p.disasm_sha1 if p else "",
            "mnemonic_preview_legit": l.mnemonic_preview if l else "",
            "mnemonic_preview_patched": p.mnemonic_preview if p else "",
            "_merge": "both" if (l and p) else ("left_only" if l else "right_only"),
        }
        row["classification"] = classify_row(row)

        if l and p and row["classification"] == "patched":
            row["inst_delta"] = abs(int(p.inst_count) - int(l.inst_count))
            row["size_delta"] = abs(int(p.size) - int(l.size))
        else:
            row["inst_delta"] = ""
            row["size_delta"] = ""

        rows.append(row)

    return rows


def write_csv(path: Path, rows: Sequence[dict], fieldnames: Sequence[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow(r)


def summarize(rows: Sequence[dict]) -> List[dict]:
    counts: Dict[str, int] = {}
    for r in rows:
        c = str(r.get("classification", ""))
        counts[c] = counts.get(c, 0) + 1
    out = [{"classification": k, "count": v} for k, v in counts.items()]
    out.sort(key=lambda x: int(x["count"]), reverse=True)
    return out


def get_func_by_address(conn: sqlite3.Connection, address: int) -> Optional[dict]:
    q = "SELECT id, COALESCE(name,''), COALESCE(address,0), COALESCE(size,0) FROM functions WHERE address = ?"
    row = conn.execute(q, (int(address),)).fetchone()
    if not row:
        return None
    return {
        "id": int(row[0]),
        "name": str(row[1]),
        "address": int(row[2]),
        "size": int(row[3]),
    }


def load_function_instructions(conn: sqlite3.Connection, function_id: int) -> List[Tuple[int, str]]:
    q = """
    SELECT COALESCE(address,0) AS address, COALESCE(disasm,'') AS disasm
    FROM instructions
    WHERE func_id = ?
    ORDER BY address
    """
    return [(int(a), str(d)) for a, d in conn.execute(q, (int(function_id),)).fetchall()]


def write_asm_side_by_side(
    out_path: Path,
    legit_insts: Sequence[Tuple[int, str]],
    patched_insts: Sequence[Tuple[int, str]],
) -> None:
    max_len = max(len(legit_insts), len(patched_insts))
    rows: List[dict] = []
    for idx in range(max_len):
        la = legit_insts[idx][0] if idx < len(legit_insts) else ""
        ld = legit_insts[idx][1] if idx < len(legit_insts) else ""
        pa = patched_insts[idx][0] if idx < len(patched_insts) else ""
        pd = patched_insts[idx][1] if idx < len(patched_insts) else ""
        rows.append(
            {
                "idx": idx,
                "legit_addr": la,
                "legit_disasm": ld,
                "patched_addr": pa,
                "patched_disasm": pd,
                "same_line": bool(ld == pd),
                "legit_addr_hex": f"0x{int(la):08X}" if isinstance(la, int) else "",
                "patched_addr_hex": f"0x{int(pa):08X}" if isinstance(pa, int) else "",
            }
        )

    fieldnames = [
        "idx",
        "legit_addr",
        "legit_disasm",
        "patched_addr",
        "patched_disasm",
        "same_line",
        "legit_addr_hex",
        "patched_addr_hex",
    ]
    write_csv(out_path, rows, fieldnames)


def top_patched_addresses(rows: Sequence[dict], top_n: int, min_inst_delta: int) -> List[int]:
    patched_rows = [r for r in rows if r.get("classification") == "patched"]
    patched_rows = [r for r in patched_rows if parse_intish(r.get("inst_delta")) >= min_inst_delta]
    patched_rows.sort(
        key=lambda r: (
            parse_intish(r.get("inst_delta")),
            parse_intish(r.get("size_delta")),
            parse_intish(r.get("address")),
        ),
        reverse=True,
    )
    out: List[int] = []
    for r in patched_rows[:top_n]:
        out.append(parse_intish(r.get("address")))
    return out


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Generate sqlite DB diff reports for Chrysalis analysis")
    ap.add_argument("--db-dir", default="databases", help="Directory containing *.sqlite databases")
    ap.add_argument("--legit-db", default=None, help="Path to primary/legit sqlite DB")
    ap.add_argument("--patched-db", default=None, help="Path to secondary/patched sqlite DB")
    ap.add_argument("--out-dir", default="notebooks/tables/db_diff_reports", help="Output CSV directory")
    ap.add_argument("--top-asm", type=int, default=3, help="Emit side-by-side asm CSVs for top N patched functions")
    ap.add_argument("--min-asm-inst-delta", type=int, default=150, help="Minimum inst_delta for --top-asm selection")
    args = ap.parse_args(argv)

    root = find_repo_root(Path.cwd())
    db_dir = (root / args.db_dir).resolve() if not Path(args.db_dir).is_absolute() else Path(args.db_dir)
    out_dir = (root / args.out_dir).resolve() if not Path(args.out_dir).is_absolute() else Path(args.out_dir)

    legit_db, patched_db = choose_db_pair(db_dir, args.legit_db, args.patched_db)
    if not legit_db.exists() or not patched_db.exists():
        raise SystemExit(f"DB path missing: legit={legit_db} patched={patched_db}")

    print(f"[+] Legit DB:   {legit_db}")
    print(f"[+] Patched DB: {patched_db}")

    legit = build_digests(legit_db)
    patched = build_digests(patched_db)
    rows = merge_digests(legit, patched)

    fieldnames = [
        "address",
        "name_legit",
        "name_patched",
        "size_legit",
        "size_patched",
        "nodes_legit",
        "nodes_patched",
        "edges_legit",
        "edges_patched",
        "inst_count_legit",
        "inst_count_patched",
        "mnemonic_sha1_legit",
        "mnemonic_sha1_patched",
        "disasm_sha1_legit",
        "disasm_sha1_patched",
        "mnemonic_preview_legit",
        "mnemonic_preview_patched",
        "_merge",
        "classification",
        "inst_delta",
        "size_delta",
    ]

    write_csv(out_dir / "all_functions_classified.csv", rows, fieldnames)

    same_rows = [r for r in rows if r["classification"] == "same"]
    added_rows = [r for r in rows if r["classification"] == "added_in_patched"]
    removed_rows = [r for r in rows if r["classification"] == "removed_from_patched"]
    patched_rows = [r for r in rows if r["classification"] == "patched"]

    patched_rows.sort(
        key=lambda r: (parse_intish(r.get("inst_delta")), parse_intish(r.get("size_delta")), parse_intish(r.get("address"))),
        reverse=True,
    )

    write_csv(out_dir / "same_functions.csv", same_rows, fieldnames)
    write_csv(out_dir / "added_in_patched.csv", added_rows, fieldnames)
    write_csv(out_dir / "removed_from_patched.csv", removed_rows, fieldnames)
    write_csv(out_dir / "patched_functions.csv", patched_rows, fieldnames)

    preview_rows = [
        {
            "address": r["address"],
            "name_legit": r["name_legit"],
            "name_patched": r["name_patched"],
            "mnemonic_preview_legit": r["mnemonic_preview_legit"],
            "mnemonic_preview_patched": r["mnemonic_preview_patched"],
        }
        for r in patched_rows[:200]
    ]
    write_csv(
        out_dir / "patched_preview_mnemonics.csv",
        preview_rows,
        ["address", "name_legit", "name_patched", "mnemonic_preview_legit", "mnemonic_preview_patched"],
    )

    summary_rows = summarize(rows)
    write_csv(out_dir / "summary.csv", summary_rows, ["classification", "count"])

    print(f"[+] Wrote reports to {out_dir}")
    for p in sorted(out_dir.glob("*.csv")):
        print(f"    - {p.name}")

    if args.top_asm > 0:
        addrs = top_patched_addresses(rows, args.top_asm, args.min_asm_inst_delta)
        if addrs:
            with sqlite3.connect(str(legit_db)) as c_legit, sqlite3.connect(str(patched_db)) as c_patched:
                for addr in addrs:
                    f_legit = get_func_by_address(c_legit, addr)
                    f_patched = get_func_by_address(c_patched, addr)
                    if not f_legit or not f_patched:
                        continue
                    legit_insts = load_function_instructions(c_legit, f_legit["id"])
                    patched_insts = load_function_instructions(c_patched, f_patched["id"])
                    out_csv = out_dir / f"asm_side_by_side_0x{addr:08X}.csv"
                    write_asm_side_by_side(out_csv, legit_insts, patched_insts)
                    print(f"[+] Wrote {out_csv.name}")
        else:
            print("[+] No patched functions met --min-asm-inst-delta for ASM side-by-side export")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
