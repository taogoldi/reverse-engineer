#!/usr/bin/env python3
"""
Render side-by-side CFG diff HTML from two Diaphora/BinDiff-style sqlite databases.

Goal:
- Produce cleaner, interactive HTML flowgraphs than notebook quick plots.
- Focus on selected functions only (malicious/useful routines), not entire binary.
- Show primary (legit) vs secondary (patched) next to each other.

Default useful targets for this Chrysalis case:
- 0x004471B0, 0x00447032, 0x004479BD, 0x00447870, 0x00446EE5

Output:
- One HTML per function: notebooks/visuals/cfg_html/cfg_diff_0xXXXXXXXX.html
- Optional index: notebooks/visuals/cfg_html/index.html
"""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Sequence, Tuple


DEFAULT_USEFUL_VAS = [
    0x004471B0,
    0x00447032,
    0x004479BD,
    0x00447870,
    0x00446EE5,
]


@dataclass
class Instruction:
    address: int
    disasm: str
    mnemonic: str


@dataclass
class BasicBlock:
    bb_id: int
    bb_num: int
    address: int
    instructions: List[Instruction] = field(default_factory=list)

    def mnemonic_sig(self) -> str:
        parts = [ins.mnemonic.strip().lower() for ins in self.instructions if ins.mnemonic]
        blob = "\n".join(parts).encode("utf-8", errors="ignore")
        return hashlib.sha1(blob).hexdigest()

    def label(self, max_lines: int = 14) -> str:
        lines = [f"0x{self.address:08X}"]
        for ins in self.instructions[:max_lines]:
            lines.append(f"{ins.address:08X}: {ins.disasm}")
        if len(self.instructions) > max_lines:
            lines.append(f"... (+{len(self.instructions) - max_lines} lines)")
        return "\n".join(lines)


@dataclass
class FunctionGraph:
    func_id: int
    name: str
    address: int
    size: int
    nodes: Dict[int, BasicBlock]
    edges: List[Tuple[int, int]]


class DbReader:
    def __init__(self, db_path: Path):
        self.db_path = db_path

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(str(self.db_path))

    def get_function_by_va(self, va: int) -> FunctionGraph | None:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT id, COALESCE(name,''), COALESCE(address,0), COALESCE(size,0)
                FROM functions
                WHERE address = ?
                """,
                (int(va),),
            ).fetchone()
            if not row:
                return None

            func_id, name, addr, size = int(row[0]), str(row[1]), int(row[2]), int(row[3])

            bb_rows = conn.execute(
                """
                SELECT fb.basic_block_id, COALESCE(bb.num, fb.basic_block_id), COALESCE(bb.address, 0)
                FROM function_bblocks fb
                LEFT JOIN basic_blocks bb ON bb.id = fb.basic_block_id
                WHERE fb.function_id = ?
                ORDER BY 3, 2, 1
                """,
                (func_id,),
            ).fetchall()
            if not bb_rows:
                return FunctionGraph(func_id, name, addr, size, {}, [])

            bb_ids = [int(r[0]) for r in bb_rows]
            nodes: Dict[int, BasicBlock] = {
                int(bb_id): BasicBlock(bb_id=int(bb_id), bb_num=int(bb_num), address=int(bb_addr))
                for bb_id, bb_num, bb_addr in bb_rows
            }

            placeholders = ",".join(["?"] * len(bb_ids))
            edge_rows = conn.execute(
                f"""
                SELECT parent_id, child_id
                FROM bb_relations
                WHERE parent_id IN ({placeholders}) AND child_id IN ({placeholders})
                """,
                bb_ids + bb_ids,
            ).fetchall()
            edges = [(int(s), int(d)) for s, d in edge_rows]

            ins_rows = conn.execute(
                f"""
                SELECT bi.basic_block_id, COALESCE(i.address,0), COALESCE(i.disasm,''), COALESCE(i.mnemonic,'')
                FROM bb_instructions bi
                JOIN instructions i ON i.id = bi.instruction_id
                WHERE bi.basic_block_id IN ({placeholders})
                ORDER BY bi.basic_block_id, i.address
                """,
                bb_ids,
            ).fetchall()
            for bb_id, iaddr, disasm, mnemonic in ins_rows:
                nodes[int(bb_id)].instructions.append(
                    Instruction(address=int(iaddr), disasm=str(disasm), mnemonic=str(mnemonic))
                )

            return FunctionGraph(
                func_id=func_id,
                name=name,
                address=addr,
                size=size,
                nodes=nodes,
                edges=edges,
            )


def classify_block_colors(primary: FunctionGraph, secondary: FunctionGraph) -> Tuple[Dict[int, str], Dict[int, str]]:
    p_sigs = [bb.mnemonic_sig() for bb in primary.nodes.values()]
    s_sigs = [bb.mnemonic_sig() for bb in secondary.nodes.values()]
    s_set = set(s_sigs)
    p_set = set(p_sigs)

    p_colors: Dict[int, str] = {}
    s_colors: Dict[int, str] = {}

    for bb_id, bb in primary.nodes.items():
        sig = bb.mnemonic_sig()
        p_colors[bb_id] = "#bde5c8" if sig in s_set else "#f7d7d7"

    for bb_id, bb in secondary.nodes.items():
        sig = bb.mnemonic_sig()
        s_colors[bb_id] = "#bde5c8" if sig in p_set else "#f9e7b0"

    return p_colors, s_colors


def to_vis_payload(graph: FunctionGraph, colors: Dict[int, str], max_lines: int) -> dict:
    nodes = []
    for bb_id, bb in sorted(graph.nodes.items(), key=lambda kv: (kv[1].address, kv[1].bb_num, kv[0])):
        nodes.append(
            {
                "id": int(bb_id),
                "label": bb.label(max_lines=max_lines),
                "title": html.escape(bb.label(max_lines=max_lines)).replace("\n", "<br>"),
                "shape": "box",
                "font": {"face": "Consolas, Menlo, monospace", "size": 13, "multi": True},
                "margin": 8,
                "color": {
                    "background": colors.get(bb_id, "#dce7f7"),
                    "border": "#4f4f4f",
                    "highlight": {"background": "#fff3c4", "border": "#202020"},
                },
                "borderWidth": 1,
                "shadow": True,
            }
        )

    edges = []
    for s, d in graph.edges:
        edges.append(
            {
                "from": int(s),
                "to": int(d),
                "arrows": "to",
                "color": {"color": "#666", "highlight": "#cc0000"},
                "smooth": {"enabled": True, "type": "cubicBezier", "roundness": 0.18},
            }
        )

    return {"nodes": nodes, "edges": edges}


def rank_levels(payload: dict) -> Dict[int, int]:
    indeg: Dict[int, int] = {}
    out: Dict[int, List[int]] = {}
    for n in payload.get("nodes", []):
        nid = int(n["id"])
        indeg[nid] = 0
        out[nid] = []

    for e in payload.get("edges", []):
        s = int(e["from"])
        d = int(e["to"])
        if d in indeg:
            indeg[d] += 1
        if s in out:
            out[s].append(d)

    q: List[int] = [nid for nid, d in indeg.items() if d == 0]
    level: Dict[int, int] = {nid: 0 for nid in q}
    if not q and payload.get("nodes"):
        nid = int(payload["nodes"][0]["id"])
        q = [nid]
        level[nid] = 0

    qi = 0
    while qi < len(q):
        u = q[qi]
        qi += 1
        lu = level.get(u, 0)
        for v in out.get(u, []):
            level[v] = max(level.get(v, -1), lu + 1)
            indeg[v] = indeg.get(v, 1) - 1
            if indeg[v] <= 0:
                q.append(v)

    for n in payload.get("nodes", []):
        level.setdefault(int(n["id"]), 0)
    return level


def render_static_svg(payload: dict, panel_title: str) -> str:
    levels = rank_levels(payload)

    lanes: Dict[int, List[int]] = {}
    for n in payload.get("nodes", []):
        nid = int(n["id"])
        lvl = int(levels.get(nid, 0))
        lanes.setdefault(lvl, []).append(nid)
    for k in lanes:
        lanes[k].sort()
    level_keys = sorted(lanes.keys())

    box_w = 470
    box_h = 190
    gap_x = 130
    gap_y = 65
    pad = 30

    pos: Dict[int, Tuple[int, int, int, int]] = {}
    max_col = 0
    max_row = 0
    for col in level_keys:
        rows = lanes[col]
        for row, nid in enumerate(rows):
            x = pad + col * (box_w + gap_x)
            y = pad + row * (box_h + gap_y)
            pos[nid] = (x, y, box_w, box_h)
            max_col = max(max_col, col)
            max_row = max(max_row, row)

    svg_w = 120 + (max_col + 1) * (box_w + gap_x)
    svg_h = 120 + (max_row + 1) * (box_h + gap_y)

    lines: List[str] = []
    lines.append(f"<svg xmlns='http://www.w3.org/2000/svg' width='{svg_w}' height='{svg_h}' viewBox='0 0 {svg_w} {svg_h}'>")
    lines.append("<defs>")
    lines.append("<marker id='arrow' viewBox='0 0 10 10' refX='8' refY='5' markerWidth='5' markerHeight='5' orient='auto-start-reverse'>")
    lines.append("<path d='M 0 0 L 10 5 L 0 10 z' fill='#666'/>")
    lines.append("</marker>")
    lines.append("</defs>")
    lines.append(f"<text x='20' y='20' font-family='Segoe UI,Arial,sans-serif' font-size='13' fill='#222'>{html.escape(panel_title)}</text>")

    for e in payload.get("edges", []):
        s = int(e["from"])
        d = int(e["to"])
        if s not in pos or d not in pos:
            continue
        sx, sy, sw, sh = pos[s]
        dx, dy, dw, dh = pos[d]
        x1 = sx + sw
        y1 = sy + sh // 2
        x2 = dx
        y2 = dy + dh // 2
        cx1 = x1 + 45
        cx2 = x2 - 45
        lines.append(
            f"<path d='M {x1} {y1} C {cx1} {y1}, {cx2} {y2}, {x2} {y2}' "
            "stroke='#666' stroke-width='1.25' fill='none' marker-end='url(#arrow)'/>"
        )

    node_map = {int(n["id"]): n for n in payload.get("nodes", [])}
    for nid, (x, y, w, h) in sorted(pos.items(), key=lambda kv: (kv[1][1], kv[1][0])):
        n = node_map[nid]
        bg = n.get("color", {}).get("background", "#dce7f7")
        lines.append(
            f"<rect x='{x}' y='{y}' width='{w}' height='{h}' rx='6' ry='6' "
            f"fill='{html.escape(bg)}' stroke='#4f4f4f' stroke-width='1'/>"
        )

        label_lines = str(n.get("label", "")).split("\n")[:12]
        for i, ln in enumerate(label_lines):
            tx = x + 8
            ty = y + 18 + i * 14
            fsz = "12" if i == 0 else "11"
            txt = html.escape(ln)
            lines.append(
                f"<text x='{tx}' y='{ty}' font-family='Consolas,Menlo,monospace' "
                f"font-size='{fsz}' fill='#111'>{txt}</text>"
            )

    lines.append("</svg>")
    return "".join(lines)


def build_html(
    primary: FunctionGraph,
    secondary: FunctionGraph,
    primary_payload: dict,
    secondary_payload: dict,
    primary_svg: str,
    secondary_svg: str,
) -> str:
    page_title = f"CFG Diff 0x{primary.address:08X}"

    return f"""<!doctype html>
<html lang=\"en\">
<head>
<meta charset=\"utf-8\" />
<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\" />
<title>{html.escape(page_title)}</title>
<style>
body {{ margin: 0; font-family: Segoe UI, Roboto, Helvetica, Arial, sans-serif; background: #eef0f3; color: #111; }}
.top {{ padding: 12px 16px; border-bottom: 1px solid #c8c8c8; background: #f7f7f7; }}
.top h1 {{ margin: 0 0 6px 0; font-size: 18px; }}
.top .meta {{ font-size: 13px; color: #333; }}
.wrap {{ display: grid; grid-template-columns: 1fr 1fr; gap: 8px; padding: 8px; height: calc(100vh - 95px); box-sizing: border-box; }}
.panel {{ background: #d9d9d9; border: 1px solid #b8b8b8; box-shadow: inset 0 0 0 1px #efefef; display: grid; grid-template-rows: auto 1fr; }}
.hdr {{ padding: 8px 10px; border-bottom: 1px solid #b8b8b8; background: linear-gradient(#f5f5f5, #dddddd); font-size: 14px; font-weight: 700; letter-spacing: 0.2px; }}
.graph {{ width: 100%; height: 100%; min-height: 420px; }}
.svg-wrap {{ width:100%; height:100%; overflow:auto; background:#d9d9d9; }}
.status {{ margin-top: 6px; font-size: 12px; color: #333; }}
.legend {{ display: inline-flex; gap: 14px; margin-left: 12px; font-weight: 500; font-size: 12px; }}
.dot {{ width: 10px; height: 10px; display: inline-block; border-radius: 2px; margin-right: 5px; border: 1px solid #555; vertical-align: -1px; }}
</style>
</head>
<body>
  <div class=\"top\">
    <h1>{html.escape(page_title)}</h1>
    <div class=\"meta\">
      primary: {html.escape(primary.name)} @ 0x{primary.address:08X} (size=0x{primary.size:X}) &nbsp;|&nbsp;
      secondary: {html.escape(secondary.name)} @ 0x{secondary.address:08X} (size=0x{secondary.size:X})
      <span class=\"legend\">
        <span><span class=\"dot\" style=\"background:#bde5c8\"></span>block exists both sides</span>
        <span><span class=\"dot\" style=\"background:#f7d7d7\"></span>changed/removed in secondary</span>
        <span><span class=\"dot\" style=\"background:#f9e7b0\"></span>added/changed in secondary</span>
      </span>
    </div>
    <div id=\"status\" class=\"status\"></div>
  </div>

  <div class=\"wrap\">
    <section class=\"panel\">
      <div class=\"hdr\">primary (legit)</div>
      <div id=\"g1\" class=\"graph svg-wrap\">{primary_svg}</div>
    </section>
    <section class=\"panel\">
      <div class=\"hdr\">secondary (patched)</div>
      <div id=\"g2\" class=\"graph svg-wrap\">{secondary_svg}</div>
    </section>
  </div>

<script>
const primaryData = {json.dumps(primary_payload)};
const secondaryData = {json.dumps(secondary_payload)};

(function init() {{
  const pCount = primaryData.nodes.length + " nodes / " + primaryData.edges.length + " edges";
  const sCount = secondaryData.nodes.length + " nodes / " + secondaryData.edges.length + " edges";
  const el = document.getElementById("status");
  if (el) el.textContent = "static SVG mode loaded. primary: " + pCount + ", secondary: " + sCount;
}})();
</script>
</body>
</html>
"""


def parse_addr_values(values: Sequence[str]) -> List[int]:
    out: List[int] = []
    for s in values:
        s = s.strip()
        if not s:
            continue
        out.append(int(s, 0))
    return out


def choose_addresses(args: argparse.Namespace) -> List[int]:
    if args.addr:
        return parse_addr_values(args.addr)

    if args.useful_defaults:
        return list(DEFAULT_USEFUL_VAS)

    if args.patched_csv and Path(args.patched_csv).exists():
        import csv

        rows = []
        with Path(args.patched_csv).open("r", encoding="utf-8", newline="") as f:
            r = csv.DictReader(f)
            for row in r:
                try:
                    addr = int(float(row.get("address", "0")))
                    inst_delta = float(row.get("inst_delta", "0"))
                except Exception:
                    continue
                if inst_delta >= args.min_inst_delta:
                    rows.append((inst_delta, addr))
        rows.sort(reverse=True)
        return [addr for _, addr in rows[: args.top]]

    raise SystemExit("No targets selected. Use --addr, --useful-defaults, or --patched-csv.")


def main(argv: Sequence[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Render side-by-side CFG diff HTML for selected function addresses")
    ap.add_argument("--primary-db", default="databases/BluetoothService.exe.sqlite", help="Primary/legit sqlite DB")
    ap.add_argument("--secondary-db", default="databases/main_module_patched.exe.sqlite", help="Secondary/patched sqlite DB")
    ap.add_argument("--addr", action="append", help="Function VA to render (repeatable), e.g. --addr 0x4471B0")
    ap.add_argument("--useful-defaults", action="store_true", help="Use built-in useful function VA list for this sample")
    ap.add_argument("--patched-csv", default="notebooks/tables/db_diff_reports/patched_functions.csv", help="Patched function CSV for top-N selection")
    ap.add_argument("--top", type=int, default=8, help="Top N functions from --patched-csv")
    ap.add_argument("--min-inst-delta", type=float, default=150.0, help="Minimum inst_delta for --patched-csv selection")
    ap.add_argument("--max-lines", type=int, default=12, help="Max assembly lines per basic-block label")
    ap.add_argument("--out-dir", default="notebooks/visuals/cfg_html", help="Output directory for HTML reports")
    args = ap.parse_args(argv)

    primary_db = Path(args.primary_db)
    secondary_db = Path(args.secondary_db)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    addrs = choose_addresses(args)

    p_reader = DbReader(primary_db)
    s_reader = DbReader(secondary_db)

    index_rows = []
    for va in addrs:
        p_func = p_reader.get_function_by_va(va)
        s_func = s_reader.get_function_by_va(va)

        if not p_func or not s_func:
            index_rows.append((va, "missing", "missing", "(not rendered)"))
            continue

        p_colors, s_colors = classify_block_colors(p_func, s_func)
        p_payload = to_vis_payload(p_func, p_colors, max_lines=args.max_lines)
        s_payload = to_vis_payload(s_func, s_colors, max_lines=args.max_lines)
        p_svg = render_static_svg(p_payload, "primary")
        s_svg = render_static_svg(s_payload, "secondary")

        fn = f"cfg_diff_0x{va:08X}.html"
        html_doc = build_html(p_func, s_func, p_payload, s_payload, p_svg, s_svg)
        (out_dir / fn).write_text(html_doc, encoding="utf-8")

        index_rows.append((va, p_func.name, s_func.name, fn))
        print(f"[+] wrote {out_dir / fn}")

    idx_lines = [
        "<!doctype html>",
        "<html><head><meta charset='utf-8'><title>CFG Diff Index</title>",
        "<style>body{font-family:Segoe UI,Arial,sans-serif;padding:18px;background:#f5f5f5} table{border-collapse:collapse;background:#fff} th,td{border:1px solid #ccc;padding:8px 10px} th{background:#eee}</style>",
        "</head><body>",
        "<h2>CFG Diff Reports</h2>",
        "<table><tr><th>Address</th><th>Primary name</th><th>Secondary name</th><th>Report</th></tr>",
    ]
    for va, pn, sn, report in index_rows:
        link = report if report.startswith("cfg_diff_") else ""
        rep = f"<a href='{html.escape(link)}'>{html.escape(link)}</a>" if link else html.escape(report)
        idx_lines.append(
            f"<tr><td>0x{va:08X}</td><td>{html.escape(str(pn))}</td><td>{html.escape(str(sn))}</td><td>{rep}</td></tr>"
        )
    idx_lines.append("</table></body></html>")
    (out_dir / "index.html").write_text("\n".join(idx_lines), encoding="utf-8")
    print(f"[+] wrote {out_dir / 'index.html'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
