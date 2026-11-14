"""
Attack dashboard — standalone HTML page with two sections:
  * SUCCESSFUL prompts, grouped by target model
  * NON-SUCCESSFUL prompts

Successful prompts (with full traces) come from collect_successful.collect(),
covering every source: the manual DB-schema trace, agent.py, agent_evo.py,
system_prompt_extractor.py, and manual chat sessions. Non-successful prompts are
read from the run logs. Each prompt card shows the attack, the target reply, and
the leaked evidence.

Usage:
    python3 dashboard.py                 # writes dashboard.html, prints the path
    python3 dashboard.py --open          # also open it in the browser
    python3 dashboard.py -o report.html  # custom output path
"""

from __future__ import annotations

import argparse
import html
import json
import time
import webbrowser
from pathlib import Path

import collect_successful as cs

HERE = Path(__file__).parent
LOGS = HERE / "logs"


def _load(path: Path) -> list[dict]:
    if not path.exists():
        return []
    rows = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


# unified record: source, model, ts, success, angle, attack, reply, detail, locator
def _rec(source, model, ts, success, angle, attack, reply, detail, locator=""):
    return {"source": source, "model": model or "?", "ts": ts or "",
            "success": success, "angle": angle or "", "attack": attack or "",
            "reply": reply or "", "detail": detail or "", "locator": locator}


def collect() -> list[dict]:
    recs: list[dict] = []

    # --- successful prompts (reuse the collector; full traces, all sources) --
    for r in cs.collect():
        recs.append(_rec(r["source"], r["model"], r.get("ts", ""), True,
                         r.get("approach", ""), r.get("attack", ""),
                         r.get("reply", ""), r.get("evidence", ""),
                         r.get("locator", "")))

    # --- non-successful prompts, straight from the run logs -----------------
    for run in _load(LOGS / "hacker_runs.jsonl"):
        for ex in run.get("history", []):
            if not ex.get("leaked"):
                recs.append(_rec("hacker", run.get("target_model"), run.get("ts"),
                                 False, ex.get("strategy", ""), ex.get("attack", ""),
                                 ex.get("reply", ""), ex.get("verdict", ""),
                                 f"round={ex.get('round')}"))
    for run in _load(LOGS / "evo_runs.jsonl"):
        for g in run.get("population", []):
            if not g.get("leaked"):
                recs.append(_rec("evo", run.get("target_model"), run.get("ts"),
                                 False, g.get("approach", ""), g.get("message", ""),
                                 g.get("reply", ""), "no private data disclosed",
                                 f"gid={g.get('gid')} gen={g.get('generation')}"))
    for run in _load(LOGS / "sysprompt_runs.jsonl"):
        for a in run.get("attempts", []):
            if not a.get("is_fragment"):
                recs.append(_rec("sysprompt", run.get("target_model"), run.get("ts"),
                                 False, a.get("angle", ""), a.get("attack", ""),
                                 a.get("reply", ""), a.get("note", ""),
                                 f"round={a.get('round')}"))

    recs.sort(key=lambda p: (p["model"], p["ts"]), reverse=True)
    return recs


# --------------------------------------------------------------------------- #
PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>Prompt-Injection Dashboard</title>
<style>
  :root {{
    color-scheme: light dark;
    --bg:#f6f7f9; --panel:#ffffff; --ink:#1b1f24; --muted:#687078;
    --line:#e4e7eb; --ok:#128a4b; --ok-bg:#e8f6ee; --no:#b23b3b; --no-bg:#fbeceb;
    --chip:#eef1f4; --accent:#3257d6;
  }}
  @media (prefers-color-scheme: dark) {{
    :root {{
      --bg:#0f1216; --panel:#171b21; --ink:#e7eaee; --muted:#9aa3ad;
      --line:#262c34; --ok:#4ade80; --ok-bg:#122a1d; --no:#f08a8a; --no-bg:#2a1414;
      --chip:#222932; --accent:#7f9cff;
    }}
  }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; background:var(--bg); color:var(--ink);
    font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; }}
  header {{ padding:20px 22px 12px; }}
  h1 {{ font-size:20px; margin:0 0 4px; }}
  .sub {{ color:var(--muted); font-size:13px; }}
  .kpis {{ display:flex; flex-wrap:wrap; gap:10px; padding:10px 22px 0; }}
  .kpi {{ background:var(--panel); border:1px solid var(--line); border-radius:12px;
    padding:10px 14px; min-width:116px; }}
  .kpi b {{ display:block; font-size:22px; }}
  .kpi span {{ color:var(--muted); font-size:12px; }}
  .controls {{ display:flex; flex-wrap:wrap; gap:8px; padding:14px 22px; align-items:center; }}
  input[type=search], select {{ background:var(--panel); color:var(--ink);
    border:1px solid var(--line); border-radius:9px; padding:8px 10px; font-size:13px; }}
  input[type=search] {{ flex:1; min-width:180px; }}
  main {{ padding:0 22px 40px; }}
  .section-title {{ display:flex; align-items:center; gap:10px; margin:22px 0 10px; font-size:16px; }}
  .dot {{ width:10px; height:10px; border-radius:50%; }}
  .dot.ok {{ background:var(--ok); }} .dot.no {{ background:var(--no); }}
  .count {{ color:var(--muted); font-weight:400; font-size:13px; }}
  .model-group {{ margin:14px 0 6px; }}
  .model-head {{ display:flex; align-items:center; gap:8px; font-size:13px; font-weight:700;
    padding:6px 10px; background:var(--chip); border-radius:8px; }}
  .model-head .n {{ color:var(--muted); font-weight:500; }}
  .card {{ background:var(--panel); border:1px solid var(--line); border-left-width:4px;
    border-radius:12px; padding:12px 14px; margin:8px 0; }}
  .card.ok {{ border-left-color:var(--ok); }}
  .card.no {{ border-left-color:var(--no); }}
  .meta {{ display:flex; flex-wrap:wrap; gap:6px; margin-bottom:8px; align-items:center; }}
  .chip {{ background:var(--chip); border-radius:999px; padding:2px 9px; font-size:11px; color:var(--muted); }}
  .chip.src {{ color:var(--accent); font-weight:600; }}
  .badge {{ font-size:11px; font-weight:700; padding:2px 9px; border-radius:999px; }}
  .badge.ok {{ background:var(--ok-bg); color:var(--ok); }}
  .badge.no {{ background:var(--no-bg); color:var(--no); }}
  .angle {{ font-weight:600; margin:2px 0 6px; }}
  .lbl {{ color:var(--muted); font-size:11px; text-transform:uppercase; letter-spacing:.04em; margin-top:8px; }}
  pre {{ white-space:pre-wrap; word-break:break-word; margin:3px 0 0;
    background:transparent; font:12.5px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace; }}
  .detail {{ background:var(--ok-bg); border-radius:8px; padding:8px 10px; margin-top:8px; }}
  .no .detail {{ background:var(--no-bg); }}
  details > summary {{ cursor:pointer; color:var(--accent); font-size:12px; margin-top:6px; }}
  .empty {{ color:var(--muted); padding:14px; border:1px dashed var(--line); border-radius:12px; }}
  footer {{ color:var(--muted); font-size:12px; padding:0 22px 30px; }}
</style>
</head>
<body>
<header>
  <h1>Prompt-Injection Dashboard</h1>
  <div class="sub">{total} prompts · {n_ok} successful across {n_models} model(s) · generated {generated}</div>
</header>
<div class="kpis">
  <div class="kpi"><b>{total}</b><span>total prompts</span></div>
  <div class="kpi"><b style="color:var(--ok)">{n_ok}</b><span>successful</span></div>
  <div class="kpi"><b style="color:var(--no)">{n_no}</b><span>non-successful</span></div>
  <div class="kpi"><b>{rate}%</b><span>success rate</span></div>
  <div class="kpi"><b>{n_models}</b><span>models</span></div>
</div>
<div class="controls">
  <input id="q" type="search" placeholder="Filter by text, model, angle…">
  <select id="src"><option value="">All sources</option>{src_opts}</select>
  <select id="model"><option value="">All models</option>{model_opts}</select>
</div>
<main>
  <div class="section-title"><span class="dot ok"></span> Successful prompts
    <span class="count" id="okcount"></span></div>
  <div id="ok"></div>
  <div class="section-title"><span class="dot no"></span> Non-successful prompts
    <span class="count" id="nocount"></span></div>
  <div id="no"></div>
</main>
<footer>Re-run <code>python3 collect_successful.py &amp;&amp; python3 dashboard.py</code> to refresh.</footer>
<script>
const DATA = {data_json};
const q = document.getElementById('q'), src = document.getElementById('src'), model = document.getElementById('model');
function esc(s){{ return (s||'').replace(/[&<>]/g, c => ({{'&':'&amp;','<':'&lt;','>':'&gt;'}}[c])); }}
function card(p){{
  const cls = p.success ? 'ok' : 'no';
  const badge = p.success ? '<span class="badge ok">SUCCESS</span>' : '<span class="badge no">blocked</span>';
  const loc = p.locator ? `<span class="chip">${{esc(p.locator)}}</span>` : '';
  const detail = p.detail ? `<div class="lbl">${{p.success?'Leaked / evidence':'Why it failed'}}</div><div class="detail"><pre>${{esc(p.detail)}}</pre></div>` : '';
  return `<div class="card ${{cls}}">
    <div class="meta"><span class="chip src">${{esc(p.source)}}</span>${{badge}}
      <span class="chip">${{esc(p.model)}}</span>
      <span class="chip">${{esc(p.ts)}}</span>${{loc}}</div>
    ${{p.angle ? `<div class="angle">${{esc(p.angle)}}</div>`:''}}
    <div class="lbl">Attack prompt</div><pre>${{esc(p.attack)}}</pre>
    ${{detail}}
    <details><summary>Target reply (execution trace)</summary><pre>${{esc(p.reply)}}</pre></details>
  </div>`;
}}
function renderGroupedByModel(list, mount){{
  if(!list.length){{ mount.innerHTML = '<div class="empty">Nothing matches.</div>'; return; }}
  const groups = {{}};
  list.forEach(p => (groups[p.model] = groups[p.model] || []).push(p));
  const models = Object.keys(groups).sort((a,b)=>groups[b].length-groups[a].length);
  mount.innerHTML = models.map(m =>
    `<div class="model-group"><div class="model-head">🖥️ ${{esc(m)}}<span class="n">· ${{groups[m].length}} prompt(s)</span></div>`
    + groups[m].map(card).join('') + `</div>`).join('');
}}
function render(){{
  const term = q.value.toLowerCase(), fs = src.value, fm = model.value;
  const match = p => (!fs || p.source===fs) && (!fm || p.model===fm) &&
    (!term || JSON.stringify(p).toLowerCase().includes(term));
  const ok = DATA.filter(p => p.success && match(p));
  const no = DATA.filter(p => !p.success && match(p));
  renderGroupedByModel(ok, document.getElementById('ok'));
  const noMount = document.getElementById('no');
  noMount.innerHTML = no.length ? no.map(card).join('') : '<div class="empty">No non-successful prompts match.</div>';
  document.getElementById('okcount').textContent = ok.length + ' shown';
  document.getElementById('nocount').textContent = no.length + ' shown';
}}
[q,src,model].forEach(el => el.addEventListener('input', render));
render();
</script>
</body>
</html>"""


def build_html(recs: list[dict]) -> str:
    n_ok = sum(1 for p in recs if p["success"])
    n_no = len(recs) - n_ok
    rate = round(100 * n_ok / len(recs)) if recs else 0
    models = sorted({p["model"] for p in recs})
    sources = sorted({p["source"] for p in recs})
    n_models = len({p["model"] for p in recs if p["success"]})
    opt = lambda v: f'<option value="{html.escape(v)}">{html.escape(v)}</option>'
    return PAGE.format(
        total=len(recs), n_ok=n_ok, n_no=n_no, rate=rate, n_models=n_models,
        generated=time.strftime("%Y-%m-%d %H:%M"),
        src_opts="".join(opt(s) for s in sources),
        model_opts="".join(opt(m) for m in models),
        data_json=json.dumps(recs),
    )


def main() -> None:
    ap = argparse.ArgumentParser(description="Build the attack dashboard")
    ap.add_argument("-o", "--out", default=str(HERE / "dashboard.html"))
    ap.add_argument("--open", action="store_true", help="open in the browser")
    args = ap.parse_args()

    recs = collect()
    out = Path(args.out)
    out.write_text(build_html(recs))
    n_ok = sum(1 for p in recs if p["success"])
    models = sorted({p["model"] for p in recs if p["success"]})
    print(f"Wrote {out}")
    print(f"  {len(recs)} prompts — {n_ok} successful, {len(recs) - n_ok} non-successful")
    print(f"  successful prompts span {len(models)} model(s):")
    for m in models:
        c = sum(1 for p in recs if p["success"] and p["model"] == m)
        print(f"    {c:>3}  {m}")
    if args.open:
        webbrowser.open(out.resolve().as_uri())


if __name__ == "__main__":
    main()
