"""Self-contained HTML report for one agent run: question, verdict, attack path, evidence graph, every step with its Cypher, actions."""
from __future__ import annotations
import json, html, pathlib, datetime

ROOT = pathlib.Path(__file__).resolve().parent.parent
VENDOR = ROOT / "web" / "vendor"


def render(run: dict) -> str:
    cyjs = (VENDOR / "cytoscape.min.js").read_text()
    marked = (VENDOR / "marked.min.js").read_text()
    res = run["result"]
    tools = [{**e, "preview": (e.get("preview") or "")[:1500]} for e in run["events"] if e["type"] == "tool_result"]
    actions = [s for s in res["trace"] if s["type"] == "action"]
    data = json.dumps({"prompt": run["prompt"], "answer": res["answer"], "graph": res["graph"], "tools": tools, "trace": res["trace"], "usage": res["usage"],
                       "started": run["started"], "seconds": run["seconds"], "repo": run["graph_name"], "actions": actions, "run_id": run["run_id"], "tools_via": res.get("tools_via", "")}, default=str)
    started = datetime.datetime.fromtimestamp(run["started"]).strftime("%d %b %Y, %H:%M:%S")
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Blast Radius report · {html.escape(run['run_id'])}</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
:root{{--bg:#0b0f17;--panel:#111827;--panel2:#0f172a;--line:#1f2937;--text:#e5e7eb;--muted:#8b95a7;--accent:#f97316;--ok:#22c55e;--bad:#ef4444;--fn:#60a5fa;--pkg:#fb923c;--ep:#34d399;--au:#c084fc;--dec:#2dd4bf}}
*{{box-sizing:border-box}}body{{margin:0;background:radial-gradient(1200px 600px at 70% -10%,#15213a 0%,var(--bg) 60%);color:var(--text);font:15px/1.55 ui-sans-serif,-apple-system,"Segoe UI",Roboto,sans-serif}}
.wrap{{max-width:1100px;margin:0 auto;padding:36px 28px 80px}}
h1{{font-size:30px;margin:0;display:flex;align-items:center;gap:10px}}h1 span{{color:var(--accent)}}h1 small{{color:var(--muted);font-size:14px;font-weight:400;margin-left:8px}}
.meta{{color:var(--muted);font-size:13px;margin:6px 0 24px;display:flex;gap:18px;flex-wrap:wrap}}
h2{{font-size:13px;text-transform:uppercase;letter-spacing:.14em;color:var(--muted);margin:38px 0 12px;padding-bottom:8px;border-bottom:1px solid var(--line)}}
.card{{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:18px 20px}}
.q{{font-size:17px;color:#fff;border-left:4px solid var(--accent);padding:10px 16px;background:#1a1409;border-radius:0 12px 12px 0}}
.kpis{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin:18px 0}}.kpi{{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:12px 14px}}.kpi b{{display:block;font-size:24px;color:#fff;font-weight:600}}.kpi span{{color:var(--muted);font-size:12px}}
.verdict{{display:inline-block;font-weight:800;font-size:12px;letter-spacing:.14em;padding:5px 13px;border-radius:999px;margin-bottom:12px}}.EXPLOITABLE{{background:#3b1111;color:#fca5a5}}.NOT_REACHABLE{{background:#0f2a1a;color:#86efac}}.NEEDS_REVIEW{{background:#3a2a0a;color:#fcd34d}}
.answer .attn{{border-left:3px solid #ef4444;background:rgba(239,68,68,.10);padding:4px 8px;margin:4px 0;border-radius:4px;color:#fecaca}}.answer tr.attn td{{background:rgba(239,68,68,.12);color:#fecaca}}.answer h1,.answer h2,.answer h3{{font-size:13px;text-transform:uppercase;letter-spacing:.1em;color:var(--muted);margin:16px 0 6px;border:0;padding:0}}.answer table{{border-collapse:collapse;width:100%;font-size:13.5px;margin:8px 0}}.answer td,.answer th{{border:1px solid var(--line);padding:6px 9px;text-align:left;vertical-align:top}}.answer th{{background:var(--panel2);color:var(--muted)}}
.answer code{{background:#1a2333;padding:1px 5px;border-radius:4px;font-size:13px;font-family:ui-monospace,Menlo,monospace}}.answer pre{{background:var(--panel2);padding:10px;border-radius:8px;overflow:auto}}
.chain{{display:flex;flex-wrap:wrap;align-items:center;gap:8px}}.hop{{padding:7px 12px;border-radius:999px;font-size:13px;border:1px solid var(--line);background:var(--panel2);animation:pop .5s ease both}}.hop small{{display:block;color:var(--muted);font-size:11px}}.arr{{color:var(--muted)}}
.hop.Entrypoint{{border-color:var(--ep);color:#d1fae5}}.hop.Function{{border-color:var(--fn)}}.hop.Package{{border-color:var(--pkg);color:#fed7aa;font-weight:600}}.hop.Vulnerability{{border-color:var(--bad);color:#fca5a5}}
@keyframes pop{{from{{opacity:0;transform:scale(.8)}}to{{opacity:1;transform:none}}}}
#cy{{height:520px;border:1px solid var(--line);border-radius:14px;background:var(--panel2)}}.legend{{display:flex;gap:14px;font-size:12px;color:var(--muted);margin-top:8px;flex-wrap:wrap}}.legend i{{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:5px}}
.step{{display:flex;gap:14px;padding:14px 0;border-bottom:1px solid var(--line)}}.step:last-child{{border:0}}.num{{width:28px;height:28px;border-radius:50%;background:#163a2a;color:var(--ok);display:flex;align-items:center;justify-content:center;font-weight:700;flex:none;font-size:13px}}.step.act .num{{background:#3a2410;color:var(--accent)}}
.step .t{{font-weight:600}}.step .s{{color:var(--muted);font-size:13.5px}}.step .ms{{margin-left:auto;color:var(--muted);font-size:12px;white-space:nowrap}}
.cy{{margin-top:8px;font-family:ui-monospace,Menlo,monospace;font-size:11.5px;color:#9fb3c8;background:var(--panel2);border:1px solid var(--line);border-radius:8px;padding:8px 10px;white-space:pre-wrap;word-break:break-word}}.cy b{{color:var(--muted);font-weight:400}}
.diff{{font-family:ui-monospace,Menlo,monospace;font-size:12px;white-space:pre;background:#0a0f1a;border:1px solid var(--line);border-radius:8px;padding:10px;overflow:auto;margin-top:8px}}.add{{color:#86efac;display:block}}.del{{color:#fca5a5;display:block}}.hunk{{color:var(--muted);display:block}}
.foot{{color:var(--muted);font-size:12px;margin-top:40px}}
@media print{{body{{background:#fff;color:#111}}.card,.kpi,.hop,.cy,.diff{{background:#f6f7f9;border-color:#ddd;color:#111}}#cy{{display:none}}}}
</style></head><body><div class="wrap">
<h1><span style="width:14px;height:14px;border-radius:50%;border:3px solid var(--accent);display:inline-block"></span>Blast <span>Radius</span><small>triage report</small></h1>
<div class="meta"><span>{started}</span><span>repo: {html.escape(run['graph_name'])}</span><span>run {html.escape(run['run_id'])}</span></div>
<div class="q" id="q"></div>
<div class="kpis" id="kpis"></div>
<h2>Verdict and findings</h2><div class="card answer" id="answer"></div>
<h2>Shortest attack path</h2><div class="card"><div class="chain" id="chain"></div></div>
<h2>Evidence graph · everything the agent touched</h2><div id="cy"></div>
<div class="legend"><span><i style="background:var(--bad)"></i>Vulnerability</span><span><i style="background:var(--pkg)"></i>Package</span><span><i style="background:var(--fn)"></i>Function</span><span><i style="background:var(--ep)"></i>Endpoint</span><span><i style="background:var(--au)"></i>Author</span><span><i style="background:var(--dec)"></i>Decision</span><span style="margin-left:auto">highlighted = shortest attack path · dashed = name-matched call</span></div>
<h2>How it got there · every step and query</h2><div class="card" id="steps"></div>
<h2>Actions taken</h2><div class="card" id="actions"></div>
<div class="foot">Generated by Blast Radius. Graph: FalkorDB. Every endpoint, owner and version above came from a graph query shown in the steps.</div>
</div>
<script>{cyjs}</script><script>{marked}</script>
<script>
const D = {data};
const esc = s => String(s ?? '').replace(/[&<>]/g, c => ({{'&':'&amp;','<':'&lt;','>':'&gt;'}}[c]));
document.getElementById('q').textContent = D.prompt;
const nq = D.trace.filter(s => s.type === 'cypher').length, nact = D.actions.length;
document.getElementById('kpis').innerHTML = [[D.tools.length,'tool calls' + (D.tools_via === 'mcp' ? ' via MCP' : '')],[nq,'graph queries'],[nact,'actions taken'],[D.seconds + ' s','wall time'],[D.usage.input.toLocaleString(),'tokens in'],[D.usage.output.toLocaleString(),'tokens out']].map(([v,l]) => `<div class="kpi"><b>${{v}}</b><span>${{l}}</span></div>`).join('');
const m = D.answer.match(/\\*\\*Verdict:\\*\\*\\s*(EXPLOITABLE|NOT REACHABLE|NEEDS REVIEW)/i);
document.getElementById('answer').innerHTML = (m ? `<span class="verdict ${{m[1].toUpperCase().replace(' ','_')}}">${{m[1].toUpperCase()}}</span>` : '') + marked.parse(D.answer);
document.querySelectorAll('#answer li, #answer p').forEach(el => {{ if (/^\\s*(🔴|⚠️|⚠)/.test(el.textContent)) el.classList.add('attn'); }}); document.querySelectorAll('#answer tr').forEach(tr => {{ if (/(🔴|⚠️|⚠)/.test(tr.textContent)) tr.classList.add('attn'); }});
const COLORS = {{Vulnerability:'#ef4444',Package:'#fb923c',Function:'#60a5fa',Entrypoint:'#34d399',Author:'#c084fc',Decision:'#2dd4bf',File:'#94a3b8'}};
const cy = cytoscape({{container: document.getElementById('cy'), elements: {{nodes: D.graph.nodes.map(n => ({{data: n}})), edges: D.graph.edges.filter(e => D.graph.nodes.some(n => n.id === e.source) && D.graph.nodes.some(n => n.id === e.target)).map(e => ({{data: {{id: e.source + '|' + e.type + '|' + e.target, ...e}}}}))}},
  style: [{{selector:'node',style:{{'background-color': e => COLORS[e.data('label')] || '#94a3b8', label:'data(name)', color:'#cbd5e1','font-size':9,'text-valign':'bottom','text-margin-y':3,width:18,height:18,'text-wrap':'ellipsis','text-max-width':120}}}},
    {{selector:'node[label="Package"]',style:{{shape:'hexagon',width:32,height:32,'font-size':11,color:'#fed7aa'}}}},{{selector:'node[label="Entrypoint"]',style:{{shape:'round-rectangle',width:28,height:16,color:'#d1fae5'}}}},{{selector:'node[attn="public"]',style:{{'background-color':'#ef4444','border-width':3,'border-color':'#fecaca',color:'#fecaca','font-size':10,'font-weight':700}}}},{{selector:'node[attn="unknown"]',style:{{'background-color':'#f59e0b','border-width':3,'border-color':'#fde68a',color:'#fde68a','font-size':10,'font-weight':700}}}},{{selector:'node[label="Vulnerability"]',style:{{shape:'diamond','font-size':7.5}}}},{{selector:'node[label="Decision"]',style:{{shape:'tag','font-size':7.5}}}},
    {{selector:'edge',style:{{width:1.2,'line-color':'#334155','target-arrow-color':'#334155','target-arrow-shape':'triangle','arrow-scale':.7,'curve-style':'bezier'}}}},{{selector:'edge[type="CALLS"], edge[type="EXPOSES"]',style:{{'line-color':'#3b82f6','target-arrow-color':'#3b82f6'}}}},{{selector:'edge[type="USES"], edge[type="DEPENDS_ON"]',style:{{'line-color':'#f97316','target-arrow-color':'#f97316'}}}},{{selector:'edge[type="OWNS"]',style:{{'line-color':'#7c3aed','target-arrow-color':'#7c3aed','line-style':'dotted'}}}},{{selector:'edge[confidence="medium"]',style:{{'line-style':'dashed'}}}},
    {{selector:'.dim',style:{{opacity:.18}}}},{{selector:'node.hot',style:{{'border-width':4,'border-color':'#fff','font-size':11,color:'#fff','z-index':9}}}},{{selector:'edge.hot',style:{{width:4,'line-color':'#fb923c','target-arrow-color':'#fb923c','z-index':9}}}}],
  layout: {{name:'cose', animate:false, nodeRepulsion:12000, idealEdgeLength:80, padding:30}}, wheelSensitivity:.25}});
if (cy.nodes().length > 70) cy.nodes('[label="Function"], [label="Vulnerability"]').style('label', '');
(function path() {{
  const eps = cy.nodes('[label="Entrypoint"]'), targets = cy.nodes('[label="Package"]'); let best = null;
  eps.forEach(ep => {{ const d = cy.elements().dijkstra({{root: ep, directed: false}}); targets.forEach(t => {{ const dist = d.distanceTo(t); if (isFinite(dist) && (!best || dist < best.dist)) best = {{dist, path: d.pathTo(t)}}; }}); }});
  const chain = document.getElementById('chain');
  if (!best) {{ chain.innerHTML = '<span style="color:var(--muted)">No endpoint-to-package path in this run (question did not require reachability).</span>'; return; }}
  const vulns = best.path.nodes().last().connectedEdges().connectedNodes('[label="Vulnerability"]'); const vuln = vulns.filter('[severity="CRITICAL"]').first().length ? vulns.filter('[severity="CRITICAL"]').first() : vulns.filter('[severity="HIGH"]').first().length ? vulns.filter('[severity="HIGH"]').first() : vulns.first();
  let seq = best.path; if (vuln.length) seq = seq.union(best.path.nodes().last().edgesWith(vuln)).union(vuln);
  cy.elements().addClass('dim'); seq.removeClass('dim').addClass('hot'); seq.nodes().style('label', e => e.data('name'));
  const nodes = seq.nodes().toArray(); const edges = seq.edges();
  chain.innerHTML = nodes.map((n, i) => {{ const d = n.data(); const e = i ? edges.filter(x => (x.source().id() === n.id() || x.target().id() === n.id()) && (x.source().id() === nodes[i-1].id() || x.target().id() === nodes[i-1].id())).first() : null;
    const sub = d.label === 'Entrypoint' ? 'attacker-facing endpoint' : d.label === 'Package' ? ('vulnerable library' + (d.version ? ' ' + d.version : '')) : d.label === 'Vulnerability' ? (d.severity + (d.summary ? ' · ' + d.summary : '')) : (d.file || 'function') + (e && e.data('confidence') === 'medium' ? ' · name-matched call' : '');
    return (i ? `<span class="arr">→</span>` : '') + `<span class="hop ${{d.label}}" style="animation-delay:${{i*120}}ms">${{esc(d.name || d.id)}}<small>${{esc(sub)}}</small></span>`; }}).join('');
}})();
const ACT = new Set(['apply_dependency_fix','open_pull_request','record_triage_decision']);
document.getElementById('steps').innerHTML = D.tools.map((t, i) => `<div class="step ${{ACT.has(t.name) ? 'act' : ''}}"><div class="num">${{i+1}}</div><div style="min-width:0;flex:1"><div class="t">${{esc(t.title || t.name)}}</div><div class="s">${{esc(t.summary || '')}}</div>${{t.input !== undefined ? `<div class="cy"><b>→ ${{D.tools_via === 'mcp' ? 'mcp.call_tool' : 'call'}}("${{esc(t.name)}}", ${{esc(JSON.stringify(t.input))}})</b>\n← ${{esc((t.preview || '').slice(0, 600))}}${{(t.result_chars || 0) > 600 ? ' …' : ''}}</div>` : ''}}${{(t.steps||[]).filter(s => s.query).map(s => `<div class="cy"><b>${{esc(s.label)}} · ${{s.rows}} rows · ${{s.ms}} ms</b>\\n${{esc(s.query)}}</div>`).join('')}}${{t.diff ? `<div class="diff">${{t.diff.split('\\n').filter(l => !l.startsWith('diff --git') && !l.startsWith('index ')).map(l => `<span class="${{l.startsWith('+')?'add':l.startsWith('-')?'del':l.startsWith('@@')?'hunk':''}}">${{esc(l)}}</span>`).join('')}}</div>` : ''}}</div><div class="ms">${{t.ms}} ms</div></div>`).join('');
document.getElementById('actions').innerHTML = D.actions.length ? '<ul style="margin:0;padding-left:18px">' + D.actions.map(a => `<li>${{esc(a.label)}}</li>`).join('') + '</ul>' : '<span style="color:var(--muted)">No write actions in this run: the question only asked for an assessment.</span>';
</script></body></html>"""
