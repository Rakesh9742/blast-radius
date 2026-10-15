"""Full-screen 'story mode' replay of one run: question -> investigation step by step (graph grows) -> attack path hop by hop -> verdict."""
from __future__ import annotations
import json, html, pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
VENDOR = ROOT / "web" / "vendor"


def render(run: dict) -> str:
    cyjs = (VENDOR / "cytoscape.min.js").read_text()
    marked = (VENDOR / "marked.min.js").read_text()
    res = run["result"]
    tools = [{k: e.get(k) for k in ("name", "title", "summary", "phase", "steps", "graph", "diff", "ms", "error")} for e in run["events"] if e["type"] == "tool_result"]
    data = json.dumps({"prompt": run["prompt"], "answer": res["answer"], "tools": tools, "graph": res["graph"], "usage": res["usage"], "seconds": run["seconds"],
                       "actions": [s for s in res["trace"] if s["type"] == "action"], "run_id": run["run_id"], "repo": run["graph_name"]}, default=str)
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Blast Radius · replay {html.escape(run['run_id'])}</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
:root{{--bg:#070a12;--panel:#111827;--line:#1f2937;--text:#e5e7eb;--muted:#8b95a7;--accent:#f97316;--ok:#22c55e;--bad:#ef4444;--fn:#60a5fa;--pkg:#fb923c;--ep:#34d399;--au:#c084fc;--dec:#2dd4bf}}
*{{box-sizing:border-box}}html,body{{height:100%;margin:0}}body{{background:radial-gradient(1400px 900px at 50% 40%,#131c30 0%,var(--bg) 65%);color:var(--text);font:15px/1.5 ui-sans-serif,-apple-system,"Segoe UI",Roboto,sans-serif;overflow:hidden}}
#cy{{position:absolute;inset:0}}
.top{{position:absolute;top:0;left:0;right:0;padding:14px 22px;display:flex;align-items:center;gap:16px;z-index:5;background:linear-gradient(180deg,rgba(7,10,18,.9),transparent)}}
.brand{{font-weight:700;font-size:15px;display:flex;align-items:center;gap:8px}}.brand span{{color:var(--accent)}}.brand small{{color:var(--muted);font-weight:400;margin-left:6px}}
.chapters{{margin-left:auto;display:flex;gap:6px}}.ch{{font-size:10.5px;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);padding:5px 10px;border-radius:999px;background:rgba(26,35,51,.7);border:1px solid transparent;transition:all .35s}}.ch.on{{color:#111;background:var(--accent);font-weight:700;box-shadow:0 0 18px rgba(249,115,22,.45)}}.ch.done{{color:var(--text);border-color:#2a3d57}}
.prog{{position:absolute;top:0;left:0;height:3px;background:var(--accent);width:0;transition:width .5s ease;z-index:6;box-shadow:0 0 10px var(--accent)}}
.card{{position:absolute;left:28px;bottom:28px;width:min(560px,44vw);background:rgba(11,15,23,.93);border:1px solid #2a3647;border-radius:18px;padding:20px 24px;z-index:5;backdrop-filter:blur(10px);box-shadow:0 20px 60px rgba(0,0,0,.6),0 0 0 1px rgba(249,115,22,.12);animation:up .45s cubic-bezier(.2,.9,.3,1) both}}
@keyframes up{{from{{opacity:0;transform:translateY(16px)}}to{{opacity:1;transform:none}}}}
.card .k{{font-size:10.5px;letter-spacing:.16em;text-transform:uppercase;color:var(--accent);font-weight:700;display:flex;justify-content:space-between}}.card .k span:last-child{{color:var(--muted);font-weight:500}}
.card h2{{font-size:22px;margin:6px 0 4px;color:#fff;line-height:1.25;animation:up .5s .05s both}}.card p{{margin:4px 0;color:#cbd5e1;font-size:14.5px;animation:up .5s .12s both}}.card .q{{font-family:ui-monospace,Menlo,monospace;font-size:11px;color:#9fb3c8;background:#0a0f1a;border:1px solid var(--line);border-radius:8px;padding:8px 10px;margin-top:10px;white-space:pre-wrap;word-break:break-word;max-height:110px;overflow:auto;animation:up .5s .2s both}}
.verdict{{display:inline-block;font-weight:800;font-size:12px;letter-spacing:.14em;padding:5px 13px;border-radius:999px;margin-bottom:8px}}.EXPLOITABLE{{background:#3b1111;color:#fca5a5;box-shadow:0 0 18px rgba(239,68,68,.4)}}.NOT_REACHABLE{{background:#0f2a1a;color:#86efac}}.NEEDS_REVIEW{{background:#3a2a0a;color:#fcd34d}}
.card ul{{margin:6px 0 0;padding-left:18px;font-size:14px;color:#cbd5e1}}.card li{{margin:3px 0}}
.ctl{{position:absolute;right:28px;bottom:28px;display:flex;gap:8px;z-index:5;align-items:center}}.ctl button{{background:rgba(26,35,51,.85);color:var(--text);border:1px solid #2a3d57;border-radius:10px;padding:9px 14px;font:inherit;font-weight:600;cursor:pointer;transition:all .18s;backdrop-filter:blur(6px)}}.ctl button:hover{{border-color:var(--accent);transform:translateY(-1px)}}.ctl .play{{background:linear-gradient(180deg,#fb923c,#f97316);color:#111;border:0;padding:9px 18px}}
.ctl .hint{{color:var(--muted);font-size:11.5px;margin-right:6px}}
.title{{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center;z-index:4;padding:40px;background:radial-gradient(900px 500px at 50% 50%,rgba(249,115,22,.08),transparent 70%);transition:opacity .6s}}
.title h1{{font-size:46px;margin:0 0 8px;letter-spacing:-.5px}}.title h1 span{{color:var(--accent)}}.title .sub{{color:var(--muted);font-size:16px;margin-bottom:28px}}.title .qq{{max-width:820px;font-size:22px;line-height:1.4;color:#fff;border-left:4px solid var(--accent);padding:12px 22px;background:rgba(26,20,9,.7);border-radius:0 14px 14px 0;text-align:left;animation:up .6s .2s both}}
.title .go{{margin-top:34px;color:var(--muted);font-size:13px;animation:blink 1.6s infinite}}@keyframes blink{{50%{{opacity:.35}}}}
.hide{{opacity:0;pointer-events:none}}
.cnt{{position:absolute;left:28px;top:64px;z-index:5;font-size:12px;color:var(--muted);background:rgba(11,15,23,.7);padding:5px 10px;border-radius:999px;border:1px solid var(--line)}}
</style></head><body>
<div class="prog" id="prog"></div>
<div class="top"><div class="brand"><span style="width:12px;height:12px;border-radius:50%;border:3px solid var(--accent);display:inline-block"></span>Blast <span>Radius</span><small>replay · {html.escape(run['graph_name'])}</small></div>
<div class="chapters" id="chapters"><span class="ch" data-c="0">Question</span><span class="ch" data-c="1">Investigation</span><span class="ch" data-c="2">Attack path</span><span class="ch" data-c="3">Verdict</span></div></div>
<div id="cy"></div>
<div class="cnt" id="cnt"></div>
<div class="title" id="title"><h1>Blast <span>Radius</span></h1><div class="sub">graph-native security triage · what the agent did, step by step</div><div class="qq" id="qq"></div><div class="go">press play or → to begin</div></div>
<div class="card hide" id="card"></div>
<div class="ctl"><span class="hint">← → step · space play/pause · R restart</span><button id="prev">←</button><button class="play" id="play">▶ Play</button><button id="next">→</button><button id="speed">1×</button><button id="fs">⛶</button><button id="back" style="display:none">✕ Back to console (Esc)</button></div>
<script>{cyjs}</script><script>{marked}</script>
<script>
const D = {data};
const esc = s => String(s ?? '').replace(/[&<>]/g, c => ({{'&':'&amp;','<':'&lt;','>':'&gt;'}}[c]));
document.getElementById('qq').textContent = D.prompt;
const COLORS = {{Vulnerability:'#ef4444',Package:'#fb923c',Function:'#60a5fa',Entrypoint:'#34d399',Author:'#c084fc',Decision:'#2dd4bf',File:'#94a3b8'}};
const cy = cytoscape({{container: document.getElementById('cy'), wheelSensitivity:.25, style: [
  {{selector:'node',style:{{'background-color': e => COLORS[e.data('label')] || '#94a3b8', label:'data(name)', color:'#cbd5e1','font-size':10,'text-valign':'bottom','text-margin-y':4,width:22,height:22,'text-wrap':'ellipsis','text-max-width':140,'border-width':1,'border-color':'#070a12','transition-property':'border-width,border-color,width,height','transition-duration':'0.3s'}}}},
  {{selector:'node[label="Package"]',style:{{shape:'hexagon',width:40,height:40,'font-size':13,'font-weight':600,color:'#fed7aa'}}}},{{selector:'node[label="Entrypoint"]',style:{{shape:'round-rectangle',width:34,height:20,'font-size':11,color:'#d1fae5'}}}},{{selector:'node[label="Vulnerability"]',style:{{shape:'diamond','font-size':8.5}}}},{{selector:'node[label="Decision"]',style:{{shape:'tag','font-size':8.5}}}},{{selector:'node[label="Author"]',style:{{width:26,height:26,color:'#e9d5ff'}}}},
  {{selector:'edge',style:{{width:1.4,'line-color':'#334155','target-arrow-color':'#334155','target-arrow-shape':'triangle','arrow-scale':.8,'curve-style':'bezier','transition-property':'line-color,width','transition-duration':'0.4s'}}}},{{selector:'edge[type="CALLS"], edge[type="EXPOSES"]',style:{{'line-color':'#3b82f6','target-arrow-color':'#3b82f6',width:1.8}}}},{{selector:'edge[type="USES"], edge[type="DEPENDS_ON"]',style:{{'line-color':'#f97316','target-arrow-color':'#f97316'}}}},{{selector:'edge[type="OWNS"]',style:{{'line-color':'#7c3aed','target-arrow-color':'#7c3aed','line-style':'dotted'}}}},{{selector:'edge[confidence="medium"]',style:{{'line-style':'dashed'}}}},
  {{selector:'.fresh',style:{{'border-width':4,'border-color':'#f97316'}}}},{{selector:'edge.fresh',style:{{width:3.5,'line-color':'#fb923c','target-arrow-color':'#fb923c'}}}},
  {{selector:'.dim',style:{{opacity:.1}}}},{{selector:'node.hot',style:{{opacity:1,'border-width':6,'border-color':'#fff','font-size':13,color:'#fff','z-index':99,'text-background-color':'#070a12','text-background-opacity':.85,'text-background-padding':3}}}},{{selector:'edge.hot',style:{{opacity:1,width:5,'line-color':'#fb923c','target-arrow-color':'#fb923c','z-index':99}}}},
  {{selector:'node.quiet',style:{{label:''}}}} ]}});
function addGraph(frag) {{
  cy.elements().removeClass('fresh'); const added = [];
  (frag.nodes || []).forEach(n => {{ if (!cy.getElementById(n.id).length) added.push(cy.add({{group:'nodes', data: {{...n}}}})); }});
  (frag.edges || []).forEach(e => {{ const id = e.source + '|' + e.type + '|' + e.target; if (!cy.getElementById(id).length && cy.getElementById(e.source).length && cy.getElementById(e.target).length) added.push(cy.add({{group:'edges', data: {{id, ...e}}}})); }});
  added.forEach(el => {{ el.addClass('fresh'); el.style('opacity', 0); el.animate({{style:{{opacity:1}}}}, {{duration:600}}); }});
  cy.nodes('[label="Function"], [label="Vulnerability"]').toggleClass('quiet', cy.nodes().length > 70);
  cy.layout({{name:'cose', animate:'end', animationDuration:700, animationEasing:'ease-out', nodeRepulsion:14000, idealEdgeLength:95, padding:90, randomize:false}}).run();
  setTimeout(() => cy.animate({{fit:{{eles: cy.elements(), padding: 90}}, duration: 600}}), 750);
  return added.length;
}}
// ---- build scene list
const scenes = [];
scenes.push({{ch:0, kind:'title'}});
D.tools.forEach((t, i) => scenes.push({{ch:1, kind:'tool', t, i}}));
// attack path
let pathItems = [];
(function() {{
  const tmp = cytoscape({{headless:true, elements: {{nodes: D.graph.nodes.map(n => ({{data:n}})), edges: D.graph.edges.filter(e => D.graph.nodes.some(n => n.id === e.source) && D.graph.nodes.some(n => n.id === e.target)).map(e => ({{data:{{id:e.source+'|'+e.type+'|'+e.target, ...e}}}}))}}}});
  if (!tmp.nodes('[label="Vulnerability"]').length) return;   // frontend-only graph: no attack path to narrate
  const eps = tmp.nodes('[label="Entrypoint"]'), targets = tmp.nodes('[label="Package"]').filter(n => !String(n.id()).startsWith('area:')); let best = null;
  eps.forEach(ep => {{ const d = tmp.elements().dijkstra({{root: ep, directed:false}}); targets.forEach(t => {{ const dist = d.distanceTo(t); if (isFinite(dist) && (!best || dist < best.dist)) best = {{dist, path: d.pathTo(t)}}; }}); }});
  if (!best) return;
  const vulns = best.path.nodes().last().connectedEdges().connectedNodes('[label="Vulnerability"]');
  const vuln = vulns.filter('[severity="CRITICAL"]').first().length ? vulns.filter('[severity="CRITICAL"]').first() : vulns.filter('[severity="HIGH"]').first().length ? vulns.filter('[severity="HIGH"]').first() : vulns.first();
  let seq = best.path; if (vuln.length) seq = seq.union(best.path.nodes().last().edgesWith(vuln)).union(vuln);
  pathItems = seq.toArray().map(x => ({{id: x.id(), node: x.isNode(), data: x.data()}}));
}})();
const hops = pathItems.filter(x => x.node);
hops.forEach((h, i) => scenes.push({{ch:2, kind:'hop', i, total: hops.length}}));
// frontend-only graphs: tour the API areas and the flagged calls instead of an attack path
let surf = [];
if (!hops.length) {{
  const cnt = n => parseInt((String(n.name || '').match(/\\((\\d+)\\)/) || [0, 0])[1]) || 0;
  const areas = D.graph.nodes.filter(n => String(n.id).startsWith('area:')).sort((a, b) => cnt(b) - cnt(a)).slice(0, 5);
  const flagged = D.graph.nodes.filter(n => n.attn === 'public').concat(D.graph.nodes.filter(n => n.attn === 'unknown'));
  surf = areas.map(n => ({{id: n.id, kind: 'area', data: n}})).concat(flagged.map(n => ({{id: n.id, kind: n.attn, data: n}})));
  surf.forEach((x, i) => scenes.push({{ch:2, kind:'surf', i, total: surf.length}}));
  const chEl = document.querySelector('.ch[data-c="2"]'); if (chEl) chEl.textContent = 'API surface';
}}
scenes.push({{ch:3, kind:'verdict'}});

const POS = {{}};
cy.on('layoutstop', () => cy.nodes().forEach(n => POS[n.id()] = {{...n.position()}}));
function rebuild(g) {{
  cy.elements().remove(); let unknown = 0;
  cy.add(g.nodes.map(n => {{ const p = POS[n.id]; if (!p) unknown++; return {{group:'nodes', data:{{...n}}, position: p ? {{...p}} : {{x: 0, y: 0}}}}; }}));
  g.edges.forEach(e => {{ const id = e.source+'|'+e.type+'|'+e.target; if (cy.getElementById(e.source).length && cy.getElementById(e.target).length) cy.add({{group:'edges', data:{{id, ...e}}}}); }});
  return unknown;
}}
let cur = -1, playing = false, speed = 1, timer = null;
const card = document.getElementById('card'), titleEl = document.getElementById('title');
function showCard(html) {{ card.classList.remove('hide'); card.style.animation = 'none'; card.offsetHeight; card.style.animation = ''; card.innerHTML = html; }}
function setChapter(c) {{ document.querySelectorAll('.ch').forEach(x => {{ x.classList.toggle('on', +x.dataset.c === c); x.classList.toggle('done', +x.dataset.c < c); }}); }}
function render(i) {{
  const s = scenes[i]; setChapter(s.ch);
  document.getElementById('prog').style.width = (100 * (i + 1) / scenes.length) + '%';
  document.getElementById('cnt').textContent = `scene ${{i + 1}} of ${{scenes.length}}`;
  // rebuild graph state up to this scene
  const lastTool = scenes.slice(0, i + 1).filter(x => x.kind === 'tool').pop();
  const unknown = rebuild(lastTool ? (lastTool.t.graph || D.graph) : (s.kind === 'title' ? {{nodes:[], edges:[]}} : D.graph));
  if (unknown && s.kind !== 'tool') {{ cy.layout({{name:'cose', animate:false, nodeRepulsion:14000, idealEdgeLength:95, padding:90, randomize:true}}).run(); }}
  if (s.kind !== 'title') titleEl.classList.add('hide'); else titleEl.classList.remove('hide');
  if (s.kind === 'title') {{ card.classList.add('hide'); return 2600; }}
  if (s.kind === 'tool') {{
    const t = s.t; const prev = scenes.slice(0, i).filter(x => x.kind === 'tool').pop();
    const prevIds = new Set(prev ? (prev.t.graph.nodes.map(n => n.id)) : []);
    cy.nodes().forEach(n => {{ if (!prevIds.has(n.id())) n.addClass('fresh'); }});
    cy.nodes('[label="Function"], [label="Vulnerability"]').toggleClass('quiet', cy.nodes().length > 70); cy.nodes('.fresh').removeClass('quiet');
    if (unknown) cy.layout({{name:'cose', animate:'end', animationDuration:650, nodeRepulsion:14000, idealEdgeLength:95, padding:90, randomize:false}}).run();
    setTimeout(() => cy.animate({{fit:{{eles: cy.elements(), padding: 90}}, duration: 500}}), unknown ? 700 : 50);
    const q = (t.steps || []).filter(x => x.query)[0];
    showCard(`<div class="k"><span>step ${{s.i + 1}} of ${{D.tools.length}} · ${{esc(t.phase)}}</span><span>${{t.ms}} ms</span></div><h2>${{esc(t.title || t.name)}}</h2><p>${{esc(t.summary || '')}}</p>${{q ? `<div class="q">${{esc(q.label)}} · ${{q.rows}} rows · ${{q.ms}} ms\\n${{esc(q.query)}}</div>` : ''}}${{t.diff ? `<div class="q">${{esc(t.diff.split('\\n').filter(l => l.startsWith('+') || l.startsWith('-')).filter(l => !l.startsWith('+++') && !l.startsWith('---')).join('\\n'))}}</div>` : ''}}`);
    return 3400;
  }}
  if (s.kind === 'surf') {{
    const it = surf[s.i], el = cy.getElementById(it.id);
    cy.elements().addClass('dim').removeClass('hot');
    const hood = el.length ? el.closedNeighborhood() : cy.collection();
    hood.removeClass('dim quiet').addClass('hot');
    if (hood.length) cy.animate({{fit:{{eles: hood, padding: it.kind === 'area' ? 120 : 220}}, duration: 500}});
    let title, sub, tag;
    if (it.kind === 'area') {{ title = `API area ${{it.data.name}}`; sub = 'The frontend calls this part of the backend. Confirmed HTTP calls are shown around it.'; tag = 'mapping…'; }}
    else if (it.kind === 'public') {{ title = `🔴 ${{it.data.name}}`; sub = 'Callable without login. Needs a human check: is this meant to be public?'; tag = 'flagging…'; }}
    else {{ title = `⚠ ${{it.data.name}}`; sub = 'No auth status recorded and the path looks like it serves a file, certificate or export. Check it first.'; tag = 'flagging…'; }}
    showCard(`<div class="k"><span>api surface · step ${{s.i + 1}} of ${{s.total}}</span><span>${{s.i + 1 === s.total ? 'done' : tag}}</span></div><h2>${{esc(title)}}</h2><p>${{esc(sub)}}</p>`);
    return 2600;
  }}
  if (s.kind === 'hop') {{
    cy.elements().addClass('dim');
    const upto = []; let n = -1; for (const it of pathItems) {{ if (it.node) n++; if (n > s.i) break; upto.push(it); }}
    upto.forEach(it => {{ const el = cy.getElementById(it.id); el.removeClass('dim quiet').addClass('hot'); }});
    const seq = cy.collection(pathItems.map(it => cy.getElementById(it.id)));
    cy.animate({{fit:{{eles: seq, padding: 200}}, duration: 500}});
    const h = hops[s.i], d = h.data; const prevEdge = upto.length > 1 ? upto[upto.length - 2] : null; const medium = prevEdge && !prevEdge.node && prevEdge.data.confidence === 'medium';
    let title, sub;
    if (d.label === 'Entrypoint') {{ title = `Attacker sends ${{d.name}}`; sub = 'Public HTTP endpoint. This is where the request enters the system.'; }}
    else if (d.label === 'Function') {{ title = s.i === 1 ? `Handled by ${{d.name}}()` : `…which calls ${{d.name}}()`; sub = (d.file ? d.file + ' · ' : '') + (medium ? 'call matched by method name only · medium confidence' : 'call resolved statically · high confidence'); }}
    else if (d.label === 'Package') {{ title = `Reaches ${{d.name}}${{d.version ? ' ' + d.version : ''}}`; sub = 'The vulnerable library. Attacker-controlled data arrives here.'; }}
    else {{ title = `${{d.name}}${{d.severity ? ' · ' + d.severity : ''}}`; sub = (d.summary || 'Published advisory affecting the installed version.') + (d.fixed ? ` · fixed in ${{d.fixed}}` : ''); }}
    showCard(`<div class="k"><span>attack path · hop ${{s.i + 1}} of ${{s.total}}</span><span>${{s.i + 1 === s.total ? 'reached' : 'tracing…'}}</span></div><h2>${{esc(title)}}</h2><p>${{esc(sub)}}</p>`);
    return 2600;
  }}
  if (s.kind === 'verdict') {{
    cy.elements().removeClass('dim hot'); cy.animate({{fit:{{eles: cy.elements(), padding: 90}}, duration: 600}});
    const m = D.answer.match(/\\*\\*Verdict:\\*\\*\\s*(EXPLOITABLE|NOT REACHABLE|NEEDS REVIEW)/i);
    const first = (D.answer.split('\\n').find(l => l.includes('**Verdict:**')) || '').replace(/\\*\\*Verdict:\\*\\*\\s*(EXPLOITABLE|NOT REACHABLE|NEEDS REVIEW)\\.?/i, '').replace(/\\*\\*/g, '').trim();
    const acts = D.actions.map(a => `<li>${{esc(a.label)}}</li>`).join('');
    showCard(`<div class="k"><span>verdict</span><span>${{D.tools.length}} steps · ${{D.seconds}} s</span></div>${{m ? `<span class="verdict ${{m[1].toUpperCase().replace(' ','_')}}">${{m[1].toUpperCase()}}</span>` : ''}}<h2 style="font-size:17px">${{esc(first.slice(0, 260))}}</h2>${{acts ? `<p style="margin-top:10px;color:var(--muted);font-size:12px;letter-spacing:.1em;text-transform:uppercase">actions taken</p><ul>${{acts}}</ul>` : ''}}<p style="margin-top:12px"><a href="/api/report/${{D.run_id}}" target="_blank" style="color:var(--accent)">Open the full report →</a></p>`);
    return 0;
  }}
}}
function go(i) {{ if (i < 0 || i >= scenes.length) return; cur = i; const d = render(i); clearTimeout(timer); if (playing && d) timer = setTimeout(() => go(cur + 1), d / speed); if (playing && !d) setPlaying(false); }}
function setPlaying(p) {{ playing = p; document.getElementById('play').textContent = p ? '❚❚ Pause' : '▶ Play'; if (p) go(cur < 0 ? 0 : cur); else clearTimeout(timer); }}
document.getElementById('play').onclick = () => setPlaying(!playing);
document.getElementById('next').onclick = () => {{ clearTimeout(timer); go(cur + 1); }};
document.getElementById('prev').onclick = () => {{ clearTimeout(timer); go(cur - 1); }};
document.getElementById('speed').onclick = e => {{ speed = speed === 1 ? 1.5 : speed === 1.5 ? 2 : 1; e.target.textContent = speed + '×'; }};
if (window.parent !== window) {{ const b = document.getElementById('back'); b.style.display = ''; b.onclick = () => window.parent.postMessage('close-story', '*'); }}
document.getElementById('fs').onclick = () => document.fullscreenElement ? document.exitFullscreen() : document.documentElement.requestFullscreen();
document.addEventListener('keydown', e => {{ if (e.key === 'Escape' && window.parent !== window) window.parent.postMessage('close-story', '*'); if (e.key === 'ArrowRight') {{ clearTimeout(timer); go(cur + 1); }} else if (e.key === 'ArrowLeft') {{ clearTimeout(timer); go(cur - 1); }} else if (e.key === ' ') {{ e.preventDefault(); setPlaying(!playing); }} else if (e.key.toLowerCase() === 'r') {{ setPlaying(false); go(0); }} }});
go(0);
if (new URLSearchParams(location.search).get('autoplay') === '1') setTimeout(() => setPlaying(true), 1200);
</script></body></html>"""
