// Records the Blast Radius demo: drives the console, captions + speaks each line, writes a timeline for ffmpeg.
const puppeteer = require('puppeteer-core');
const fs = require('fs'), path = require('path'), { execSync } = require('child_process');
const OUT = process.env.OUT || '/tmp/demo'; fs.mkdirSync(OUT, { recursive: true });
const VOICE = process.env.VOICE || 'Samantha', RATE = process.env.RATE || '178';
const sleep = ms => new Promise(r => setTimeout(r, ms));
const BASE = 'http://localhost:8000';

// ---------- narration ----------
const L = {
  intro1: "A dependency scanner tells you this codebase has 329 advisories in its lockfile. It cannot tell you whether any of them matter.",
  intro2: "Blast Radius loads the whole repository into FalkorDB as one graph, and lets an agent walk it. Top right: 329 advisories, 123 in packages the code actually calls, 30 high or critical ones reachable from an HTTP endpoint.",
  graph: "Every file, function, call, route, package, advisory, data table and git-blame owner is a node or an edge in FalkorDB. All twenty agent tools are Cypher queries or FalkorDB graph algorithms, served to the agent over MCP.",
  ask: "Let's ask the question a security engineer actually has: Pillow has new CVEs. Which of our endpoints are exposed, who owns that code, and fix it.",
  identify: "Identify. Eighteen advisories on Pillow, and the live deployment status of the demo site, so deployed, unauthenticated endpoints rank first.",
  reach: "Reach. One variable-length path query walks from the package through the call graph to the HTTP handlers. FalkorDB's shortest-path algorithm ranks the attack paths, and betweenness plus PageRank find the choke-point function.",
  owners: "Owners. Git blame lives on the graph too, so the agent names who maintains the image code.",
  fix: "Fix. The minimum safe version is verified against OSV: Pillow 12.3.0 is clean.",
  act: "Act. The dependency is bumped on a branch, and a real pull request is opened on the fork.",
  record: "Record. The decision is written back into FalkorDB, so the next run remembers what was already triaged.",
  verdict: "Verdict: exploitable. Eight endpoints pass uploaded or scraped images into Pillow with no format check. Each row shows the hops, the confidence, and whether the endpoint is live and needs login.",
  attention: "Anything that needs a human is flagged in red, so reviewers see the risk before the details.",
  cypher: "Every step is a real graph query you can read: the exact Cypher, the rows it returned, and the latency.",
  diff: "And the fix is a real change: here is the pyproject diff the agent committed on its branch.",
  replay: "Now the evidence graph replays the attack path hop by hop: the request enters at the upload endpoint, is handled by the controller, which calls the minifier, which reaches Pillow.",
  pr: "The pull request is real. Pillow 11.3.0 to 12.3.0 on the fork, with the advisories, the reachable endpoints and the owners in the description.",
  memory: "Back in the console, the fourth tile now reads eighteen triaged, and the advisory feed shows the decision instead of a button. The graph is also the agent's memory.",
  story: "Every run also produces a full-screen story and an HTML report for reviewers: the question, the investigation one query at a time, the attack path, and the verdict.",
  outro: "Blast Radius: from advisory to merged fix, with every hop explained, running on FalkorDB. The repository is github.com slash Rakesh9742 slash blast-radius. Thank you.",
};
// pre-render speech and measure durations
const DUR = {};
for (const [k, text] of Object.entries(L)) {
  const f = path.join(OUT, `${k}.aiff`);
  execSync(`say -v ${VOICE} -r ${RATE} -o "${f}" ${JSON.stringify(text)}`);
  DUR[k] = Math.round(parseFloat(execSync(`ffprobe -v error -show_entries format=duration -of csv=p=0 "${f}"`).toString()) * 1000);
}
console.log('narration total', Math.round(Object.values(DUR).reduce((a, b) => a + b, 0) / 1000), 's');

// ---------- caption overlay ----------
const CAPTION_CSS = `#narr{position:fixed;left:50%;bottom:26px;transform:translateX(-50%);max-width:1180px;background:rgba(8,12,20,.88);color:#f1f5f9;font:500 21px/1.35 -apple-system,Inter,Segoe UI,sans-serif;padding:12px 20px;border-radius:12px;border:1px solid rgba(249,115,22,.45);box-shadow:0 10px 40px rgba(0,0,0,.5);z-index:2147483647;opacity:0;transition:opacity .25s;text-align:center;pointer-events:none}#narr.show{opacity:1}`;
async function ensureCaption(page) {
  await page.evaluate(css => { if (!document.getElementById('narr')) { const s = document.createElement('style'); s.textContent = css; document.head.appendChild(s); const d = document.createElement('div'); d.id = 'narr'; document.body.appendChild(d); } }, CAPTION_CSS).catch(() => {});
}
async function caption(page, text) { await ensureCaption(page); await page.evaluate(t => { const d = document.getElementById('narr'); if (!d) return; d.textContent = t; d.classList.toggle('show', !!t); }, text).catch(() => {}); }

// ---------- audio timeline (sequential queue) ----------
const timeline = []; let t0 = 0, queueEnd = 0;
async function say(page, key) {        // schedule the clip after the previous one, show caption when it starts
  const start = Math.max(Date.now(), queueEnd);
  const wait = start - Date.now(); if (wait > 0) await sleep(wait);
  timeline.push({ key, startMs: Date.now() - t0, durMs: DUR[key] });
  queueEnd = Date.now() + DUR[key] + 250;
  await caption(page, L[key]);
  return DUR[key];
}
const drain = async () => { const w = queueEnd - Date.now(); if (w > 0) await sleep(w); };

(async () => {
  const browser = await puppeteer.launch({ executablePath: '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', headless: 'new', protocolTimeout: 600000, args: ['--window-size=1600,900', '--hide-scrollbars'] });
  const page = await browser.newPage(); await page.setViewport({ width: 1600, height: 900 });
  page.on('pageerror', e => console.log('PAGE ERROR', e.message));
  await page.goto(`${BASE}/?story=0`, { waitUntil: 'networkidle0' }); await sleep(800); await ensureCaption(page);
  const rec = await page.screencast({ path: path.join(OUT, 'raw.webm') }); t0 = Date.now(); await sleep(600);

  // 1. intro: hover the funnel tiles
  await say(page, 'intro1');
  const tiles = await page.$$('.funnel .tile, #funnel > div'); 
  await sleep(2500);
  await say(page, 'intro2');
  for (const t of tiles.slice(0, 4)) { try { await t.hover(); } catch {} await sleep(1500); }
  await drain();

  // 2. the graph
  await say(page, 'graph');
  await page.hover('#mcpbadge').catch(() => {}); await sleep(1800);
  const pts = await page.evaluate(() => { const r = document.getElementById('cy').getBoundingClientRect(); return cy.nodes().slice(0, 40).map(n => { const p = n.renderedPosition(); return { x: r.x + p.x, y: r.y + p.y }; }); });
  for (const p of pts.filter((_, i) => i % 6 === 0).slice(0, 6)) { await page.mouse.move(p.x, p.y, { steps: 6 }); await sleep(900); }
  await drain();

  // 3. run the scenario, narrate phases as they complete
  await say(page, 'ask');
  await page.hover('#scenarios button'); await sleep(1200);
  await page.click('#scenarios button');
  const spoken = new Set(); const order = ['identify', 'reach', 'owners', 'fix', 'act', 'record'];
  const deadline = Date.now() + 240000;
  while (Date.now() < deadline) {
    const st = await page.evaluate(() => Object.fromEntries([...document.querySelectorAll('.phase')].map(p => [p.dataset.p, p.classList.contains('done') ? 'done' : p.classList.contains('active') ? 'active' : ''])));
    const finished = await page.evaluate(() => document.getElementById('usage').textContent.includes('tokens'));
    for (const k of order) if (!spoken.has(k) && (st[k] === 'active' || st[k] === 'done')) { spoken.add(k); await say(page, k); break; }
    if (finished) { for (const k of order) if (!spoken.has(k) && st[k] === 'done') { spoken.add(k); await say(page, k); } break; }
    await sleep(400);
  }
  await page.waitForFunction(() => document.getElementById('usage').textContent.includes('tokens'), { timeout: 240000, polling: 500 });
  await page.waitForFunction(() => typeof lastRunId !== 'undefined' && lastRunId, { timeout: 60000, polling: 500 }).catch(() => {});
  await drain();

  // 4. the answer
  await page.evaluate(() => { replayTimers.forEach(clearTimeout); cy.elements().removeClass('dim hot'); document.getElementById('caption').classList.remove('show'); const m = document.querySelector('.msg.agent'); if (m) m.scrollIntoView({ block: 'start' }); });
  await say(page, 'verdict'); await sleep(DUR.verdict * 0.6);
  await page.evaluate(() => { const a = document.querySelector('.msg .attn'); if (a) a.scrollIntoView({ block: 'center' }); });
  await drain(); await say(page, 'attention'); await drain();

  // 5. a step card with its Cypher, then the diff
  await page.evaluate(() => { const c = document.querySelector('.tool[data-name="reachability"]') || document.querySelectorAll('.tool')[2]; if (c) { c.scrollIntoView({ block: 'center' }); c.classList.add('open'); } });
  await say(page, 'cypher'); await drain();
  await page.evaluate(() => { document.querySelectorAll('.tool.open').forEach(c => c.classList.remove('open')); const c = document.querySelector('.tool[data-name="apply_dependency_fix"]'); if (c) { c.scrollIntoView({ block: 'center' }); c.classList.add('open'); } });
  await say(page, 'diff'); await drain();

  // 6. attack-path replay on the graph
  await page.evaluate(() => { document.querySelectorAll('.tool.open').forEach(c => c.classList.remove('open')); replayPath(); });
  await say(page, 'replay');
  await page.waitForFunction(() => !document.getElementById('caption').classList.contains('show'), { timeout: 40000, polling: 300 }).catch(() => {});
  await sleep(800); await drain();

  // 7. the pull request on GitHub
  const runId = await page.evaluate(() => lastRunId);
  const prUrl = await page.evaluate(() => { const a = [...document.querySelectorAll('.msg.agent a')].find(a => /github\.com\/.+\/pull\/\d+/.test(a.href)); return a ? a.href : null; });
  console.log('run', runId, 'pr', prUrl);
  if (prUrl) {
    await page.goto(prUrl, { waitUntil: 'domcontentloaded' }); await sleep(1500); await ensureCaption(page);
    await say(page, 'pr'); await sleep(2500); await page.evaluate(() => window.scrollBy({ top: 500, behavior: 'smooth' })); await drain();
  }

  // 8. memory: funnel + feed after the run
  await page.goto(`${BASE}/?story=0`, { waitUntil: 'networkidle0' }); await sleep(1200); await ensureCaption(page);
  await say(page, 'memory');
  const tiles2 = await page.$$('.funnel .tile, #funnel > div'); if (tiles2[3]) await tiles2[3].hover();
  await sleep(2500); await page.evaluate(() => { const f = document.querySelector('.feed'); if (f) f.scrollIntoView({ block: 'start' }); }); await drain();

  // 9. story mode
  if (runId) {
    await page.goto(`${BASE}/replay/${runId}?autoplay=1`, { waitUntil: 'networkidle0' }); await sleep(600); await ensureCaption(page);
    await say(page, 'story');
    await sleep(6000); for (let i = 0; i < 4; i++) { await page.keyboard.press('ArrowRight'); await sleep(2200); }
    await drain(); await sleep(1500);
  }

  // 10. outro on the console
  await page.goto(`${BASE}/?story=0`, { waitUntil: 'networkidle0' }); await sleep(800); await ensureCaption(page);
  await say(page, 'outro'); await drain(); await sleep(1200); await caption(page, '');
  await sleep(500); await rec.stop();
  fs.writeFileSync(path.join(OUT, 'timeline.json'), JSON.stringify({ timeline, totalMs: Date.now() - t0, runId, prUrl }, null, 1));
  console.log('recorded', Math.round((Date.now() - t0) / 1000), 's; clips', timeline.length);
  await browser.close();
})().catch(e => { console.error('FAILED', e.stack || e.message); process.exit(1); });
