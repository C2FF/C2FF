#!/usr/bin/env node
// ── C2FF : poste de chasse autonome multi-programmes ──────────────────
// 100% local. Moteur FLEET-MODE sans tokens. Optional: Claude coordination.
const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = parseInt(process.argv[2] || process.env['C2FF_PORT'] || '4181', 10);
const ROOT = __dirname;
const DATA = path.join(ROOT, 'data');
const RUNS_BASE = process.env['C2FF_RUNS_BASE'] || '';

const PROGRAMS_FILE = path.join(DATA, 'programs.json');
const CHAT_FILE = path.join(DATA, 'chat.jsonl');
const FINDINGS_FILE = path.join(DATA, 'findings.jsonl');
const FLEET_FILE = path.join(DATA, 'fleet.json');

// ---------- utilitaires ----------
const trunc = (s, n) => { s = String(s == null ? '' : s).replace(/\s+/g, ' ').trim(); return s.length > n ? s.slice(0, n) + '…' : s; };
function readJson(file, fallback) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch (e) { return fallback; }
}
function appendJsonl(file, obj) {
  try { fs.appendFileSync(file, JSON.stringify(obj) + '\n'); } catch (e) { console.error('append fail:', e.message); }
}

// ---------- programmes ----------
const DEFAULT_PROGRAMS = [
  { id: 'exemple', name: 'Exemple Program', platform: 'Bugcrowd', header: 'X-Bug-Bounty: <ton-handle>', scope: ['*.exemple.com'], creds: '', runs: [] },
];
function loadPrograms() {
  const list = readJson(PROGRAMS_FILE, null);
  if (Array.isArray(list) && list.length) return list;
  try { fs.writeFileSync(PROGRAMS_FILE, JSON.stringify(DEFAULT_PROGRAMS, null, 1)); } catch (e) {}
  return DEFAULT_PROGRAMS;
}
function guessProgram(runId, runLabel, sampleText) {
  const byRun = loadPrograms().find(p => (p.runs || []).includes(runId));
  if (byRun) return byRun.id;
  const hay = (runId + ' ' + (runLabel || '') + ' ' + (sampleText || '')).toLowerCase();
  if (/blockchain\.com|blockchain\.info|ws\.blockchain/.test(hay)) return 'blockchain';
  if (/bullish/.test(hay)) return 'bullish';
  if (/rapyd/.test(hay)) return 'rapyd';
  if (/nubank|nu\.com\.(mx|co)/.test(hay)) return 'nubank';
  if (/transferwise|\bwise\b/.test(hay)) return 'wise';
  return (loadPrograms()[0] || {}).id || 'exemple';
}

// ---------- labels des runs connus ----------
const RUN_LABELS = {
  'wf_88743a37-910': 'HORDE P1/P2',
  'wf_dd7c2985-83a': 'VAGUE LFI',
  'wf_7ccb9b3c-46d': 'JACKPOT PARTNERS',
  'wf_b4059542-158': 'DUO SQLI',
  'wf_e68ff29c-147': 'DUO RCE/SSTI',
  'wf_90702594-023': 'BINOME SSRF',
};

// ---------- detection signaux ----------
const FINDING_RE = /(P1|P2|\bP3\b|finding|hypoth[eè]se|hypothesis|vulnerab|vuln[eé]rab|bypass|idor|bola|sqli|sql injection|inject|traversal|passwd|race condition|secret|credential|auth bypass|exploitabl|open redirect|privilege|escalat|jackpot|verdict|confirmed|confirme|takeover|unfurl|ssrf|ssti)/i;
const NOISE_RE = /temporarily unavailable|safety of \w+ right now|auto mode cannot determine|classify|glm-5\.3-flash|No such file or directory|permission denied|EADDRINUSE|timed out and|timed out, so/i;
const SEV_RE = /\b(P1|P2|P3)\b/;

// ---------- etat ----------
const state = {
  seq: 0, runs: new Map(), findings: [], offsets: new Map(),
  labelTried: {}, namedAgents: new Set(),
};

// ---------- persistence des findings ----------
function loadFindings() {
  const out = [], seen = new Set();
  try {
    for (const l of fs.readFileSync(FINDINGS_FILE, 'utf8').split('\n')) {
      if (!l.trim()) continue;
      let f; try { f = JSON.parse(l); } catch (e) { continue; }
      if (!f.key || seen.has(f.key)) continue;
      seen.add(f.key);
      out.push(f);
      const m = /^F(\d+)$/.exec(f.id || '');
      if (m && parseInt(m[1], 10) > state.seq) state.seq = parseInt(m[1], 10);
    }
  } catch (e) {}
  out.sort((a, b) => (b.t || 0) - (a.t || 0));
  state.findings = out.slice(0, 500);
}
let persistTimer = null;
function persistFindings() {
  if (persistTimer) return;
  persistTimer = setTimeout(() => {
    persistTimer = null;
    try { fs.writeFileSync(FINDINGS_FILE, state.findings.map(f => JSON.stringify(f)).join('\n') + '\n'); } catch (e) {}
  }, 400);
}

// ---------- moteur local FLEET-MODE (100% local, sans tokens) ----------
const fleet = require('./fleet.js');
fleet.init({
  file: FLEET_FILE,
  onFinding: (f) => {
    f.key = f.key || 'local:' + f.program + ':' + f.agent + ':' + (f.text || '').toLowerCase().slice(0, 120);
    if (state.findings.find(x => x.key === f.key)) return null;
    state.seq++;
    const full = { key: f.key, id: 'F' + String(state.seq).padStart(4, '0'), t: Date.now(), sev: f.sev || 'SIG', status: 'signal', text: f.text, program: f.program, run: 'FLEET-LOCAL', agent: f.agent };
    state.findings.unshift(full);
    if (state.findings.length > 500) state.findings.pop();
    persistFindings();
    return full;
  },
});

// chargement initial
loadFindings();
fleet.load();
fleet.setSource(() => loadPrograms());
fleet.startLoop();

function runState(id) {
  if (!state.runs.has(id)) state.runs.set(id, { id, label: RUN_LABELS[id] || id, program: 'etoro', agents: new Map() });
  return state.runs.get(id);
}
function agentState(run, base) {
  if (!run.agents.has(base)) {
    run.agents.set(base, { base, name: base === 'workflow' ? 'ORCHESTRATOR' : base.replace('agent-', '#'), status: 'running', events: [], last: '', total: 0 });
  }
  return run.agents.get(base);
}
function bumpAgentName(run, base, text) {
  const m = /tu es agent ([A-Za-z0-9_\/-]{3,28})/i.exec(String(text));
  if (m && !state.namedAgents.has(run.id + ':' + base)) {
    state.namedAgents.add(run.id + ':' + base);
    agentState(run, base).name = m[1].toUpperCase().slice(0, 28);
  }
}

function capture(run, base, text) {
  bumpAgentName(run, base, text);
  for (const line of String(text).split(/\n+/)) {
    const l = trunc(line, 260);
    if (l.length < 14 || NOISE_RE.test(l)) continue;
    const key = l.toLowerCase().slice(0, 120);
    if (FINDING_RE.test(l) && !state.findings.find(f => f.key === key)) {
      const sev = (l.match(SEV_RE) || [null])[0];
      state.seq++;
      state.findings.unshift({
        key, id: 'F' + String(state.seq).padStart(4, '0'), t: Date.now(),
        program: run.program, run: run.label, agent: agentState(run, base).name,
        sev: sev || (/jackpot|confirmed|confirme|bypass|sqli|ssrf|ssti|exploitabl/i.test(l) ? 'HIT' : 'SIG'),
        text: l, status: 'signal',
      });
      if (state.findings.length > 500) state.findings.pop();
    }
  }
}

// ---------- lecture incrementale des transcripts ----------
function extractContent(run, base, content) {
  const a = agentState(run, base);
  if (!Array.isArray(content)) return;
  for (const b of content) {
    if (b.type === 'tool_use') {
      if (/StructuredOutput/i.test(b.name || '')) a.status = 'done';
      const i = b.input || {};
      const detail = i.command || i.url || i.file_path || i.query || i.pattern || JSON.stringify(i).slice(0, 150);
      a.events.push({ kind: 'run', text: '» ' + trunc(detail, 190), t: Date.now() });
      a.total++;
      capture(run, base, detail + ' ' + (i.command || i.url || ''));
    } else if (b.type === 'tool_result') {
      const c = typeof b.content === 'string' ? b.content : JSON.stringify(b.content);
      a.events.push({ kind: 'out', text: '« ' + trunc(c, 190), t: Date.now() });
      a.total++;
      capture(run, base, c);
    } else if (b.type === 'text' && b.text) {
      a.last = trunc(b.text, 280);
      a.events.push({ kind: 'txt', text: trunc(b.text, 200), t: Date.now() });
      a.total++;
      capture(run, base, b.text);
    } else if (b.type === 'thinking' && b.thinking) {
      capture(run, base, b.thinking.slice(0, 600));
    }
  }
  if (a.events.length > 400) a.events.splice(0, a.events.length - 400);
}
function addAgentLines(run, base, text) {
  for (const line of String(text).split('\n')) {
    if (!line.trim()) continue;
    let o; try { o = JSON.parse(line); } catch (e) { continue; }
    const msg = o.message || o;
    if (msg && Array.isArray(msg.content)) extractContent(run, base, msg.content);
    else if (Array.isArray(o.content)) extractContent(run, base, o.content);
    if (o.type === 'result' || o.subtype === 'success') agentState(run, base).status = 'done';
    if (o.isError === true) agentState(run, base).status = 'error';
  }
}
function readNew(file, run, kind) {
  let size = 0; try { size = fs.statSync(file).size; } catch (e) { return; }
  const off = state.offsets.get(file) || 0;
  if (size <= off) return;
  let fh; try { fh = fs.openSync(file, 'r'); } catch (e) { return; }
  try {
    const buf = Buffer.alloc(size - off);
    fs.readSync(fh, buf, 0, buf.length, off);
    state.offsets.set(file, size);
    if (kind === 'journal') {
      const w = agentState(run, 'workflow');
      for (const line of String(buf).split('\n')) {
        if (!line.trim()) continue;
        let o; try { o = JSON.parse(line); } catch (e) { continue; }
        const det = o.message || o.label || o.phase || (o.agent ? o.agent + (o.status ? ' · ' + o.status : '') : '');
        w.events.push({ kind: 'info', text: 'ⓘ ' + trunc(typeof det === 'string' ? det : JSON.stringify(det), 240), t: Date.now() });
        w.total++;
        capture(run, 'workflow', typeof det === 'string' ? det : JSON.stringify(det));
      }
      if (w.events.length > 400) w.events.splice(0, w.events.length - 400);
    } else {
      addAgentLines(run, path.basename(file).replace('.jsonl', ''), String(buf));
    }
  } finally { fs.closeSync(fh); }
}
function sweep() {
  if (!RUNS_BASE) return;
  let dirs = [];
  try { dirs = fs.readdirSync(RUNS_BASE).filter(d => /^wf_/.test(d)); } catch (e) { return; }
  for (const id of dirs) {
    const dir = path.join(RUNS_BASE, id);
    let files = []; try { files = fs.readdirSync(dir).filter(f => f.endsWith('.jsonl')); } catch (e) { continue; }
    const run = runState(id);
    if (!RUN_LABELS[id] && !state.labelTried[id]) {
      for (const f of files) {
        try {
          const head = fs.readFileSync(path.join(dir, f), 'utf8').slice(0, 300000);
          const m = /(?:tu es agent |ton axe : )([A-Za-z0-9_\/ -]{3,40})/i.exec(head);
          if (m) { run.label = m[1].trim().toUpperCase().slice(0, 30); break; }
        } catch (e) {}
      }
      state.labelTried[id] = true;
    }
    if (run.program === 'etoro' && !guessProgram(id, run.label, '')) {} // fallback programme par defaut
    const sample = (state.findings.find(f => f.run === run.label) || {}).text || '';
    run.program = guessProgram(id, run.label, sample);
    for (const f of files.sort()) {
      readNew(path.join(dir, f), run, f === 'journal.jsonl' ? 'journal' : 'agent');
    }
  }
}

// ---------- chat ----------
function lastChat(n) {
  const out = [];
  try {
    for (const l of fs.readFileSync(CHAT_FILE, 'utf8').split('\n')) {
      if (!l.trim()) continue;
      try { out.push(JSON.parse(l)); } catch (e) {}
    }
  } catch (e) {}
  return out.slice(-n);
}

// ---------- API ----------
function send(res, code, type, body) { res.writeHead(code, { 'content-type': type, 'cache-control': 'no-store' }); res.end(body); }
function sendJson(res, obj) { send(res, 200, 'application/json', JSON.stringify(obj)); }
function readBody(req, cb) {
  let chunks = [], n = 0;
  req.on('data', c => { n += c.length; if (n < 2e6) chunks.push(c); });
  req.on('end', () => { try { cb(JSON.parse(Buffer.concat(chunks).toString() || '{}')); } catch (e) { cb({}); } });
}

function apiState(res) {
  const runs = [...state.runs.values()].map(r => {
    // l'agregateur "workflow" se marque termine quand tous les vrais agents ont fini
    const real = [...r.agents.values()].filter(a => a.base !== 'workflow');
    if (real.length && real.every(a => a.status !== 'running')) {
      const w = r.agents.get('workflow');
      if (w && w.status === 'running') w.status = 'done';
    }
    const agents = [...r.agents.values()].map(a => ({ base: a.base, name: a.name, status: a.status, total: a.total, last: a.last, events: a.events.slice(-12) }));
    const done = agents.filter(a => a.status !== 'running').length;
    return { id: r.id, label: r.label, program: r.program, n: agents.length, done, list: agents };
  }).sort((a, b) => (b.n - b.done) - (a.n - a.done) || b.n - a.n);
  sendJson(res, { now: new Date().toISOString(), runs, findings: state.findings, programs: loadPrograms(), chat: lastChat(80), fleet: fleet.state() });
}

const server = http.createServer((req, res) => {
  sweep();
  const url = new URL(req.url, 'http://x');
  const p = url.pathname;

  if (req.method === 'POST') {
    readBody(req, body => {
      if (p === '/api/chat') {
        appendJsonl(CHAT_FILE, { t: Date.now(), from: 'user', kind: 'chat', text: trunc(body.text || '', 4000) });
        return sendJson(res, { ok: true });
      }
      if (p === '/api/queue') {
        appendJsonl(CHAT_FILE, { t: Date.now(), from: 'user', kind: 'queue', playbook: body.playbook || '', program: body.program || '', note: trunc(body.note || '', 1000) });
        return sendJson(res, { ok: true });
      }
      if (p === '/api/findings') {
        if (body.op === 'patch' && body.key) {
          const f = state.findings.find(x => x.key === body.key);
          if (f && typeof body.status === 'string') f.status = body.status;
          persistFindings();
          return sendJson(res, { ok: true });
        }
        state.seq++;
        state.findings.unshift({
          key: 'manual:' + Date.now(), id: 'F' + String(state.seq).padStart(4, '0'), t: Date.now(),
          program: body.program || 'etoro', run: 'MANUEL', agent: 'OPERATOR',
          sev: ['P1', 'P2', 'P3', 'HIT', 'SIG'].includes(body.sev) ? body.sev : 'HIT',
          text: trunc(body.text || '', 400), status: 'analyse',
        });
        return sendJson(res, { ok: true });
      }
      if (p === '/api/programs') {
        if (Array.isArray(body.programs)) {
          try { fs.writeFileSync(PROGRAMS_FILE, JSON.stringify(body.programs, null, 1)); return sendJson(res, { ok: true }); }
          catch (e) { return sendJson(res, { ok: false }); }
        }
        return sendJson(res, { ok: false });
      }
      if (p === '/api/fleet') {
        if (body.op === 'test') {
          // cycle immediat, sans changer la config persistee
          if (!fleet.enabled) fleet.apply({ enabled: true });
          fleet.cycle().catch(() => {});
          return sendJson(res, { ok: true, fleet: fleet.state() });
        }
        const st = fleet.apply(body);
        return sendJson(res, { ok: true, fleet: st });
      }
      sendJson(res, { ok: false, error: 'unknown' });
    });
    return;
  }

  if (p === '/api/state') return apiState(res);
  if (p === '/app.js') return send(res, 200, 'application/javascript; charset=utf-8', fs.readFileSync(path.join(ROOT, 'app.js')));
  if (p === '/banner.png') return send(res, 200, 'image/png', fs.readFileSync(path.join(ROOT, 'docs', 'assets', 'banner.png')));
  if (p === '/' || p === '/index.html') return send(res, 200, 'text/html; charset=utf-8', fs.readFileSync(path.join(ROOT, 'index.html')));
  send(res, 404, 'text/plain', 'not found');
});

sweep();
server.listen(PORT, '127.0.0.1', () => console.log('C2//FLEET : http://localhost:' + PORT));