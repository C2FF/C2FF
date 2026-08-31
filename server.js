#!/usr/bin/env node
// ── C2FF : poste de chasse autonome multi-programmes ──────────────────
// 100% local. Moteur FLEET-MODE sans tokens. Optional: Claude coordination.
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const os = require('os');

const PORT = parseInt(process.argv[2] || process.env['C2FF_PORT'] || '4181', 10);
let BIND = process.env['C2FF_BIND'] || '127.0.0.1';
const ROOT = __dirname;
const DATA = path.join(ROOT, 'data');
try { fs.mkdirSync(DATA, { recursive: true }); } catch (e) {}
const RUNS_BASE = process.env['C2FF_RUNS_BASE'] || '';

const PROGRAMS_FILE = path.join(DATA, 'programs.json');
const CHAT_FILE = path.join(DATA, 'chat.jsonl');
const FINDINGS_FILE = path.join(DATA, 'findings.jsonl');
const FLEET_FILE = path.join(DATA, 'fleet.json');
const AI_FILE = path.join(DATA, 'ai.json');
const TEAM_FILE = path.join(DATA, 'team.json');
// golive (bouton UI) persiste "live" dans team.json : le respawn (auto ou watchdog)
// reprend le bind reseau sans env. C2FF_BIND reste l'override manuel.
if (!process.env['C2FF_BIND']) {
  const tb = readJson(TEAM_FILE, null) || {};
  if (tb.live) BIND = '0.0.0.0';
}

// ---------- utilitaires ----------
const trunc = (s, n) => { s = String(s == null ? '' : s).replace(/\s+/g, ' ').trim(); return s.length > n ? s.slice(0, n) + '…' : s; };
function readJson(file, fallback) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch (e) { return fallback; }
}
function appendJsonl(file, obj) {
  try { fs.appendFileSync(file, JSON.stringify(obj) + '\n'); } catch (e) { console.error('append fail:', e.message); }
}

// ---------- agent IA optionnel ----------
// le framework marche a 100% sans IA ; cette passerelle sert seulement
// a brancher l'IA de l'utilisateur (OpenAI-compatible, Ollama, Anthropic)
// pour l'analyse ponctuelle d'un finding.
function aiCfg() {
  const c = readJson(AI_FILE, null) || {};
  return {
    enabled: !!c.enabled, protocol: ['ollama', 'anthropic', 'openai'].includes(c.protocol) ? c.protocol : 'openai',
    baseURL: String(c.baseURL || ''), model: String(c.model || ''), apiKey: String(c.apiKey || ''),
  };
}
function saveAiCfg(c) { try { fs.writeFileSync(AI_FILE, JSON.stringify(c, null, 1)); } catch (e) {} }
async function aiChat(messages, cfgOverride) {
  const c = cfgOverride || aiCfg();
  if (!c.baseURL) throw new Error('baseURL non configuree');
  if (!c.model) throw new Error('model non configure');
  let url, headers = { 'content-type': 'application/json' }, payload, extract;
  if (c.protocol === 'ollama') {
    url = c.baseURL.replace(/\/+$/, '') + '/api/chat';
    payload = { model: c.model, messages, stream: false };
    extract = j => ((j.message || {}).content || '');
  } else if (c.protocol === 'anthropic') {
    url = c.baseURL.replace(/\/+$/, '').replace(/\/v1$/, '') + '/v1/messages';
    headers['x-api-key'] = c.apiKey; headers['anthropic-version'] = '2023-06-01';
    payload = { model: c.model, max_tokens: 700, system: (messages.find(m => m.role === 'system') || {}).content,
      messages: messages.filter(m => m.role !== 'system') };
    extract = j => (((j.content || [])[0] || {}).text || '');
  } else {
    url = c.baseURL.replace(/\/+$/, '').replace(/\/chat\/completions$/, '') + '/chat/completions';
    if (c.apiKey) headers.authorization = 'Bearer ' + c.apiKey;
    payload = { model: c.model, max_tokens: 700, messages };
    extract = j => ((((j.choices || [])[0] || {}).message || {}).content || '');
  }
  let r;
  try { r = await fetch(url, { method: 'POST', headers, body: JSON.stringify(payload) }); }
  catch (e) { throw new Error('inaccessible : ' + e.message); }
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error('HTTP ' + r.status + ' ' + trunc(JSON.stringify(j), 160));
  const text = extract(j);
  if (!text) throw new Error('reponse vide : ' + trunc(JSON.stringify(j), 160));
  return text;
}
const AI_ANALYST_PROMPT = "Tu es analyste bug bounty dans le framework C2FF. On te passe un signal brut " +
  "(probe deterministe locale). Reponds en 6 lignes max, structure : VERDICT defendable (SIG / P3 / P2 / P1) ; " +
  "pourquoi c'est (ou pas) un vrai probleme ; impact concret ; next probe en 1 commande curl pour confirmer " +
  "ou infirmer. Pas de blabla, pas de speculations sans preuve.";

// ---------- mode team : sessions de groupe a distance ----------
function teamCfg() {
  const c = readJson(TEAM_FILE, null) || {};
  return { enabled: !!c.enabled, room: String(c.room || ''), key: String(c.key || ''), live: !!c.live };
}
function saveTeamCfg(c) { try { fs.writeFileSync(TEAM_FILE, JSON.stringify(c, null, 1)); } catch (e) {} }
function genKey() { return 'c2ff-' + crypto.randomBytes(12).toString('hex'); }
const PRESENCE = new Map(); // handle -> { last, reqs }
const cleanHandle = h => String(h == null ? '' : h).replace(/[^\w \-.]{1,}/g, '').trim().slice(0, 16);
const isLoopback = req => ['127.0.0.1', '::1', '::ffff:127.0.0.1'].includes(String(req.socket.remoteAddress || ''));
const lanAddr = () => {
  try {
    for (const list of Object.values(os.networkInterfaces()))
      for (const i of list || []) if (i.family === 'IPv4' && !i.internal) return i.address + ':' + PORT;
  } catch (e) {}
  return '';
};
// depuis localhost : acces complet. Depuis ailleurs : la cle de salle suffit.
function teamAllowed(req, url) {
  const t = teamCfg();
  if (!t.enabled) return true;
  if (isLoopback(req)) return true;
  return (url.searchParams.get('k') || req.headers['x-c2ff-key'] || '') === t.key;
}
function teamState() {
  const t = teamCfg();
  const now = Date.now();
  const members = [];
  for (const [h, m] of PRESENCE) {
    const ms = now - m.last;
    if (ms > 600000) { PRESENCE.delete(h); continue; }
    members.push({ h, last: m.last, ms, active: ms < 25000, reqs: m.reqs });
  }
  members.sort((a, b) => a.last - b.last);
  return {
    enabled: t.enabled, room: t.room, protected: t.enabled,
    bind: BIND === '0.0.0.0' ? 'lan' : 'local', lan: lanAddr(),
    members, online: members.filter(m => m.active).length,
  };
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
  for (const p of loadPrograms()) {
    const scopes = (p.scope || []).map(x => String(x).replace(/^\*\./, '').replace(/\s+only$/i, '').toLowerCase());
    if (scopes.some(sc => sc && hay.includes(sc))) return p.id;
  }
  return (loadPrograms()[0] || {}).id || '';
}

// ---------- labels des runs connus ----------
// renseigner ici un mapping { '<runId>': 'label' } si besoin,
// sinon les labels sont deduits des transcripts d agents
const RUN_LABELS = {};

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
  if (!state.runs.has(id)) state.runs.set(id, { id, label: RUN_LABELS[id] || id, program: '', agents: new Map() });
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
  const ai = aiCfg();
  sendJson(res, {
    now: new Date().toISOString(), runs, findings: state.findings, programs: loadPrograms(), chat: lastChat(80),
    fleet: fleet.state(), modes: fleet.catalog(), team: teamState(),
    ai: { enabled: ai.enabled, protocol: ai.protocol, baseURL: ai.baseURL, model: ai.model, ready: !!(ai.baseURL && ai.model) },
  });
}

const server = http.createServer((req, res) => {
  sweep();
  const url = new URL(req.url, 'http://x');
  const p = url.pathname;
  if (p.startsWith('/api/')) {
    if (!teamAllowed(req, url)) return send(res, 403, 'text/plain', 'team key required');
  }

  if (req.method === 'POST') {
    readBody(req, async body => {
      if (p === '/api/team') {
        if (body.op === 'beat') {
          const h = cleanHandle(body.handle);
          if (h) PRESENCE.set(h, { last: Date.now(), reqs: (PRESENCE.get(h) || { reqs: 0 }).reqs + 1 });
          return sendJson(res, { ok: true, team: teamState() });
        }
        if (body.op === 'config') {
          const cur = teamCfg();
          const next = {
            enabled: typeof body.enabled === 'boolean' ? body.enabled : cur.enabled,
            room: typeof body.room === 'string' ? body.room.trim().slice(0, 32) : cur.room,
            key: cur.key || genKey(),
          };
          saveTeamCfg(next);
          return sendJson(res, { ok: true, team: next });
        }
        if (body.op === 'regen') {
          const cur = teamCfg();
          const next = { enabled: cur.enabled, room: cur.room, key: genKey() };
          saveTeamCfg(next);
          return sendJson(res, { ok: true, team: next });
        }
        // golive : le serveur se re-bind en 0.0.0.0 (respawn propre). shore : retour 127.0.0.1.
        // decision de bind = decision locale, loopback uniquement.
        if (body.op === 'golive' || body.op === 'shore') {
          if (!isLoopback(req)) return sendJson(res, { ok: false, error: 'loopback only' });
          const cur = teamCfg();
          if (!cur.enabled) return sendJson(res, { ok: false, error: 'enable the room first' });
          const next = { enabled: cur.enabled, room: cur.room, key: cur.key, live: body.op === 'golive' };
          saveTeamCfg(next);
          try {
            require('child_process').spawn(process.execPath, process.argv.slice(1), { env: process.env, detached: true, stdio: 'ignore', cwd: ROOT }).unref();
          } catch (e) {}
          setTimeout(() => { try { process.exit(0); } catch (e) {} }, 250);
          return sendJson(res, { ok: true, restarting: true, team: next });
        }
        return sendJson(res, { ok: false, error: 'unknown op' });
      }
      if (p === '/api/chat') {
        appendJsonl(CHAT_FILE, { t: Date.now(), from: 'user', name: cleanHandle(body.name) || 'OPERATOR', kind: 'chat', text: trunc(body.text || '', 4000) });
        return sendJson(res, { ok: true });
      }
      if (p === '/api/queue') {
        appendJsonl(CHAT_FILE, { t: Date.now(), from: 'user', kind: 'queue', playbook: body.playbook || '', program: body.program || '', note: trunc(body.note || '', 1000) });
        return sendJson(res, { ok: true });
      }
      if (p === '/api/findings') {
        if (body.op === 'patch' && body.key) {
          const f = state.findings.find(x => x.key === body.key);
          if (f && typeof body.status === 'string') {
            f.status = body.status;
            f.tri = (f.tri || []).concat([{ by: cleanHandle(body.name) || 'OPERATOR', st: body.status, t: Date.now() }]).slice(-20);
          }
          persistFindings();
          return sendJson(res, { ok: true });
        }
        state.seq++;
        state.findings.unshift({
          key: 'manual:' + Date.now(), id: 'F' + String(state.seq).padStart(4, '0'), t: Date.now(),
          program: body.program || (loadPrograms()[0] || {}).id || '', run: 'MANUEL', agent: cleanHandle(body.name) || 'OPERATOR',
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
        if (body.op === 'run') {
          // lancement local d'un mode par l'UI : cible + mode, IA pas requise
          const patch = { enabled: true, paused: false };
          if (body.mode) patch.mode = String(body.mode);
          fleet.apply(patch);
          fleet.cycle({ program: body.program || '' }).catch(() => {});
          return sendJson(res, { ok: true, fleet: fleet.state() });
        }
        const st = fleet.apply(body);
        return sendJson(res, { ok: true, fleet: st });
      }
      if (p === '/api/ai') {
        if (body.op === 'test') {
          // teste avec les champs du formulaire (ou la config sauvee si vides)
          const cur = aiCfg();
          const cfg = {
            enabled: true,
            protocol: ['ollama', 'anthropic', 'openai'].includes(body.protocol) ? body.protocol : cur.protocol,
            baseURL: body.baseURL || cur.baseURL,
            model: body.model || cur.model,
            apiKey: typeof body.apiKey === 'string' && body.apiKey ? body.apiKey : cur.apiKey,
          };
          try {
            const reply = await aiChat([{ role: 'user', content: 'ping : reponds juste "pong".' }], cfg);
            return sendJson(res, { ok: true, reply: trunc(reply, 200) });
          } catch (e) { return sendJson(res, { ok: false, error: trunc(e.message, 200) }); }
        }
        if (body.op === 'analyse') {
          const text = trunc(body.text || '', 2000);
          if (!text) return sendJson(res, { ok: false, error: 'texte vide' });
          try {
            const reply = await aiChat([
              { role: 'system', content: AI_ANALYST_PROMPT },
              { role: 'user', content: text },
            ]);
            appendJsonl(CHAT_FILE, { t: Date.now(), from: 'ia', kind: 'chat', text: trunc(reply, 4000) });
            return sendJson(res, { ok: true, reply: trunc(reply, 2000) });
          } catch (e) { return sendJson(res, { ok: false, error: trunc(e.message, 200) }); }
        }
        // sauvegarde de la config
        if (typeof body.enabled === 'boolean' || body.baseURL || body.model || body.protocol) {
          const cur = aiCfg();
          const next = {
            enabled: typeof body.enabled === 'boolean' ? body.enabled : cur.enabled,
            protocol: ['ollama', 'anthropic', 'openai'].includes(body.protocol) ? body.protocol : cur.protocol,
            baseURL: typeof body.baseURL === 'string' ? body.baseURL.trim() : cur.baseURL,
            model: typeof body.model === 'string' ? body.model.trim() : cur.model,
            apiKey: typeof body.apiKey === 'string' ? body.apiKey.trim() : cur.apiKey,
          };
          saveAiCfg(next);
          return sendJson(res, { ok: true });
        }
        return sendJson(res, { ok: false, error: 'unknown op' });
      }
      sendJson(res, { ok: false, error: 'unknown' });
    });
    return;
  }

  if (p === '/api/state') return apiState(res);
  if (p === '/app.js') return send(res, 200, 'application/javascript; charset=utf-8', fs.readFileSync(path.join(ROOT, 'app.js')));
  if (p === '/banner.png') return send(res, 200, 'image/png', fs.readFileSync(path.join(ROOT, 'docs', 'assets', 'banner.png')));
  if (p === '/banner_app.gif') return send(res, 200, 'image/gif', fs.readFileSync(path.join(ROOT, 'docs', 'assets', 'banner_app.gif')));
  if (p === '/' || p === '/index.html') return send(res, 200, 'text/html; charset=utf-8', fs.readFileSync(path.join(ROOT, 'index.html')));
  send(res, 404, 'text/plain', 'not found');
});

sweep();
server.listen(PORT, BIND, () => console.log('C2//FLEET : http://' + (BIND === '0.0.0.0' ? '<ip-locale> (lan)' : 'localhost') + ':' + PORT + (BIND !== '127.0.0.1' ? ' - mode team accessible' : '')));
// respawn chain : le remplacant attend la liberation du port (le vieux process vient de mourir)
let bindTries = 0;
server.on('error', e => {
  if (e.code === 'EADDRINUSE' && bindTries++ < 60) {
    setTimeout(() => { try { server.listen(PORT, BIND); } catch (e2) {} }, 500);
    return;
  }
  console.error('server error:', e.message);
  process.exit(1);
});