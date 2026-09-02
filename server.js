#!/usr/bin/env node
// ── C2FF : poste de chasse autonome multi-programmes ──────────────────
// 100% local. Moteur FLEET-MODE sans tokens. Optional: Claude coordination.
const http = require('http');
const https = require('https');
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
const VOTES_FILE = path.join(DATA, 'votes.json');
const JSINT_FILE = path.join(DATA, 'jsint.json');
const URLS_FILE = path.join(DATA, 'urls.json');
const MODULES_FILE = path.join(DATA, 'modules.json');
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
const RANKS = { viewer: 0, member: 1, hunter: 2, coadmin: 3, admin: 4, owner: 5 };
function teamCfg() {
  const c = readJson(TEAM_FILE, null) || {};
  const members = (c.members && typeof c.members === 'object') ? c.members : {};
  // migration legacy : roles {handle:'admin'} -> membre approuve sans pin
  for (const [h, r] of Object.entries(c.roles || {}))
    if (r === 'admin' && !members[h]) members[h] = { pin: '', role: 'admin', status: 'approved', t: 0 };
  // epingles expires : disparus des qu'ils sont lus (durée de l'evenement ecoulee)
  const news = Array.isArray(c.news) ? c.news.filter(n => n && typeof n === 'object' && (!n.exp || n.exp > Date.now())).slice(-3) : [];
  // registre des challenges : { [newsId]: { limit, parts: { [handle]: { t, finds } } } }
  // les entrees d'epingles purges sont nettoyees en meme temps
  const chal = (c.chal && typeof c.chal === 'object') ? { ...c.chal } : {};
  for (const k of Object.keys(chal)) if (!news.some(n => n.id === k)) delete chal[k];
  // chats de session multiples : [{id, name, min (grade requis), event (newsId)}]
  // 'session' est le canal par defaut, indestructible ; les chats d'event sont
  // purges avec leur epingle (le chat du challenge meurt avec le challenge)
  const chats = (Array.isArray(c.chats) ? c.chats : []).filter(x => x && typeof x === 'object'
    && x.id && x.id !== 'session' && (!x.event || news.some(n => n.id === x.event)))
    .map(x => ({ id: String(x.id).slice(0, 32), name: String(x.name || 'chat').slice(0, 24),
      min: Math.max(0, Math.min(4, Math.floor(Number(x.min) || 0))), event: String(x.event || '') }))
    .slice(0, 7);
  chats.unshift({ id: 'session', name: 'session', min: 0, event: '' });
  return {
    enabled: !!c.enabled, room: String(c.room || ''), key: String(c.key || ''), live: !!c.live,
    roles: (c.roles && typeof c.roles === 'object') ? c.roles : {},
    members,
    blocked: Array.isArray(c.blocked) ? c.blocked : [],
    welcome: String(c.welcome || '').slice(0, 200),
    news,
    chal,
    chats,
  };
}
// acces a un chat : grade >= min ; un chat d'event (challenge) est reserve aux
// participants inscrits (moderation : admin et proprietaire passent toujours)
function chatOk(c, h, rk) {
  if (!c) return false;
  // wispe (chat prive) : SEULS les deux membres du couple y accedent, ni la
  // moderation ni le proprietaire - un message prive reste prive
  if ((c.id || '').indexOf('pm-') === 0) return !!h && c.id.slice(3).split('--').indexOf(h) >= 0;
  if (c.event) return rk >= 4 || !!(h && c._parts && c._parts[h]);
  return rk >= (c.min || 0);
}
// porte limite d'un event (challenge OU epingle avec chat dedie) : participation
// requise, limite par participant enforcee, increment atomique. retourne
// { err } si l'envoi est refuse, { cur2 } (config a sauver) si il passe.
function chalGate(cur, nid, h) {
  const n = (cur.news || []).find(x => x.id === nid);
  const c = n && (cur.chal || {})[n.id];
  if (!n || !c) return { ok: true }; // pas un event limite : libre
  if (!c.parts[h]) return { err: 'rejoins l\'event (bouton participer du bandeau) pour envoyer tes findings' };
  if ((c.limit || 0) > 0 && c.parts[h].finds >= c.limit)
    return { err: 'limite de l\'event atteinte : ' + c.parts[h].finds + '/' + c.limit + ' findings deja envoyes' };
  const chal2 = { ...cur.chal };
  chal2[nid] = { ...c, parts: { ...c.parts, [h]: { ...c.parts[h], finds: c.parts[h].finds + 1 } } };
  return { ok: true, cur2: { ...cur, chal: chal2 } };
}
function saveTeamCfg(c) { try { fs.writeFileSync(TEAM_FILE, JSON.stringify(c, null, 1)); } catch (e) {} }
function genKey() { return 'c2ff-' + crypto.randomBytes(12).toString('hex'); }
const loadVotes = () => { const v = readJson(VOTES_FILE, null); return (v && typeof v === 'object') ? v : {}; };
function saveVotes(v) { try { fs.writeFileSync(VOTES_FILE, JSON.stringify(v, null, 1)); } catch (e) {} }
const PRESENCE = new Map(); // handle -> { last, reqs }
const cleanHandle = h => String(h == null ? '' : h).replace(/[^\w \-.]{1,}/g, '').trim().slice(0, 16);
const hashPin = (h, pin) => crypto.createHash('sha256').update('c2ff-pin:' + h + ':' + pin).digest('hex');
const reqHandle = req => cleanHandle(req.headers['x-c2ff-handle']);
// role effectif : le poste local est owner ; sinon le membre approuve (members),
// fallback legacy roles{h:'admin'} ; un inconnu (ou en attente) = viewer
const roleOf = (req, h) => {
  if (isLoopback(req)) return 'owner'; // le proprietaire : grade ultime, sans equivalent
  const t = teamCfg();
  const m = t.members[h];
  if (m && m.status === 'approved') return RANKS[m.role] !== undefined ? m.role : 'member';
  if (h && t.roles[h] === 'admin') return 'admin';
  return 'viewer';
};
const rankOf = (req, h) => RANKS[roleOf(req, h)] || 0;
// membre valide de la salle (hors loopback). '' = inconnu ou en attente de validation.
// salle desactivee : usage solo, tout est permis.
const memberRole = (req, h) => {
  if (!teamCfg().enabled || isLoopback(req)) return 'owner';
  const m = teamCfg().members[h];
  return (m && m.status === 'approved') ? m.role : '';
};
// usage d'un programme : le createur et les membres de rang >= access peuvent
// s'en servir (recon, GO, arsenal). pub ne rend que VISIBLE, pas utilisable.
const progUsable = (req, pr) => {
  if (isLoopback(req) || !pr) return true;
  const a = pr.access || 1;
  const h = reqHandle(req);
  return (pr.owner && pr.owner === h) || rankOf(req, h) >= a;
};
const isLoopback = req => !req.internalTunnel && ['127.0.0.1', '::1', '::ffff:127.0.0.1'].includes(String(req.socket.remoteAddress || ''));
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
function teamState(req, h) {
  h = h || (req ? reqHandle(req) : '');
  const t = teamCfg();
  const now = Date.now();
  const rk = rankOf(req, h);
  const members = [];
  for (const [mh, m] of PRESENCE) {
    const ms = now - m.last;
    if (ms > 600000) { PRESENCE.delete(mh); continue; }
    const mm = t.members[mh];
    members.push({ h: mh, last: m.last, ms, active: ms < 25000, reqs: m.reqs, role: m.role, st: mm ? mm.status : '' });
  }
  members.sort((a, b) => a.h.localeCompare(b.h)); // ordre stable : les lignes ne sautent pas a chaque beat
  // file d'attente d'entree : visible des ranks >= co-admin seulement
  const requests = rk >= 3
    ? Object.entries(t.members).filter(([, m]) => m && m.status === 'pending').map(([mh, m]) => ({ h: mh, t: m.t }))
    : [];
  return {
    enabled: t.enabled, room: t.room, protected: t.enabled,
    roles: t.roles, blocked: t.blocked,
    welcome: t.welcome || '',
    wizz: (() => { const mm = (h && (t.members || {})[h]) || null; return { mute: !!(mm && mm.wizz_mute), rcv: (mm && mm.wizz_rcv) || 0 }; })(),
    news: (t.news || []).map(n => (t.chal || {})[n.id] ? (() => {
      const c = (t.chal || {})[n.id] || {};
      return { ...n, limit: c.limit || 0, nparts: Object.keys(c.parts || {}).length,
        me: (h && (c.parts || {})[h]) || null };
    })() : n),
    bind: BIND === '0.0.0.0' ? 'lan' : 'local', lan: lanAddr(),
    tunnel: TUNNEL ? (TUNNEL.ready && TUNNEL.url ? TUNNEL.url : (TUNNEL.err ? 'err:' + TUNNEL.err : 'starting')) : '',
    chats: (t.chats || []).filter(c => (c.id || '').indexOf('pm-') !== 0 || (h && c.id.slice(3).split('--').indexOf(h) >= 0)).map(c => {
      // l'acces aux chats d'event demande la liste des participants du challenge
      const cc = c.event ? ((t.chal || {})[c.event] || {}) : {};
      const cc2 = c.event ? { ...c, _parts: cc.parts || {} } : c;
      return { id: c.id, name: c.name, min: c.min || 0, event: c.event || '', ok: chatOk(cc2, h, rk) };
    }),
    chat: (() => {
      const V = loadVotes();
      // isolation : on ne recoit QUE les messages des chats auxquels on a acces
      // (les non-participants ne voient pas le chat du challenge, ni le lire)
      const okc = new Set((t.chats || []).filter(c => {
        const cc = c.event ? ((t.chal || {})[c.event] || {}) : {};
        return chatOk(c.event ? { ...c, _parts: cc.parts || {} } : c, h, rk);
      }).map(c => c.id));
      return lastChat(200).filter(m => (m.kind === 'team' || m.kind === 'finding' || m.kind === 'term' || m.kind === 'wizz') && okc.has(m.ch || 'session')).slice(-100).map(m => {
        const vv = V[m.id];
        if (!vv) return m;
        let up = 0, down = 0;
        for (const x of Object.values(vv)) { if (x === 1) up++; else down++; }
        return Object.assign({}, m, { v: { up, down, me: (h && vv[h]) || 0 } });
      });
    })(),
    rtc: rtcList(now).filter(m => m.to === h),
    you: req ? roleOf(req, h) : 'viewer',
    meRole: memberRole(req, h),
    requests,
    members, online: members.filter(m => m.active).length,
  };
}

// tunnel public opt-in (cloudflared) : une URL universelle, pas seulement le LAN
let TUNNEL = null; // { proc, url }

// signalisation WebRTC : relais pur, le media reste membre-a-membre
const RTCMAP = new Map(); // id -> { from, to, typ, data, t }
const WIZZRATE = new Map(); // handle -> dernier wizz (anti-flood, 1/min)
function rtcList(now) {
  const out = [];
  for (const [id, m] of RTCMAP) {
    if (now - m.t > 30000) { RTCMAP.delete(id); continue; }
    out.push(Object.assign({ id }, m));
  }
  return out.slice(-200);
}

// ---------- terminal de travail ----------
// un shell reel par identite (loopback = 'local', distant = handle admin).
// script(1) donne un PTY complet (prompt, couleurs, readline) ; fallback bash -i.
// acces : loopback toujours ; reseau uniquement si salle ON + role admin + non banni.
const TERMS = new Map(); // id -> { proc, buf: string, clients: Set, dead: bool, t0 }
const TERM_MAX_SESSIONS = 4;
const TERM_BUF_MAX = 160000;

const termId = (req, h) => (isLoopback(req) ? 'local' : cleanHandle(h) || '');
// acces terminaux : groupe = membre+ ; perso = UN PTY prive par membre valide
// (id = son handle) ; spy = lire le perso de quelqu'un d'autre, co-admin+
function termTermAllowed(req, h, group) {
  if (isLoopback(req)) return true;
  const t = teamCfg();
  if (!t.enabled) return false;           // pas de shell expose en reseau sans salle
  if (t.blocked.includes(h)) return false;
  if (group) return rankOf(req, h) >= 1;
  return rankOf(req, h) >= 1;             // terminal perso : chaque membre a le sien
}
function termSpyAllowed(req, viewer, who) {
  if (isLoopback(req)) return true;
  if (!teamCfg().enabled || who === 'local' || !who) return false; // jamais le shell hote a distance
  return rankOf(req, viewer) >= 3;        // le VIEWER doit etre co-admin+, lecture seule
}
function termBroadcast(ts, text) {
  ts.buf = (ts.buf + text).slice(-TERM_BUF_MAX);
  for (const c of ts.clients) {
    try { c.res.write('data: ' + JSON.stringify(text) + '\n\n'); } catch (e) {}
  }
}
function termKill(ts) {
  try { ts.proc.kill('SIGHUP'); } catch (e) {}
  if (ts.cname) { try { require('child_process').spawn('docker', ['kill', ts.cname], { stdio: 'ignore' }).unref(); } catch (e) {} }
}
function termSpawn(id) {
  const old = TERMS.get(id);
  if (old && !old.dead) return null; // deja vivant
  const ts = { proc: null, buf: '', clients: new Set(), dead: false, t0: Date.now(), cname: '' };
  let proc;
  if (id !== 'local' && dockerAvailable()) {
    // terminal perso d un membre distant : conteneur isole (PAS le systeme
    // de fichiers de l hebergeant) - meme montage que le terminal groupe
    const sc = sandboxCfg();
    const uid = typeof process.getuid === 'function' ? process.getuid() : 1000;
    const gid = typeof process.getgid === 'function' ? process.getgid() : 1000;
    ts.cname = 'c2ff-p-' + require('crypto').createHash('sha256').update(id).digest('hex').slice(0, 12);
    const argv = ['run', '--rm', '-i', '--name', ts.cname, '--user', uid + ':' + gid,
      '-v', GROUP_WORKDIR + ':/ws', '-w', '/ws',
      '--memory', String(sc.memory || '1g'), '--pids-limit', String(sc.pids || 256), '--cpus', String(sc.cpus || '2'),
      '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
      '-e', 'PATH=/opt/gobin:/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin',
      '-e', 'HOME=/ws', '-e', 'TERM=xterm-256color', '-e', 'LANG=C.UTF-8'];
    const tool = path.join(ROOT, '..', sc.toolbin || 'go/bin');
    try { if (fs.existsSync(tool)) argv.push('-v', tool + ':/opt/gobin:ro'); } catch (e) {}
    // script(1) dans le conteneur = PTY interne (prompt + couleurs), stdin en pipe cote client
    argv.push(String(sc.image || 'c2ff-sandbox'), '/usr/bin/script', '-qfc', '/bin/bash', '/dev/null');
    try { proc = require('child_process').spawn('docker', argv); } catch (e) { return null; }
  } else {
    const env = { ...process.env, TERM: 'xterm-256color', COLUMNS: '110', LINES: '32' };
    try {
      if (process.platform !== 'win32' && fs.existsSync('/usr/bin/script')) {
        proc = require('child_process').spawn('/usr/bin/script', ['-qfc', process.env['SHELL'] || '/bin/bash', '/dev/null'], { env, stdio: ['pipe', 'pipe', 'pipe'] });
      } else {
        proc = require('child_process').spawn(process.env['SHELL'] || '/bin/bash', ['-i'], { env, stdio: ['pipe', 'pipe', 'pipe'] });
      }
    } catch (e) { return null; }
  }
  ts.proc = proc;
  const feed = d => termBroadcast(ts, String(d));
  proc.stdout.on('data', feed);
  proc.stderr.on('data', feed);
  proc.on('error', () => { ts.dead = true; termBroadcast(ts, '\r\n[shell indisponible]\r\n'); });
  proc.on('exit', code => {
    if (TERMS.get(id) !== ts) return;
    ts.dead = true;
    termBroadcast(ts, '\r\n[shell termine (exit ' + code + ') - relance avec la commande start]\r\n');
    if (!ts.clients.size) TERMS.delete(id);
  });
  TERMS.set(id, ts);
  return ts;
}
// limite globale : vieux shells sans client fermes
setInterval(() => {
  for (const [id, ts] of TERMS) {
    if (ts.dead && !ts.clients.size) { TERMS.delete(id); continue; }
    if (!ts.dead && !ts.clients.size && Date.now() - ts.t0 > 3600000) termKill(ts);
  }
}, 60000);

// ---------- terminal groupe : cartes de commandes ----------
// pas de PTY partage brut : chaque commande est une carte signee du pseudo,
// type + description auto-detectes, sortie masquee par defaut chez les autres.
// Un seul point d'execution (cwd dedie) -> tout le monde recoit la meme carte,
// la transparence reste l'anti-triche ; les cartes sont l'anti-flood.
const GROUPCARDS = [];        // {id, by, cmd, type, desc, out, trunc, exit, run, t, ms}
const GROUPCLIENTS = new Set();
const GROUPRATE = new Map();  // handle -> { last, running }
const GROUPPROCS = new Map(); // card id -> child process (kill possible)
let GROUPEPOCH = 0;           // incremente a chaque reset : les clients polling detectent la purge
const GROUP_WORKDIR = path.join(DATA, 'groupws');
const GROUP_MAX_CARDS = 60, GROUP_OUT_MAX = 16000, GROUP_TIMEOUT = 60000, GROUP_COOLDOWN = 1500;
let groupRunning = 0;
try { fs.mkdirSync(GROUP_WORKDIR, { recursive: true }); } catch (e) {}
// isolation reelle (prevention) : chaque commande groupe tourne dans un
// conteneur docker jetable - systeme de fichiers de l image uniquement,
// seul le dossier de travail est monte (rw), outils du chasseur montes ro,
// caps droppes, quotas memoire/pids/cpu. config.json group_terminal.sandbox :
// 'auto' (docker si dispo, sinon hote), 'docker' (refuse si absent), 'none'.
function sandboxCfg() {
  try {
    const c = JSON.parse(fs.readFileSync(CFG_FILE, 'utf8'));
    if (c && c.group_terminal) return c.group_terminal;
  } catch (e) {}
  return { sandbox: 'auto', image: 'c2ff-sandbox', memory: '1g', pids: 256, cpus: '2', toolbin: 'go/bin' };
}
let _dockerOk = null; // cache : -1 non, sinon chemin ok
function dockerAvailable() {
  if (_dockerOk !== null) return _dockerOk === 1;
  try {
    if (!fs.existsSync('/var/run/docker.sock')) { _dockerOk = -1; return false; }
    const r = require('child_process').spawnSync('docker', ['version', '--format', 'ok'], { timeout: 5000 });
    _dockerOk = r.status === 0 ? 1 : -1;
  } catch (e) { _dockerOk = -1; }
  return _dockerOk === 1;
}
function sandboxSpawn(cmd) {
  const sc = sandboxCfg();
  const mode = sc.sandbox === 'auto' ? (dockerAvailable() ? 'docker' : 'host') : (sc.sandbox === 'docker' ? (dockerAvailable() ? 'docker' : null) : 'host');
  if (mode === null) return { err: 'sandbox docker demande mais indisponible - passe group_terminal.sandbox a auto/none' };
  if (mode === 'host') {
    return { mode, proc: require('child_process').spawn('/bin/bash', ['-c', cmd], { cwd: GROUP_WORKDIR, env: { ...process.env, TERM: 'dumb', HOME: GROUP_WORKDIR } }) };
  }
  const uid = typeof process.getuid === 'function' ? process.getuid() : 1000;
  const gid = typeof process.getgid === 'function' ? process.getgid() : 1000;
  const tool = path.join(ROOT, '..', sc.toolbin || 'go/bin'); // ~/go/bin monte en read-only
  const cname = 'c2ff-g-' + Date.now().toString(36) + Math.random().toString(36).slice(2, 5);
  const argv = ['run', '--rm', '--name', cname, '--user', uid + ':' + gid,
    '-v', GROUP_WORKDIR + ':/ws', '-w', '/ws',
    '--memory', String(sc.memory || '1g'), '--pids-limit', String(sc.pids || 256), '--cpus', String(sc.cpus || '2'),
    '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
    '-e', 'PATH=/opt/gobin:/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin',
    '-e', 'HOME=/ws', '-e', 'TERM=dumb', '-e', 'LANG=C.UTF-8'];
  try { if (fs.existsSync(tool)) argv.push('-v', tool + ':/opt/gobin:ro'); } catch (e) {}
  argv.push(String(sc.image || 'c2ff-sandbox'), '/bin/bash', '-c', cmd);
  return { mode, cname, proc: require('child_process').spawn('docker', argv, { cwd: GROUP_WORKDIR }) };
}
const CMD_DESC = {
  curl: 'requete HTTP', wget: 'telechargement HTTP', httpx: 'sonde HTTP', nc: 'connexion reseau brute', ncat: 'connexion reseau brute', socat: 'connexion reseau brute',
  nmap: 'scan de ports', masscan: 'scan de ports', rustscan: 'scan de ports', naabu: 'scan de ports',
  ffuf: 'fuzzing web', gobuster: 'fuzzing web', dirsearch: 'fuzzing web', feroxbuster: 'fuzzing web', wfuzz: 'fuzzing web',
  subfinder: 'enum sous-domaines', amass: 'enum sous-domaines', assetfinder: 'enum sous-domaines', findomain: 'enum sous-domaines',
  nuclei: 'scan de vulnerabilites', nikto: 'scan de vulnerabilites', dalfox: 'scan XSS', sqlmap: 'test injection SQL',
  dig: 'requete DNS', host: 'requete DNS', nslookup: 'requete DNS', whois: 'whois',
  hydra: 'attaque login', john: 'casse de hash', hashcat: 'casse de hash',
  ssh: 'shell distant', ping: 'diagnostic reseau', traceroute: 'diagnostic reseau', mtr: 'diagnostic reseau',
  ls: 'liste de fichiers', cat: 'lecture de fichier', head: 'lecture de fichier', tail: 'lecture de fichier', less: 'lecture de fichier', wc: 'comptage',
  grep: 'filtre de texte', rg: 'filtre de texte', awk: 'filtre de texte', sed: 'transformation de texte', cut: 'filtre de texte', sort: 'tri', uniq: 'dedoublonnage', tr: 'transformation de texte',
  find: 'recherche de fichiers', locate: 'recherche de fichiers', fd: 'recherche de fichiers',
  ps: 'processus', top: 'processus', htop: 'processus', ss: 'sockets reseau', netstat: 'sockets reseau', lsof: 'fichiers ouverts',
  python: 'script python', python3: 'script python', node: 'script node', php: 'script php', ruby: 'script ruby', perl: 'script perl', bash: 'script shell', sh: 'script shell',
  git: 'git', mkdir: 'creation de dossier', touch: 'creation de fichier', rm: 'suppression', mv: 'deplacement', cp: 'copie', ln: 'lien',
  chmod: 'permissions', chown: 'permissions', tar: 'archive', gzip: 'archive', gunzip: 'archive', unzip: 'archive', zip: 'archive',
  jq: 'traitement JSON', base64: 'encodage', openssl: 'crypto', xxd: 'hexdump', md5sum: 'hash', sha256sum: 'hash',
  docker: 'docker', npm: 'paquets node', pip: 'paquets python', pip3: 'paquets python', go: 'toolchain go', cargo: 'paquets rust',
  echo: 'affichage', printf: 'affichage', cd: 'navigation', pwd: 'navigation', history: 'historique', sudo: 'privileges root', env: 'variables d env', date: 'horloge',
};
const CMD_SKIP = new Set(['sudo', 'env', 'nohup', 'time', 'nice', 'command', 'xargs', 'stdbuf', 'timeout', 'watch']);
function cmdClass(cmd) {
  const toks = String(cmd).trim().split(/\s+/);
  let base = '';
  for (const w of toks) {
    if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(w)) continue; // VAR=x cmd
    const k = w.split('/').pop();
    if (CMD_SKIP.has(k)) continue;
    base = k; break;
  }
  const type = CMD_DESC[base] || ('commande ' + (base || '?'));
  let target = '';
  const url = cmd.match(/https?:\/\/[^\s'"]+/);
  if (url) target = url[0];
  else {
    const i = toks.indexOf(base);
    for (let j = i + 1; j < toks.length; j++) {
      if (toks[j].startsWith('-')) continue;
      target = toks[j].replace(/^['"]|['"]$/g, ''); break;
    }
  }
  return { type, desc: type + (target ? ' : ' + target.slice(0, 60) : '') };
}
function groupSend(c, payload) { try { c.res.write('data: ' + JSON.stringify(payload) + '\n\n'); } catch (e) {} }
function groupBroadcast(payload) { for (const c of GROUPCLIENTS) groupSend(c, payload); }

// ---------- programmes ----------
const DEFAULT_PROGRAMS = [
  { id: 'exemple', name: 'Exemple Program', platform: 'Bugcrowd', header: 'X-Bug-Bounty: <ton-handle>', scope: ['*.exemple.com'], creds: '', runs: [], demo: true },
];
const isDemo = p => !!(p && (p.demo || (p.scope || []).join(' ').includes('exemple.com')));
function loadPrograms() {
  const list = readJson(PROGRAMS_FILE, null);
  if (Array.isArray(list) && list.length) {
    // heuristique : un programme dont le scope vise exemple.com est un seed demo
    for (const p of list) if (isDemo(p)) p.demo = true;
    return list;
  }
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
// vide toutes les donnees recon d'un programme (stores keyed par prog.id)
const PURGE_FILES = ['surface.json', 'attack.json', 'plan.json', 'urls.json', 'jsint.json', 'modules.json', 'baseline.json', 'advanced_report.json', 'arsenal.json'];
function purgeProgData(id) {
  for (const f of PURGE_FILES) {
    const fp = path.join(DATA, f);
    let store; try { store = JSON.parse(fs.readFileSync(fp, 'utf8')); } catch (e) { continue; }
    if (!store || typeof store !== 'object' || !(id in store)) continue;
    delete store[id];
    try { fs.writeFileSync(fp, JSON.stringify(store, null, 1)); } catch (e) {}
  }
}

// ---------- moteur local FLEET-MODE (100% local, sans tokens) ----------
const fleet = require('./fleet.js');
const RECON = require('./recon.js');
const ATTACK = require('./attack.js');
const PLAN = require('./plan.js');
const ARSENAL = require('./arsenal.js');
const JSINT = require('./jsint.js');
const URLS = require('./urls.js');
const AUTH = require('./auth.js');
const MODULES = require('./modules.js');
const BASELINE = require('./baseline.js');
// config.json : bloc advanced_hacks (modes avances) - recharge a chaque
// lecture, les reglages sont editables sans restart
const CFG_FILE = path.join(ROOT, 'config.json');
const ADV_REPORT_FILE = path.join(DATA, 'advanced_report.json');
function advCfg() {
  try {
    const c = JSON.parse(fs.readFileSync(CFG_FILE, 'utf8'));
    if (c && c.advanced_hacks) return c.advanced_hacks;
  } catch (e) {}
  return { enabled: true, priority_filter: ['P1', 'P2'], budget: 60, base_gap_ms: 1000, timeouts: { BLIND_SQL: 15000, DNS_OOB: 8000, default: 10000 }, payloads_custom: {} };
}
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

// finding -> rapport markdown reproductible (regles PoC : 3 etapes max, " - ", defensible)
function pocMarkdown(f, prog) {
  const dash = s => String(s || '').replace(/[—–]/g, '-');
  let text = dash(f.text).trim();
  // un finding manuel est mono-ligne (le champ input) : on separe les commandes curl
  let lines = text.split('\n').map(l => l.trim()).filter(Boolean);
  if (lines.length === 1 && /curl\s/.test(lines[0])) {
    lines = lines[0].split(/ ; | (?=curl\s)/).map(l => l.trim()).filter(Boolean);
    text = lines.join('\n');
  }
  const title = (lines[0] || 'Finding').replace(/^#+\s*/, '').slice(0, 100);
  const rest = lines.slice(1);
  // etapes : lignes numerotees, tirets ou commandes curl ; sinon tout le corps = 1 bloc
  const steps = rest.filter(l => /^\d+[.)]\s/.test(l) || /^-\s/.test(l) || /^curl\s/.test(l));
  const curl = rest.filter(l => /^curl\s/.test(l));
  let md = '# [' + (f.sev || 'SIG') + '] ' + ((prog && prog.name) || f.program || 'programme') + ' - ' + title + '\n\n';
  const sum = rest.length ? rest.filter(l => !steps.includes(l)).join('\n') : text;
  md += '## Summary\n\n' + (sum || title) + '\n\n';
  md += '## Steps to reproduce\n\n';
  if (steps.length) md += steps.slice(0, 3).map((s, i) => (i + 1) + '. ' + s.replace(/^(\d+[.)]\s|-\s)/, '')).join('\n');
  else if (curl.length) md += '1. Executer :\n\n```\n' + curl[0] + '\n```';
  else md += '1. ' + text;
  md += '\n\n## Impact\n\n' + (f.sev === 'P1' ? 'acces non autorise a des donnees sensibles' : f.sev === 'P2' ? 'contourne une mesure de securite sur une surface reelle' : 'signal a confirmer avant soumission') + '\n\n';
  md += '---\n\n' + dash('program : ' + ((prog && prog.name) || f.program || '?') + ' | id : ' + (f.id || '?') + ' | run : ' + (f.run || '?') + ' | agent : ' + (f.agent || '?') + ' | date : ' + new Date(f.t).toISOString().slice(0, 16).replace('T', ' ')) + '\n';
  return md;
}
function readBody(req, cb) {
  let chunks = [], n = 0;
  req.on('data', c => { n += c.length; if (n < 2e6) chunks.push(c); });
  req.on('end', () => { try { cb(JSON.parse(Buffer.concat(chunks).toString() || '{}')); } catch (e) { cb({}); } });
}

function apiState(res, req) {
  const th = reqHandle(req);
  // salle ON + visiteur non valide : etat minimal, aucune donnee de chasse ne sort
  if (teamCfg().enabled && !isLoopback(req) && !memberRole(req, th)) {
    const t = teamCfg();
    const me = t.members[th];
    return sendJson(res, {
      now: new Date().toISOString(), runs: [], findings: [], programs: [], chat: [], fleet: null, modes: [],
      ai: { enabled: false, protocol: '', baseURL: '', model: '', ready: false },
      team: { enabled: true, room: t.room, bind: 'lan', you: 'pending', meRole: '', requests: [], members: [], online: 0, chat: [] },
      pendingMe: !!(me && me.status === 'pending'),
    });
  }
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
  // programmes : visibles si public (pub, meme sans le grade pour rejoindre),
  // ou si le grade suffit (access), ou si c'est le sien (owner/staff/local)
  const programs = isLoopback(req) ? loadPrograms() : (() => {
    const rk = RANKS[memberRole(req, th)] || 0;
    return loadPrograms().filter(pr => pr.pub === true
      || !pr.access || pr.access <= 1
      || (pr.owner && pr.owner === th) || rk >= pr.access);
  })();
  sendJson(res, {
    now: new Date().toISOString(), runs, findings: state.findings, programs, chat: lastChat(80),
    fleet: fleet.state(), modes: fleet.catalog(), team: teamState(req, th),
    ai: { enabled: ai.enabled, protocol: ai.protocol, baseURL: ai.baseURL, model: ai.model, ready: !!(ai.baseURL && ai.model) },
  });
}

const MAIN = (req, res) => {
  sweep();
  const url = new URL(req.url, 'http://x');
  const p = url.pathname;
  if (p.startsWith('/api/term')) {
    // debug temporaire : tracons l'acces des terminaux (qui, comment, resultats)
    console.log('[term]', req.method, p, 'ip=' + req.socket.remoteAddress, 'tun=' + !!req.internalTunnel,
      'h=' + JSON.stringify(req.headers['x-c2ff-handle'] || '') , 'q=' + (url.searchParams.get('handle') || '') + '/' + (url.searchParams.get('who') || '') + '/' + (url.searchParams.get('term') || ''),
      'k=' + (url.searchParams.get('k') || req.headers['x-c2ff-key'] || '') .slice(0, 12));
  }
  if (p.startsWith('/api/')) {
    if (!teamAllowed(req, url)) return send(res, 403, 'text/plain', 'team key required');
    // salle ON + non valide : seul /api/state repond (etat minimal), rien d'autre.
    // le handle arrive en header OU en query (les flux SSE ne peuvent pas poser de header)
    if (req.method === 'GET' && p !== '/api/state' && p !== '/index.html' && p !== '/' &&
        teamCfg().enabled && !isLoopback(req) &&
        !memberRole(req, reqHandle(req) || cleanHandle(url.searchParams.get('handle') || ''))) {
      return sendJson(res, { ok: false, error: 'acces en attente de validation' });
    }
  }

  if (req.method === 'GET' && p === '/api/surface') {
    const f = path.join(DATA, 'surface.json');
    try { return sendJson(res, JSON.parse(fs.readFileSync(f, 'utf8'))); } catch (e) { return sendJson(res, {}); }
  }

  if (req.method === 'GET' && p === '/api/attack') {
    const f = path.join(DATA, 'attack.json');
    try { return sendJson(res, JSON.parse(fs.readFileSync(f, 'utf8'))); } catch (e) { return sendJson(res, {}); }
  }

  // ---- MODES AVANCES : config + registry + baseline + rapport ----
  if (req.method === 'GET' && p === '/api/advanced') {
    const cfg = advCfg();
    const name = String(url.searchParams.get('name') || '').toLowerCase();
    let report = []; try { report = JSON.parse(fs.readFileSync(ADV_REPORT_FILE, 'utf8'))[name] || []; } catch (e) {}
    return sendJson(res, {
      cfg,
      modes: Object.entries(MODULES.ADV_MODES).map(([key, m]) => ({ key, label: key, ...m })),
      pools: fleet.planBudget(cfg.budget),
      baseline: BASELINE.stats(name),
      report,
    });
  }

  // ---- PLAN : hypotheses executables + statuts persistes par programme ----
  function hypProgram(name) {
    const progs = (() => { try { return JSON.parse(fs.readFileSync(PROGRAMS_FILE, 'utf8')); } catch (e) { return []; } })();
    const prog = progs.find(x => x.id === String(name || '').toLowerCase());
    if (!prog || isDemo(prog)) return null;
    let surf = {}; try { surf = JSON.parse(fs.readFileSync(path.join(DATA, 'surface.json'), 'utf8'))[prog.id] || {}; } catch (e) {}
    if (!surf.host) return { prog, surf: null };
    return { prog, surf };
  }
  if (req.method === 'GET' && p === '/api/plan') {
    const h = hypProgram(url.searchParams.get('program'));
    if (!h || !h.surf) return sendJson(res, { items: [] });
    let st = {}; try { st = JSON.parse(fs.readFileSync(path.join(DATA, 'plan.json'), 'utf8'))[h.prog.id] || {}; } catch (e) {}
    const items = PLAN.plan(h.surf, h.prog).map(it => {
      const r = st[it.k];
      it.status = r ? (r.status || '') : '';
      it.ev = r ? (r.ev || null) : null;
      return it;
    });
    return sendJson(res, { items });
  }

  // export PoC : un finding -> rapport markdown pret a coller (3 etapes max, pas de cadratin)
  if (req.method === 'GET' && p === '/api/poc') {
    const id = url.searchParams.get('id') || '';
    const f = state.findings.find(x => x.id === id || x.key === id);
    if (!f) return send(res, 404, 'text/plain; charset=utf-8', 'finding introuvable');
    const prog = loadPrograms().find(pp => String(pp.id || '').toLowerCase() === String(f.program || '').toLowerCase());
    return send(res, 200, 'text/markdown; charset=utf-8', pocMarkdown(f, prog));
  }

  // JS INTEL : endpoints + secrets + sourcemaps extraits des bundles (passif puis testable)
  if (req.method === 'GET' && p === '/api/jsint') {
    const name = String(url.searchParams.get('name') || '').toLowerCase();
    let all = {}; try { all = JSON.parse(fs.readFileSync(JSINT_FILE, 'utf8')); } catch (e) {}
    if (!name) return sendJson(res, { ok: true, all });
    const h = hypProgram(name);
    if (!h) return sendJson(res, { ok: false, err: 'programme introuvable' });
    return sendJson(res, { ok: true, prog: h.prog.id, res: all[h.prog.id] || null });
  }

  // URLS passives : wayback CDX + OTX, mining de params
  if (req.method === 'GET' && p === '/api/urls') {
    const name = String(url.searchParams.get('name') || '').toLowerCase();
    let all = {}; try { all = JSON.parse(fs.readFileSync(URLS_FILE, 'utf8')); } catch (e) {}
    if (!name) return sendJson(res, { ok: true, all });
    const h = hypProgram(name);
    if (!h) return sendJson(res, { ok: false, err: 'programme introuvable' });
    return sendJson(res, { ok: true, prog: h.prog.id, res: all[h.prog.id] || null });
  }

  // MODULES a preuve : REFLECT + AUTHZ, req+res captures, persistes par programme
  if (req.method === 'GET' && p === '/api/modules') {
    const name = String(url.searchParams.get('name') || '').toLowerCase();
    let all = {}; try { all = JSON.parse(fs.readFileSync(MODULES_FILE, 'utf8')); } catch (e) {}
    if (!name) return sendJson(res, { ok: true, all });
    const h = hypProgram(name);
    if (!h) return sendJson(res, { ok: false, err: 'programme introuvable' });
    return sendJson(res, { ok: true, prog: h.prog.id, res: all[h.prog.id] || null });
  }

  // AUTH : creds par programme (stockees dans programs.json), test avec/sans preuve
  if (req.method === 'GET' && p === '/api/auth') {
    const name = String(url.searchParams.get('name') || '').toLowerCase();
    const h = hypProgram(name);
    if (!h) return sendJson(res, { ok: false, err: 'programme introuvable' });
    const ap = AUTH.parse(h.prog.creds);
    return sendJson(res, { ok: true, prog: h.prog.id, creds: AUTH.mask(h.prog.creds), kinds: ap.kinds });
  }

  if (req.method === 'POST') {
    readBody(req, async body => {
      // graduations d'ecriture : observateur = lecture pure (meme pas le chat),
      // membre = chasse, co-admin = moderation (suppressions, creds), admin = config.
      // /api/team et /api/term gatent leurs ops en interne.
      const MINW = {
        '/api/chat': 1, '/api/queue': 1, '/api/findings': 1, '/api/jsint': 1, '/api/urls': 1,
        '/api/auth': 3, '/api/modules': 1, '/api/attack': 1, '/api/advanced': 1, '/api/planrun': 1,
        '/api/planpatch': 1, '/api/programs': 1, '/api/fast': 1, '/api/recon': 1, '/api/surface': 1,
        '/api/fleet': 1, '/api/arsenal': 1, '/api/ai': 1,
      };
      if (p !== '/api/team' && p !== '/api/term' && teamCfg().enabled && !isLoopback(req)) {
        // identite : le header x-c2ff-handle prime ; fallback body (name peut etre
        // un nom de PROGRAMME sur certains endpoints - ne jamais s'y fier en premier)
        const _r = memberRole(req, reqHandle(req) || cleanHandle(body.handle || body.by || body.name || ''));
        if (!_r) return sendJson(res, { ok: false, error: 'acces en attente de validation' });
        if ((RANKS[_r] || 0) < (MINW[p] === undefined ? 1 : MINW[p])) {
          return sendJson(res, { ok: false, error: _r === 'viewer' ? 'lecture seule (observateur)' : 'grade insuffisant pour cette action' });
        }
      }
      if (p === '/api/team') {
        // join : signup (pseudo libre + pin libre 4-32 caracteres) ou signin (pseudo connu + pin).
        // toute nouvelle entree passe en status pending : un admin/co-admin doit l'accepter.
        if (body.op === 'join') {
          const t = teamCfg();
          if (!t.enabled) return sendJson(res, { ok: false, error: 'salle inactive' });
          const h = cleanHandle(body.handle);
          const pin = String(body.pin || '');
          if (h.length < 2) return sendJson(res, { ok: false, error: 'pseudo requis (2 caracteres min)' });
          if (t.blocked.includes(h)) return sendJson(res, { ok: false, error: 'pseudo refuse' });
          // pin libre : 4 a 32 caracteres, sans espace (resiste au brute-force
          // meme si le pseudo est connu - chiffres seuls = 10^8 max, libre = astral)
          if (!/^\S{4,32}$/.test(pin)) return sendJson(res, { ok: false, error: 'pin : 4 a 32 caracteres, espaces interdits' });
          const m = t.members[h];
          // unicite stricte : un pseudo ACTIF dans la salle (beat < 25 s) ne peut
          // pas etre pris par quelqu'un d'autre - uniquement pour un pseudo encore
          // non inscrit (un inscrit se reconnecte via son pin, refresh compris)
          const _p = PRESENCE.get(h);
          if (!m && _p && Date.now() - _p.last < 25000) return sendJson(res, { ok: false, error: 'pseudo deja pris' });
          if (!m) {
            saveTeamCfg({ ...t, members: { ...t.members, [h]: { pin: hashPin(h, pin), role: 'member', status: 'pending', t: Date.now() } } });
            return sendJson(res, { ok: true, pending: true });
          }
          if (m.pin) {
            if (hashPin(h, pin) !== m.pin) return sendJson(res, { ok: false, error: 'pin errone pour ce pseudo' });
          } else {
            m.pin = hashPin(h, pin); // pseudo legacy sans pin : il le definit a la premiere connexion
            saveTeamCfg(t);
          }
          if (m.status !== 'approved') return sendJson(res, { ok: true, pending: true });
          return sendJson(res, { ok: true, joined: true, role: m.role });
        }
        // approve/deny : validation des demandes d'entree (rank >= co-admin).
        // deny : le pseudo est supprime ET bloque (pas de re-demande spam).
        if (body.op === 'approve' || body.op === 'deny') {
          const by = cleanHandle(body.by || body.handle);
          if (rankOf(req, by) < 3) return sendJson(res, { ok: false, error: 'admin ou co-admin requis' });
          const h = cleanHandle(body.h);
          const cur = teamCfg();
          const m = cur.members[h];
          if (!m || m.status !== 'pending') return sendJson(res, { ok: false, error: 'demande introuvable' });
          if (body.op === 'deny') {
            const members = { ...cur.members };
            delete members[h];
            saveTeamCfg({ ...cur, members, blocked: cur.blocked.filter(x => x !== h).concat([h]).slice(-50) });
            PRESENCE.delete(h);
          } else {
            // le grade peut etre choisi dans la ligne de demande au moment d'accepter
            const r = ['admin', 'coadmin', 'hunter', 'member', 'viewer'].includes(body.r) ? body.r : (m.role || 'member');
            saveTeamCfg({ ...cur, members: { ...cur.members, [h]: { ...m, role: r, status: 'approved' } } });
            if (PRESENCE.has(h)) PRESENCE.get(h).role = r;
          }
          return sendJson(res, { ok: true, team: teamState(req, by) });
        }
        // vote like/dislike sur un message du chat de session (toggle au re-clic)
        if (body.op === 'vote') {
          const by = cleanHandle(body.by || body.handle);
          if (rankOf(req, by) < 1) return sendJson(res, { ok: false, error: 'lecture seule (observateur)' });
          const id = String(body.id || '').slice(0, 60);
          if (!id) return sendJson(res, { ok: false, error: 'message introuvable' });
          const v = body.v === 'up' ? 1 : body.v === 'down' ? -1 : 0;
          const votes = loadVotes();
          const cur = votes[id] || {};
          if (!v || cur[by] === v) delete cur[by]; else cur[by] = v;
          if (Object.keys(cur).length) votes[id] = cur; else delete votes[id];
          saveVotes(votes);
          return sendJson(res, { ok: true });
        }
        // leave : changer de pseudo = l'ancienne identite quitte la session.
        // presence supprimee -> le pseudo sort de la liste instantanement (plus
        // de fantome actif ni de doublon). Uniquement SA propre identite (header
        // prime) ; l'inscription reste en base : connexion pseudo + pin pour revenir.
        if (body.op === 'leave') {
          const h = reqHandle(req) || cleanHandle(body.handle || '');
          if (!h) return sendJson(res, { ok: false, error: 'identite manquante' });
          if (isLoopback(req)) return sendJson(res, { ok: false, error: 'le poste local n a pas de session a quitter' });
          PRESENCE.delete(h);
          return sendJson(res, { ok: true });
        }
        // rename : changer de pseudo SANS repasser par la modal de connexion.
        // l'inscription (pin, grade, statut) est transferee vers le nouveau pseudo,
        // l'ancien est libere. unicite stricte : le nouveau doit etre libre
        // (ni inscrit, ni bloque, ni actif dans la salle).
        if (body.op === 'rename') {
          const h = reqHandle(req) || cleanHandle(body.handle || '');
          const nh = cleanHandle(body.nh);
          if (!h) return sendJson(res, { ok: false, error: 'identite manquante' });
          if (isLoopback(req)) return sendJson(res, { ok: false, error: 'le poste local n a pas de session a renommer' });
          if (nh.length < 2) return sendJson(res, { ok: false, error: 'pseudo requis (2 caracteres min)' });
          if (nh === h) return sendJson(res, { ok: false, error: 'pseudo identique' });
          const t = teamCfg();
          if (t.blocked.includes(nh)) return sendJson(res, { ok: false, error: 'pseudo refuse' });
          if (t.members[nh]) return sendJson(res, { ok: false, error: 'pseudo deja pris' });
          const _p = PRESENCE.get(nh);
          if (_p && Date.now() - _p.last < 25000) return sendJson(res, { ok: false, error: 'pseudo deja pris' });
          if (!t.members[h]) return sendJson(res, { ok: false, error: 'inscris-toi d abord (pseudo + pin)' });
          const role = t.members[h].role;
          const members = { ...t.members };
          members[nh] = { ...members[h], t: Date.now() };
          delete members[h];
          saveTeamCfg({ ...t, members });
          PRESENCE.delete(h);
          PRESENCE.set(nh, { last: Date.now(), reqs: (PRESENCE.get(nh) || { reqs: 0 }).reqs + 1, role });
          // anti-demaskage : tout ce qui a ete publie sous l'ancien pseudo suit
          // le nouveau nom - messages chat (name), findings (agent + tri), votes.
          // impossible de renommer pour faire disparaitre ses messages.
          try {
            const _ls = fs.readFileSync(CHAT_FILE, 'utf8').split('\n');
            const _out = [];
            let _ch = 0;
            for (const l of _ls) {
              if (!l.trim()) continue;
              try {
                const m = JSON.parse(l);
                if (m.name === h) { m.name = nh; _ch++; }
                _out.push(JSON.stringify(m));
              } catch (e) { _out.push(l); }
            }
            if (_ch) fs.writeFileSync(CHAT_FILE, _out.join('\n') + '\n');
          } catch (e) {}
          try {
            let _fch = 0;
            for (const f of state.findings) {
              if (f.agent === h) { f.agent = nh; _fch++; }
              if (Array.isArray(f.tri)) for (const tr of f.tri) if (tr.by === h) tr.by = nh;
            }
            if (_fch) {
              fs.writeFileSync(FINDINGS_FILE, state.findings.map(f => JSON.stringify(f)).join('\n') + '\n');
            }
          } catch (e) {}
          try {
            const votes = loadVotes();
            let _vch = false;
            for (const id of Object.keys(votes)) {
              if (votes[id] && votes[id][h] !== undefined) { votes[id][nh] = votes[id][h]; delete votes[id][h]; _vch = true; }
            }
            if (_vch) saveVotes(votes);
          } catch (e) {}
          return sendJson(res, { ok: true, renamed: true, role });
        }
        if (body.op === 'beat') {
          const h = cleanHandle(body.handle);
          if (h) {
            if (teamCfg().blocked.includes(h)) return sendJson(res, { ok: false, error: 'kicked from this room' });
            PRESENCE.set(h, { last: Date.now(), reqs: (PRESENCE.get(h) || { reqs: 0 }).reqs + 1, role: roleOf(req, h) });
          }
          const t = teamCfg();
          const me = t.members[h];
          return sendJson(res, {
            ok: true, team: teamState(req, h),
            me: !h || isLoopback(req) ? 'approved' : (me ? me.status : 'none'),
          });
        }
        if (body.op === 'rtc') {
          const from = cleanHandle(body.from) || 'invide';
          RTCMAP.set(from + ':' + body.typ + ':' + (body.to || '') + ':' + Date.now(),
            { from, to: cleanHandle(body.to) || '', typ: String(body.typ || '').slice(0, 8), data: String(body.data || '').slice(0, 8000), t: Date.now() });
          return sendJson(res, { ok: true });
        }
        // wispe : ouvre (ou retrouve) le chat prive entre deux membres.
        // accessible au couple uniquement - personne d'autre ne le voit,
        // pas meme la moderation. cap 24 chats prives, les plus anciens ferment.
        if (body.op === 'wsp') {
          const by = cleanHandle(body.by || body.handle);
          const to = cleanHandle(body.to || '');
          if (rankOf(req, by) < 1) return sendJson(res, { ok: false, error: 'membre requis' });
          if (!to || to === by) return sendJson(res, { ok: false, error: 'destinataire invalide' });
          const cur = teamCfg();
          if (!(cur.members || {})[to]) return sendJson(res, { ok: false, error: 'membre inconnu : ' + to });
          const pid = 'pm-' + [by, to].sort().join('--');
          if (!(cur.chats || []).find(c => c.id === pid)) {
            const pmKeep = (cur.chats || []).filter(c => (c.id || '').indexOf('pm-') === 0 && c.id !== pid).slice(-23);
            saveTeamCfg({
              ...cur,
              chats: [...(cur.chats || []).filter(c => (c.id || '').indexOf('pm-') !== 0), ...pmKeep, { id: pid, name: 'prive', min: 0, pm: [by, to].sort() }],
            });
          }
          return sendJson(res, { ok: true, ch: pid, team: teamState(req, by) });
        }
        // desactivation de la reception des wizz : accessible seulement apres
        // avoir deja recu au moins un wizz (le premier debloque le choix)
        if (body.op === 'wizzmute') {
          const by = cleanHandle(body.by || body.handle);
          const cur = teamCfg();
          const mm = (cur.members || {})[by];
          if (!mm) return sendJson(res, { ok: false, error: 'inscris-toi d abord (pseudo + pin)' });
          if (!(mm.wizz_rcv > 0)) return sendJson(res, { ok: false, error: 'recois d abord un wizz avant de pouvoir desactiver' });
          const mem2 = { ...cur.members, [by]: { ...mm, wizz_mute: body.mute !== false } };
          saveTeamCfg({ ...cur, members: mem2 });
          return sendJson(res, { ok: true, team: teamState(req, by) });
        }
        // welcome / pin / unpin : message de bienvenue + epinglage d'actu ou de
        // programme prioritaire, affiches dans le bandeau visible sur TOUS les
        // onglets. decision admin uniquement (le proprietaire, grade ultime, passe).
        if (body.op === 'welcome') {
          const by = cleanHandle(body.by || body.handle);
          if (rankOf(req, by) < 4) return sendJson(res, { ok: false, error: 'admin only' });
          const cur = teamCfg();
          saveTeamCfg({ ...cur, welcome: String(body.text || '').trim().slice(0, 200) });
          return sendJson(res, { ok: true, team: teamState(req, by) });
        }
        if (body.op === 'pin') {
          const by = cleanHandle(body.by || body.handle);
          if (rankOf(req, by) < 4) return sendJson(res, { ok: false, error: 'admin only' });
          const text = String(body.text || '').trim().slice(0, 200);
          const prog = String(body.prog || '').slice(0, 40);
          const style = ['accent', 'urgence', 'info', 'or'].includes(body.style) ? body.style : 'accent';
          const dur = Number(body.dur) > 0 ? Math.min(Number(body.dur), 2592000) : 0; // 0 = toujours, max 30 j
          const kind = body.kind === 'challenge' ? 'challenge' : 'pin'; // challenge = epreuve chronometree
          if (!text && !prog) return sendJson(res, { ok: false, error: 'rien a epingler' });
          const cur = teamCfg();
          const nid = Date.now().toString(36) + Math.random().toString(36).slice(2, 5);
          const news = (cur.news || [])
            .concat([{ id: nid, t: Date.now(), text, prog, style, kind, exp: dur ? Date.now() + dur * 1000 : 0 }])
            .slice(-3); // max 3 : le bandeau reste discret
          // registre de participation + limite de findings par participant :
          // challenge, ou epingle simple avec chat dedie (la limite cadre le chat)
          const chal = { ...(cur.chal || {}) };
          const lim = Math.max(0, Math.min(20, Math.floor(Number(body.lim) || 0))); // 0 = illimite
          if (kind === 'challenge' || body.evchat) chal[nid] = { limit: lim, parts: {} };
          // option "chat dedie a l'event" : un chat reserve aux participants,
          // ouvert a l'epingle et ferme avec elle (challenge ou epingle simple)
          let chats = [...(cur.chats || [])];
          if (body.evchat) {
            chats = chats.filter(c => c && c.id !== 'ev-' + nid)
              .concat([{ id: 'ev-' + nid, name: 'event ' + (prog || '').slice(0, 12), min: 0, event: nid }]).slice(-8);
          }
          saveTeamCfg({ ...cur, news, chal, chats });
          return sendJson(res, { ok: true, team: teamState(req, by) });
        }
        // chaljoin : le marqueur qui ATTACHE le membre au challenge (cote
        // serveur, incompressible). Sans participation, pas de findings envoyes
        // sur le programme du challenge ; avec, la limite s'applique a coup sur.
        if (body.op === 'chaljoin') {
          const h = reqHandle(req) || cleanHandle(body.handle || '');
          if (!h) return sendJson(res, { ok: false, error: 'identite manquante' });
          if (rankOf(req, h) < 1) return sendJson(res, { ok: false, error: 'membre requis pour participer' });
          const cur = teamCfg();
          const n = (cur.news || []).find(x => x.id === String(body.id || '') && (x.kind === 'challenge' || (cur.chal || {})[x.id]));
          if (!n) return sendJson(res, { ok: false, error: 'challenge introuvable ou termine' });
          const chal = { ...(cur.chal || {}) };
          const c = { limit: 0, parts: {}, ...(chal[n.id] || {}) };
          if (!c.parts[h]) c.parts = { ...c.parts, [h]: { t: Date.now(), finds: 0 } };
          chal[n.id] = c;
          saveTeamCfg({ ...cur, chal });
          return sendJson(res, { ok: true });
        }
        if (body.op === 'unpin') {
          const by = cleanHandle(body.by || body.handle);
          if (rankOf(req, by) < 4) return sendJson(res, { ok: false, error: 'admin only' });
          const cur = teamCfg();
          const id = String(body.id || '');
          // la croix du bandeau : on DE-EPINGLE seulement (le news quitte le
          // bandeau mais l'event reste vivant : chrono, participation, chat)
          saveTeamCfg({
            ...cur,
            news: (cur.news || []).map(n => n.id === id ? { ...n, pinned: false } : n),
          });
          return sendJson(res, { ok: true, team: teamState(req, by) });
        }
        // eventdel : suppression COMPLETE de l'event chez tout le monde (par id
        // ou par programme) - epingle, challenge, chat de l'event. Le createur
        // du programme passe aussi, meme sans grade admin.
        if (body.op === 'eventdel') {
          const by = cleanHandle(body.by || body.handle);
          const id = String(body.id || '');
          const prog = String(body.prog || '').slice(0, 40);
          const cur = teamCfg();
          const pr = loadPrograms().find(x => x.id === prog);
          const owner = pr && pr.owner === by;
          if (rankOf(req, by) < 4 && !owner) return sendJson(res, { ok: false, error: 'admin ou createur du programme requis' });
          const dead = (cur.news || []).filter(n => n.id === id || n.prog === prog).map(n => n.id);
          if (!dead.length) return sendJson(res, { ok: false, error: 'aucun event a supprimer' });
          saveTeamCfg({
            ...cur,
            news: (cur.news || []).filter(n => n.id !== id && n.prog !== prog),
            chal: Object.fromEntries(Object.entries(cur.chal || {}).filter(([k]) => !dead.includes(k))),
            chats: (cur.chats || []).filter(c => !c.event || !dead.includes(c.event)),
          });
          return sendJson(res, { ok: true, team: teamState(req, by) });
        }
        // chatadd / chatdel : la creation de chats est un droit de proprietaire
        // (le poste local) ; le grade minimum d'entree se choisit a la creation
        if (body.op === 'chatadd') {
          const by = cleanHandle(body.by || body.handle);
          if (rankOf(req, by) < 5) return sendJson(res, { ok: false, error: 'proprietaire uniquement' });
          const name = String(body.name || '').replace(/[<>]{1,}/g, '').trim().slice(0, 24);
          if (name.length < 2) return sendJson(res, { ok: false, error: 'nom trop court (2 caracteres min)' });
          const min = Math.max(0, Math.min(4, Math.floor(Number(body.min) || 0)));
          const cur = teamCfg();
          if ((cur.chats || []).filter(c => c.id !== 'session' && !c.event).length >= 6)
            return sendJson(res, { ok: false, error: 'maximum 6 chats personnels' });
          const cid = 'c' + Date.now().toString(36) + Math.random().toString(36).slice(2, 5);
          saveTeamCfg({ ...cur, chats: (cur.chats || []).concat([{ id: cid, name, min, event: '' }]) });
          return sendJson(res, { ok: true, team: teamState(req, by) });
        }
        if (body.op === 'chatdel') {
          const by = cleanHandle(body.by || body.handle);
          if (rankOf(req, by) < 5) return sendJson(res, { ok: false, error: 'proprietaire uniquement' });
          const cid = String(body.id || '');
          if (cid === 'session') return sendJson(res, { ok: false, error: 'le chat session est indestructible' });
          const cur = teamCfg();
          if (!(cur.chats || []).some(c => c.id === cid)) return sendJson(res, { ok: false, error: 'chat inconnu' });
          saveTeamCfg({ ...cur, chats: (cur.chats || []).filter(c => c.id !== cid) });
          return sendJson(res, { ok: true, team: teamState(req, by) });
        }
        // role.set : les 5 grades, decision admin uniquement (le poste local est admin)
        if (body.op === 'role.set') {
          const by = cleanHandle(body.by || body.handle);
          const myRk = rankOf(req, by);
          if (myRk < 4) return sendJson(res, { ok: false, error: 'admin ou proprietaire requis' });
          const cur = teamCfg();
          const h = cleanHandle(body.h);
          const r = ['admin', 'coadmin', 'hunter', 'member', 'viewer'].includes(body.r) ? body.r : 'member';
          if (!h) return sendJson(res, { ok: false, error: 'handle required' });
          // personne ne touche au grade d'un membre de rang >= au sien
          // (le proprietaire seul passe) ni au role owner, non assignable
          const tRk = RANKS[(cur.members[h] || {}).role] || 0;
          if (h === by) return sendJson(res, { ok: false, error: 'on ne modifie pas son propre grade' });
          if ((tRk >= myRk || RANKS[r] >= myRk) && myRk < 5)
            return sendJson(res, { ok: false, error: 'grade du membre trop eleve pour toi' });
          const members = { ...cur.members };
          members[h] = members[h] ? { ...members[h], role: r } : { pin: '', role: r, status: 'approved', t: Date.now() };
          saveTeamCfg({ ...cur, members });
          if (PRESENCE.has(h)) PRESENCE.get(h).role = r;
          return sendJson(res, { ok: true, team: teamState(req, by) });
        }
        // kick : admin ou co-admin -> le handle est bloque, son beat est refuse instantanement (re-cliquer debloque)
        if (body.op === 'kick') {
          const h = cleanHandle(body.h);
          if (rankOf(req, cleanHandle(body.by || body.handle)) < 3) return sendJson(res, { ok: false, error: 'admin ou co-admin requis' });
          if (!h) return sendJson(res, { ok: false, error: 'handle required' });
          const cur = teamCfg();
          saveTeamCfg({ ...cur, blocked: cur.blocked.filter(x => x !== h).concat(cur.blocked.includes(h) ? [] : [h]).slice(-50) });
          PRESENCE.delete(h);
          return sendJson(res, { ok: true, team: teamState(req, cleanHandle(body.by || body.handle)) });
        }
        if (body.op === 'config') {
          if (rankOf(req, cleanHandle(body.by || body.handle)) < 4) return sendJson(res, { ok: false, error: 'admin only' });
          const cur = teamCfg();
          saveTeamCfg({
            ...cur,
            enabled: typeof body.enabled === 'boolean' ? body.enabled : cur.enabled,
            room: typeof body.room === 'string' ? body.room.trim().slice(0, 32) : cur.room,
            key: cur.key || genKey(),
          });
          return sendJson(res, { ok: true, team: teamCfg() });
        }
        if (body.op === 'regen') {
          if (rankOf(req, cleanHandle(body.by || body.handle)) < 4) return sendJson(res, { ok: false, error: 'admin only' });
          const cur = teamCfg();
          saveTeamCfg({ ...cur, key: genKey() });
          return sendJson(res, { ok: true, team: teamCfg() });
        }
        // tunnel public opt-in : URL universelle (trycloudflare) pour les membres hors LAN.
        // le tunnel passe par un proxy local marque : ses requetes comptent comme DISTANTES,
        // elles passent donc par la cle de salle au lieu du bypass loopback.
        if (body.op === 'tunnel') {
          if (rankOf(req, cleanHandle(body.by)) < 4) return sendJson(res, { ok: false, error: 'admin only' });
          if (body.action === 'close') {
            if (TUNNEL) {
              try { TUNNEL.proxy.close(); } catch (e) {}
              try { TUNNEL.proc.kill('SIGTERM'); } catch (e) {}
            }
            TUNNEL = null;
            return sendJson(res, { ok: true, team: teamState(req) });
          }
          if (TUNNEL) return sendJson(res, { ok: true, team: teamState(req) });
          const proxy = http.createServer((q, s) => { q.internalTunnel = true; MAIN(q, s); });
          let pport = PORT + 2;
          proxy.on('error', e => {
            if (e.code === 'EADDRINUSE' && pport < PORT + 40) { pport += 1; setTimeout(() => proxy.listen(pport, '127.0.0.1'), 100); return; }
          });
          proxy.listen(pport, '127.0.0.1', () => {
            try {
              const proc = require('child_process').spawn('cloudflared', ['tunnel', '--url', 'http://127.0.0.1:' + proxy.address().port, '--no-autoupdate'], { stdio: ['ignore', 'pipe', 'pipe'] });
              TUNNEL = { proc, proxy, url: '' };
              const grab = d => { const m = /https:\/\/[a-z0-9-]+\.trycloudflare\.com/.exec(String(d)); if (m && TUNNEL && TUNNEL.proc === proc && !TUNNEL.url) TUNNEL.url = m[0]; };
              proc.stderr.on('data', grab); proc.stdout.on('data', grab);
              proc.on('error', () => { TUNNEL = { proc, proxy, url: '', err: 'cloudflared absent - installe-le (https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/)' }; });
              proc.on('exit', () => { if (TUNNEL && TUNNEL.proc === proc) { try { proxy.close(); } catch (e) {} TUNNEL = null; } });
              // auto-verification : le lien n'est declare OUVERT que lorsqu il repond pour de vrai
              const verify = n => {
                if (!TUNNEL || TUNNEL.proc !== proc || !TUNNEL.url || TUNNEL.ready) return;
                const rq = require('https').get(TUNNEL.url + '/api/state?k=' + teamCfg().key, { timeout: 5000 }, r => {
                  r.resume();
                  if (r.statusCode === 200) { TUNNEL.ready = true; return; }
                  rqretry(n);
                });
                rq.on('timeout', () => { rq.destroy(); });
                rq.on('error', () => rqretry(n));
              };
              const rqretry = n => { if (n > 0 && TUNNEL && TUNNEL.proc === proc && TUNNEL.url) setTimeout(() => verify(n - 1), 2000); };
              const _vwatch = setInterval(() => {
                if (!TUNNEL || TUNNEL.proc !== proc || TUNNEL.ready) return clearInterval(_vwatch);
                if (TUNNEL.url) verify(10);
              }, 2000);
            } catch (e) {}
          });
          return sendJson(res, { ok: true, team: teamState(req) });
        }
        // golive : le serveur se re-bind en 0.0.0.0 (respawn propre). shore : retour 127.0.0.1.
        // decision de bind = admin (poste local ou membre admin).
        if (body.op === 'golive' || body.op === 'shore') {
          if (rankOf(req, cleanHandle(body.by)) < 4) return sendJson(res, { ok: false, error: 'admin only' });
          const cur = teamCfg();
          if (!cur.enabled) return sendJson(res, { ok: false, error: 'enable the room first' });
          saveTeamCfg({ ...cur, live: body.op === 'golive' });
          try {
            require('child_process').spawn(process.execPath, process.argv.slice(1), { env: process.env, detached: true, stdio: 'ignore', cwd: ROOT }).unref();
          } catch (e) {}
          setTimeout(() => { try { process.exit(0); } catch (e) {} }, 250);
          return sendJson(res, { ok: true, restarting: true, team: { ...cur, live: body.op === 'golive' } });
        }
        return sendJson(res, { ok: false, error: 'unknown op' });
      }
      if (p === '/api/term') {
        // identite : le header prime (impossible d'ecrire/run sous le pseudo d'un autre)
        const h = cleanHandle(req.headers['x-c2ff-handle'] || body.handle || '');
        const group = body.term === 'group';
        if (!termTermAllowed(req, h, group)) return sendJson(res, { ok: false, error: group ? 'terminal de groupe : membre valide requis' : 'terminal perso : membre valide requis' });
        if (group) {
          // groupe = cartes : pas de PTY brut, une commande par requete
          if (body.op === 'kill') {
            for (const [cid, pr] of GROUPPROCS) {
              const k = GROUPCARDS.find(x => x.id === cid);
              if (k && k.by === (h || 'host')) {
                try { pr.proc.kill('SIGKILL'); } catch (e) {}
                if (pr.cname) { try { require('child_process').spawn('docker', ['kill', pr.cname], { stdio: 'ignore' }); } catch (e) {} }
              }
            }
            return sendJson(res, { ok: true });
          }
          // reset : admin/co-admin vide le terminal de groupe PARTOUT - cartes
          // supprimees cote serveur, commandes en cours tuees, et un signal
          // broadcast + epoch force chaque invite a vider sa vue (personne ne
          // conserve les logs apres un reset du proprietaire).
          if (body.op === 'reset') {
            if (rankOf(req, h) < 3) return sendJson(res, { ok: false, error: 'admin ou co-admin requis' });
            for (const [, pr] of GROUPPROCS) {
              try { pr.proc.kill('SIGKILL'); } catch (e) {}
              if (pr.cname) { try { require('child_process').spawn('docker', ['kill', pr.cname], { stdio: 'ignore' }); } catch (e) {} }
            }
            GROUPPROCS.clear();
            GROUPCARDS.length = 0;
            groupRunning = 0;
            GROUPRATE.clear();
            GROUPEPOCH++;
            groupBroadcast({ reset: true });
            return sendJson(res, { ok: true, epoch: GROUPEPOCH });
          }
          // share : publie une carte du terminal de groupe sur le chat de session
          // (commande + sortie) - le challenge se joue dans le chat, les membres
          // partagent leurs executions pour les faire voir de tous.
          if (body.op === 'share') {
            const card = GROUPCARDS.find(x => x.id === String(body.id || ''));
            if (!card) return sendJson(res, { ok: false, error: 'carte introuvable' });
            // un participant d'un event actif partage dans le chat de SON
            // event (la commande + sa sortie vont aux autres participants) ;
            // sinon le partage part dans le chat session comme avant.
            // le partage est un envoi comme un autre : il compte contre la
            // limite du participant (sinon contournement de la limite).
            let chid = 'session';
            const cur = teamCfg();
            const now = Date.now();
            const mine = (cur.news || []).filter(n => (!n.exp || n.exp > now)
              && (cur.chal || {})[n.id] && ((cur.chal[n.id].parts || {})[h] || rankOf(req, h) >= 4));
            const evn = mine[mine.length - 1];
            const evc = evn && (cur.chats || []).find(c => c.event === evn.id);
            if (evc) chid = evc.id;
            if (evc && rankOf(req, h) < 4) {
              const g = chalGate(cur, evn.id, h);
              if (g.err) return sendJson(res, { ok: false, error: g.err });
              if (g.cur2) saveTeamCfg(g.cur2);
            }
            // partage repliable : le chat client replie par defaut (cmd visible,
            // sortie deroulee sur clic, re-enroulable comme les findings)
            appendJsonl(CHAT_FILE, {
              t: Date.now(), id: Date.now().toString(36) + Math.random().toString(36).slice(2, 6), from: 'me',
              name: h || 'host', kind: 'term', text: 'terminal ▸ ' + card.cmd + (card.run ? ' (en cours)' : ''),
              out: (card.out || '').slice(0, 800) + (card.trunc ? '\n… sortie tronquee' : ''), ch: chid,
            });
            return sendJson(res, { ok: true });
          }
          if (body.op === 'run') {
            const cmd = String(body.cmd || '').replace(/\x00/g, '').slice(0, 2000).trim();
            if (!cmd) return sendJson(res, { ok: false, error: 'commande vide' });
            const now = Date.now();
            const rt = GROUPRATE.get(h) || { last: 0, running: 0 };
            if (rt.running) return sendJson(res, { ok: false, error: 'ta commande precedente tourne encore - Ctrl+C pour la couper' });
            if (now - rt.last < GROUP_COOLDOWN) return sendJson(res, { ok: false, error: 'anti-flood : patiente une seconde entre deux commandes' });
            if (groupRunning >= 3) return sendJson(res, { ok: false, error: '3 commandes deja en cours sur le groupe - attends une fin' });
            const cl = cmdClass(cmd);
            const sb = sandboxSpawn(cmd);
            if (sb.err) return sendJson(res, { ok: false, error: sb.err });
            const card = { id: now.toString(36) + Math.random().toString(36).slice(2, 6), by: h || 'host', cmd, type: cl.type, desc: cl.desc, out: '', trunc: false, exit: null, run: true, t: now, ms: 0, sbx: sb.mode };
            GROUPCARDS.push(card);
            while (GROUPCARDS.length > GROUP_MAX_CARDS) GROUPCARDS.shift();
            GROUPRATE.set(h, { last: now, running: 1 });
            groupRunning++;
            groupBroadcast({ card });
            let out = '';
            const proc = sb.proc;
            if (!proc || !proc.pid) {
              card.run = false; card.out = 'impossible de lancer la commande'; card.exit = -1;
              groupRunning = Math.max(0, groupRunning - 1);
              GROUPRATE.set(h, { last: now, running: 0 });
              groupBroadcast({ card });
              return sendJson(res, { ok: true, id: card.id });
            }
            GROUPPROCS.set(card.id, { proc, cname: sb.cname });
            const killOne = () => {
              try { proc.kill('SIGKILL'); } catch (e) {}
              if (sb.cname) { try { require('child_process').spawn('docker', ['kill', sb.cname], { stdio: 'ignore' }); } catch (e) {} }
            };
            const killTimer = setTimeout(killOne, GROUP_TIMEOUT);
            const feed = d => {
              if (out.length < GROUP_OUT_MAX) out += String(d);
              else card.trunc = true;
            };
            proc.stdout.on('data', feed);
            proc.stderr.on('data', feed);
            proc.on('error', () => {});
            proc.on('close', code => {
              clearTimeout(killTimer);
              GROUPPROCS.delete(card.id);
              card.out = out.slice(0, GROUP_OUT_MAX);
              card.exit = code;
              card.run = false;
              card.ms = Date.now() - now;
              groupRunning = Math.max(0, groupRunning - 1);
              const rt2 = GROUPRATE.get(h);
              if (rt2) rt2.running = 0;
              groupBroadcast({ card });
            });
            return sendJson(res, { ok: true, id: card.id });
          }
          return sendJson(res, { ok: false, error: 'op terminal groupe inconnu' });
        }
        const id = termId(req, h);
        if (body.op === 'start') {
          const ts = termSpawn(id);
          return sendJson(res, ts ? { ok: true } : { ok: false, error: 'cannot spawn shell' });
        }
        if (body.op === 'write') {
          const ts = TERMS.get(id);
          if (!ts || ts.dead) return sendJson(res, { ok: false, error: 'no shell - send op start first' });
          const data = String(body.data || '').slice(0, 4000);
          try { ts.proc.stdin.write(data); return sendJson(res, { ok: true }); }
          catch (e) { return sendJson(res, { ok: false, error: 'shell stdin closed' }); }
        }
        if (body.op === 'exit') {
          const ts = TERMS.get(id);
          if (ts) termKill(ts);
          for (const c of ts ? ts.clients : []) { try { c.res.end(); } catch (e) {} }
          if (ts) ts.clients.clear();
          TERMS.delete(id);
          return sendJson(res, { ok: true });
        }
        return sendJson(res, { ok: false, error: 'unknown op' });
      }
      if (p === '/api/chat') {
        const _ch = cleanHandle(req.headers['x-c2ff-handle'] || body.name);
        const _teamKind = body.kind === 'team' || body.kind === 'finding' || body.kind === 'wizz';
        // chat cible : un message ne part que dans un chat accessible (grade
        // suffisant, ou participant pour un chat d'event) - verification serveur
        let _cid = 'session';
        const _cur = _teamKind ? teamCfg() : null;
        if (_teamKind) {
          const rk0 = rankOf(req, _ch);
          const cc = (_cur.chats || []).find(c => c.id === String(body.ch || 'session').slice(0, 32));
          if (!cc) return sendJson(res, { ok: false, error: 'chat inconnu' });
          if (!chatOk(cc.event ? { ...cc, _parts: ((_cur.chal || {})[cc.event] || {}).parts || {} } : cc, _ch, rk0))
            return sendJson(res, { ok: false, error: cc.event ? 'chat reserve aux participants de l event' : 'grade insuffisant pour ce chat' });
          _cid = cc.id;
        }
        // wizz (nudge MSN) - regles serrees, enforcees serveur :
        // chat de session (et tout chat non prive) : admin et proprietaire
        // SEULEMENT - admin 1 wizz / 3 min, proprietaire 1 wizz / min ;
        // chat prive : possible seulement si la conversation est deja entamee
        // (au moins un message dans le canal), chaque participant, 1/30 s,
        // et refuse si le destinataire a desactive la reception des wizz.
        if (body.kind === 'wizz') {
          const nw = Date.now();
          if (_cid.indexOf('pm-') === 0) {
            const _started = lastChat(200).some(m => m.ch === _cid);
            if (!_started) return sendJson(res, { ok: false, error: 'wizz possible seulement dans une conversation privee deja entamee' });
            const _peer = _cid.slice(3).split('--').find(x => x !== _ch);
            if (_peer && ((_cur.members || {})[_peer] || {}).wizz_mute)
              return sendJson(res, { ok: false, error: _peer + ' a desactive la reception des wizz' });
            if (nw - (WIZZRATE.get(_cid) || 0) < 30000)
              return sendJson(res, { ok: false, error: 'un wizz toutes les 30 secondes maximum en prive' });
            WIZZRATE.set(_cid, nw);
          } else {
            const _rkw = rankOf(req, _ch);
            if (_rkw < 4) return sendJson(res, { ok: false, error: 'wizz reserve aux admins et au proprietaire' });
            const _win = _rkw >= 5 ? 60000 : 180000;
            const _last = WIZZRATE.get(_ch) || 0;
            if (nw - _last < _win)
              return sendJson(res, { ok: false, error: 'prochain wizz dans ' + Math.ceil((_win - (nw - _last)) / 1000) + ' s' });
            WIZZRATE.set(_ch, nw);
          }
          // compteur de wizz recus : le premier wizz recu debloque chez chacun
          // le choix de desactiver (ou non) la reception
          const _targets = _cid.indexOf('pm-') === 0
            ? [_cid.slice(3).split('--').find(x => x !== _ch)].filter(Boolean)
            : Object.keys(_cur.members || {}).filter(x => x !== _ch
              && ((_cur.members || {})[x] || {}).status === 'approved');
          const _mem2 = { ..._cur.members };
          let _touched = false;
          for (const _hh of _targets) {
            const _m0 = _mem2[_hh];
            if (!_m0 || typeof _m0 !== 'object') continue;
            _mem2[_hh] = { ..._m0, wizz_rcv: (_m0.wizz_rcv || 0) + 1 };
            _touched = true;
          }
          if (_touched) saveTeamCfg({ ..._cur, members: _mem2 });
        }
        // limite de findings par participant, avec le marqueur de participation
        // (op chaljoin), sans contournement possible - trois portes verrouillees :
        // 1) TOUT message poste dans le chat de l'event compte (la zone de jeu :
        //    limite 1 = un seul envoi, point)
        // 2) un finding partage avec le programme d'un event compte, meme poste
        //    dans un autre chat. Identite = header PRIME (changer le nom dans la
        //    requete est inoperant), increment atomique avec le message ;
        //    l'admin et le proprietaire ne sont jamais limites.
        if (_cur && body.kind !== 'wizz' && rankOf(req, _ch) < 4) {
          const evc = (_cur.chats || []).find(c => c.id === _cid && c.event);
          const nid = evc ? evc.event
            : (body.kind === 'finding' && body.prog
              ? ((_cur.news || []).find(x => (_cur.chal || {})[x.id] && x.prog === String(body.prog).slice(0, 40)) || {}).id
              : null);
          if (nid) {
            const g = chalGate(_cur, nid, _ch);
            if (g.err) return sendJson(res, { ok: false, error: g.err });
            if (g.cur2) saveTeamCfg(g.cur2);
          }
        }
        const msg = {
          t: Date.now(), id: Date.now().toString(36) + Math.random().toString(36).slice(2, 6), from: 'me',
          name: cleanHandle(body.name) || 'OPERATOR',
          kind: body.kind === 'team' ? 'team' : (body.kind === 'finding' ? 'finding' : (body.kind === 'wizz' ? 'wizz' : 'chat')),
          text: trunc(body.text || '', 4000),
          ch: _cid,
        };
        if (body.fkey) msg.fkey = String(body.fkey).slice(0, 100);
        if (body.prog) msg.prog = String(body.prog).slice(0, 40); // programme partage : bouton rejoindre sur le chat
        if (['P1', 'P2', 'P3', 'HIT', 'SIG'].includes(body.sev)) msg.sev = body.sev;
        appendJsonl(CHAT_FILE, msg);
        return sendJson(res, { ok: true });
      }
      if (p === '/api/queue') {
        appendJsonl(CHAT_FILE, { t: Date.now(), from: 'me', kind: 'queue', playbook: body.playbook || '', program: body.program || '', note: trunc(body.note || '', 1000) });
        return sendJson(res, { ok: true });
      }
      if (p === '/api/findings') {
        if (body.op === 'delete' && body.key) {
          if (rankOf(req, cleanHandle(body.name || body.by)) < 3) return sendJson(res, { ok: false, error: 'admin ou co-admin requis' });
          const i = state.findings.findIndex(x => x.key === body.key);
          if (i >= 0) state.findings.splice(i, 1);
          persistFindings();
          return sendJson(res, { ok: true });
        }
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
          text: (s => { s = String(s == null ? '' : s).trim(); return s.length > 400 ? s.slice(0, 400) + '…' : s; })(body.text), status: 'analyse',
        });
        return sendJson(res, { ok: true });
      }
      // ---- JS INTEL : telecharge les bundles et extrait endpoints/secrets/sourcemaps ----
      if (p === '/api/jsint') {
        if (body.op === 'run') {
          const name = String(body.name || '').toLowerCase();
          const progs = loadPrograms();
          const prog = progs.find(x => x.id === name) || progs.find(x => String(x.name || '').toLowerCase() === name);
          if (!prog) return sendJson(res, { ok: false, err: 'programme introuvable' });
          if (isDemo(prog)) return sendJson(res, { ok: false, demo: true, err: 'programme de demonstration : cree ton programme avec ton vrai scope' });
          let surf = {}; try { surf = JSON.parse(fs.readFileSync(path.join(DATA, 'surface.json'), 'utf8'))[prog.id] || null; } catch (e) {}
          if (!surf) return sendJson(res, { ok: false, err: 'recon requis : lance RECON avant JS INTEL' });
          return JSINT.jsint(surf, prog, out => {
            try {
              const all = JSON.parse(fs.readFileSync(JSINT_FILE, 'utf8'));
              all[prog.id] = out;
              fs.writeFileSync(JSINT_FILE, JSON.stringify(all, null, 1));
            } catch (e) {
              fs.writeFileSync(JSINT_FILE, JSON.stringify({ [prog.id]: out }, null, 1));
            }
            sendJson(res, { ok: true, prog: prog.id, res: out });
          });
        }
        return sendJson(res, { ok: false });
      }

      // ---- URLS passives : wayback CDX + OTX, mining de params ----
      if (p === '/api/urls') {
        if (body.op === 'run') {
          const name = String(body.name || '').toLowerCase();
          const progs = loadPrograms();
          const prog = progs.find(x => x.id === name) || progs.find(x => String(x.name || '').toLowerCase() === name);
          if (!prog) return sendJson(res, { ok: false, err: 'programme introuvable' });
          if (isDemo(prog)) return sendJson(res, { ok: false, demo: true, err: 'programme de demonstration : cree ton programme avec ton vrai scope' });
          let surf = {}; try { surf = JSON.parse(fs.readFileSync(path.join(DATA, 'surface.json'), 'utf8'))[prog.id] || null; } catch (e) {}
          if (!surf || !surf.host) return sendJson(res, { ok: false, err: 'recon requis : lance RECON avant URLS' });
          return URLS.urls(surf, prog, out => {
            try {
              const all = JSON.parse(fs.readFileSync(URLS_FILE, 'utf8'));
              all[prog.id] = out;
              fs.writeFileSync(URLS_FILE, JSON.stringify(all, null, 1));
            } catch (e) {
              fs.writeFileSync(URLS_FILE, JSON.stringify({ [prog.id]: out }, null, 1));
            }
            sendJson(res, { ok: true, prog: prog.id, res: out });
          });
        }
        return sendJson(res, { ok: false });
      }

      // ---- AUTH : creds par programme, test avec/sans preuve ----
      if (p === '/api/auth') {
        const name = String(body.name || '').toLowerCase();
        const progs = loadPrograms();
        const idx = progs.findIndex(x => x.id === name || String(x.name || '').toLowerCase() === name);
        if (idx < 0) return sendJson(res, { ok: false, err: 'programme introuvable' });
        const prog = progs[idx];
        if (isDemo(prog)) return sendJson(res, { ok: false, demo: true, err: 'programme de demonstration : cree ton programme avec ton vrai scope' });
        if (body.op === 'save') {
          progs[idx].creds = String(body.creds == null ? '' : body.creds).slice(0, 4000);
          try { fs.writeFileSync(PROGRAMS_FILE, JSON.stringify(progs, null, 1)); } catch (e) { return sendJson(res, { ok: false, err: 'ecriture impossible' }); }
          const ap = AUTH.parse(progs[idx].creds);
          return sendJson(res, { ok: true, prog: prog.id, creds: AUTH.mask(progs[idx].creds), kinds: ap.kinds });
        }
        if (body.op === 'test') {
          return AUTH.probe(prog, String(body.target || '').trim() || null, r => sendJson(res, r));
        }
        return sendJson(res, { ok: false });
      }

      // ---- MODULES a preuve : REFLECT / AUTHZ, req+res captures, P2 injectees en findings ----
      if (p === '/api/modules') {
        if (body.op === 'reflect' || body.op === 'authz') {
          const name = String(body.name || '').toLowerCase();
          const progs = loadPrograms();
          const prog = progs.find(x => x.id === name) || progs.find(x => String(x.name || '').toLowerCase() === name);
          if (!prog) return sendJson(res, { ok: false, err: 'programme introuvable' });
          if (isDemo(prog)) return sendJson(res, { ok: false, demo: true, err: 'programme de demonstration : cree ton programme avec ton vrai scope' });
          let surf = {}; try { surf = JSON.parse(fs.readFileSync(path.join(DATA, 'surface.json'), 'utf8'))[prog.id] || null; } catch (e) {}
          if (!surf || !surf.host) return sendJson(res, { ok: false, err: 'recon requis : lance RECON avant ' + body.op.toUpperCase() });
          // extras : urls de l historique (URLS) + endpoints de surface, params des deux sources
          let ustore = {}; try { ustore = JSON.parse(fs.readFileSync(URLS_FILE, 'utf8'))[prog.id] || {}; } catch (e) {}
          const urls = [...new Set([...(ustore.urls || []), ...(surf.apis || [])])].slice(0, 600);
          const pm = {};
          for (const p2 of (surf.params || [])) pm[p2] = (pm[p2] || 0) + 1;
          for (const pp of (ustore.params || [])) pm[pp.p] = pp.n;
          const params = Object.entries(pm).map(([p2, n]) => ({ p: p2, n }));
          const hhAuth = AUTH.hdrsFor(prog);
          const hhBase = {};
          if (prog.header && prog.header.includes(':')) { const i2 = prog.header.indexOf(':'); hhBase[prog.header.slice(0, i2).trim()] = prog.header.slice(i2 + 1).trim(); }
          const fin = out => {
            try {
              const all = JSON.parse(fs.readFileSync(MODULES_FILE, 'utf8'));
              all[prog.id] = Object.assign({}, all[prog.id] || {}, { [body.op]: out });
              fs.writeFileSync(MODULES_FILE, JSON.stringify(all, null, 1));
            } catch (e) {
              try { fs.writeFileSync(MODULES_FILE, JSON.stringify({ [prog.id]: { [body.op]: out } }, null, 1)); } catch (e2) {}
            }
            // injection des P2 defendables en findings (la preuve req+res est dans le texte)
            const cands = out.candidates || [];
            for (const c of cands) {
              for (const t of (c.tests || [{ kind: c.kind, sev: c.sev, req: c.req, res: c.res, verdict: c.kind === 'raw' ? 'reflechi brut (XSS candidat)' : 'reflechi encode' }])) {
                if (t.sev !== 'P2') continue;
                const key = 'mod:' + body.op + ':' + prog.id + ':' + (c.param || c.url).toLowerCase().slice(0, 100);
                if (state.findings.some(x => x.key === key)) continue;
                state.seq++;
                const txt = body.op === 'reflect'
                  ? '[REFLECT] param ' + c.param + ' : ' + t.verdict + '\nPoC (3 etapes) : 1) ' + t.req + ' 2) observe la reponse : ' + t.res.status + ', contexte : ' + t.res.excerpt + ' 3) construis un payload complet et demontre l execution JS'
                  : '[AUTHZ] ' + c.url + ' : ' + t.verdict + '\nPoC (3 etapes) : 1) ' + t.req + ' 2) observe la reponse : ' + t.without.status + ', ' + t.without.len + ' o (reference avec creds : ' + t.with.status + ', ' + t.with.len + ' o) 3) confirme que la donnee appartient a un autre utilisateur / devrait etre protegee';
                state.findings.unshift({
                  key, id: 'F' + String(state.seq).padStart(4, '0'), t: Date.now(),
                  program: prog.id, run: 'MOD-' + body.op.toUpperCase(), agent: 'C2FF', sev: 'P2', status: 'analyse',
                  text: trunc(txt, 600),
                });
                persistFindings();
              }
            }
            sendJson(res, { ok: true, prog: prog.id, res: out });
          };
          if (body.op === 'reflect') return MODULES.reflect(surf, prog, hhAuth, { urls, params }, fin);
          return MODULES.authz(surf, prog, hhAuth, hhBase, { urls }, fin);
        }
        return sendJson(res, { ok: false });
      }

      // ---- ATTACK : probes ciblees sur la surface reconnee, candidates avec preuve ----
      if (p === '/api/attack') {
        const name = String(body.name || '').toLowerCase();
        const progs = (() => { try { return JSON.parse(fs.readFileSync(PROGRAMS_FILE, 'utf8')); } catch (e) { return []; } })();
        const prog = progs.find(x => x.id === name) || progs.find(x => String(x.name || '').toLowerCase() === name);
        if (!prog) return sendJson(res, { ok: false, err: 'programme introuvable' });
        if (isDemo(prog)) return sendJson(res, { ok: false, demo: true, err: 'programme de demonstration : cree ton programme avec ton vrai scope' });
        let surf = {}; try { surf = JSON.parse(fs.readFileSync(path.join(DATA, 'surface.json'), 'utf8'))[prog.id] || null; } catch (e) {}
        if (!surf) return sendJson(res, { ok: false, err: 'recon requis : lance RECON avant ATTACK' });
        let hh = AUTH.hdrsFor(prog);
        ATTACK.attack(surf, hh, null).then(a => {
          a.host = surf.host; a.program = prog.id;
          // injection des P1/P2 dans les findings (dossiers du programme), le texte porte la preuve
          for (const f of (a.findings || []).filter(x => x.sev === 'P1' || x.sev === 'P2')) {
            const key = 'atk:' + f.sev + ':' + f.mod + ':' + Buffer.from(f.title).toString('hex').slice(0, 24);
            if (state.findings.some(x => x.key === key)) continue;
            state.seq++;
            state.findings.unshift({
              key, id: 'F' + String(state.seq).padStart(4, '0'), t: Date.now(),
              program: prog.id, run: 'ATK', agent: 'C2FF', sev: f.sev, status: 'analyse',
              text: trunc('[' + f.mod + '] ' + f.title + '\nPoC (3 etapes) : 1) curl -si "' + surf.host + f.req.slice(3) + '" 2) observe la reponse : ' + f.res + ' 3) confirme l exploitabilite (validite du secret / acces authentifie)', 400),
            });
            persistFindings();
          }
          const f2 = path.join(DATA, 'attack.json');
          let store = {}; try { store = JSON.parse(fs.readFileSync(f2, 'utf8')); } catch (e) {}
          store[prog.id] = a;
          try { fs.writeFileSync(f2, JSON.stringify(store, null, 1)); } catch (e) {}
          sendJson(res, { ok: true, attack: a });
        }).catch(() => sendJson(res, { ok: false, err: 'attack echouee' }));
        return;
      }
      // ---- MODES AVANCES : capture baseline + run budgete ----
      if (p === '/api/advanced') {
        const op = String(body.op || 'run');
        const name = String(body.name || '').toLowerCase();
        const progs = (() => { try { return JSON.parse(fs.readFileSync(PROGRAMS_FILE, 'utf8')); } catch (e) { return []; } })();
        const prog = progs.find(x => x.id === name) || progs.find(x => String(x.name || '').toLowerCase() === name);
        if (!prog) return sendJson(res, { ok: false, err: 'programme introuvable' });
        if (isDemo(prog)) return sendJson(res, { ok: false, demo: true, err: 'programme de demonstration : cree ton programme avec ton vrai scope' });
        let surf = {}; try { surf = JSON.parse(fs.readFileSync(path.join(DATA, 'surface.json'), 'utf8'))[prog.id] || null; } catch (e) {}
        if (!surf) return sendJson(res, { ok: false, err: 'recon requis : lance RECON avant les modes avances' });
        const hh = AUTH.hdrsFor(prog);
        const cfgA = advCfg();
        if (!cfgA.enabled) return sendJson(res, { ok: false, err: 'advanced_hacks desactive dans config.json' });
        // base du programme : scheme du scope si present, sinon https
        const sc = (prog.scope || []).find(s => /^https?:\/\//.test(s));
        const base = sc ? sc.replace(/\/+$/, '') : (surf.base || 'https://' + String(surf.host || '').replace(/\/+$/, ''));

        // op baseline : capture des reponses propres (max 8 endpoints), cache data/baseline.json
        // cle = endpoint EXACT tel que les modes le reference (query incluse)
        if (op === 'baseline') {
          const eps = [...new Set(['/', ...(surf.apis || [])])].slice(0, 8);
          const done = [];
          for (const ep of eps) {
            const r = await ATTACK.areq(base + ep, { hdrs: hh, timeout: cfgA.timeouts && cfgA.timeouts.default || 10000 });
            if (r.code > 0) { BASELINE.setBaseline(prog.id, ep, r); done.push(ep); }
          }
          return sendJson(res, { ok: true, captured: done, baseline: BASELINE.stats(prog.id) });
        }
        // op run : 12 modes budgetes (P1 50% / P2 30% / P3 20% de 60 req)
        const modes = Array.isArray(body.modes) && body.modes.length ? body.modes : Object.keys(MODULES.ADV_MODES);
        ATTACK.advancedRun(surf, prog, hh, modes, { advanced_hacks: { ...cfgA, payloads_custom: { ...cfgA.payloads_custom } } }, m => {
          appendJsonl(CHAT_FILE, { t: Date.now(), from: 'me', kind: 'chat', name: 'ADV', text: trunc(String(m), 300) });
        }).then(async out => {
          // rapport persiste : une entree par alerte {mode, payload, status, evidence}
          let store = {}; try { store = JSON.parse(fs.readFileSync(ADV_REPORT_FILE, 'utf8')); } catch (e) {}
          const entries = out.alerts.map(a => ARSENAL.enrichAlert(a));
          store[prog.id] = entries;
          try { fs.writeFileSync(ADV_REPORT_FILE, JSON.stringify(store, null, 1)); } catch (e) {}
          // injection findings P1/P2 (3 etapes : curl / observe / confirme)
          for (const a of entries.filter(x => x.sev === 'P1' || x.sev === 'P2')) {
            const key = 'adv:' + a.mode + ':' + Buffer.from(a.title).toString('hex').slice(0, 20);
            if (state.findings.some(x => x.key === key)) continue;
            state.seq++;
            state.findings.unshift({
              key, id: 'F' + String(state.seq).padStart(4, '0'), t: Date.now(),
              program: prog.id, run: 'ADV', agent: 'ADV-' + a.mode, sev: a.sev, status: 'analyse',
              text: trunc('[' + a.mode + ' / CWE ' + a.cwe + '] ' + a.title + '\nPoC (3 etapes) : 1) ' + (a.payload || 'voir mode') + ' sur ' + a.mode + ' (curl equivalente dans le rapport) 2) statut ' + a.status + ' : ' + a.evidence + ' 3) confirme l exploitabilite manuellement', 600),
            });
            persistFindings();
          }
          // nuclei auto pour les alertes P1 (NO_SQLI, JWT_ADV, BLIND_SQL)
          const p1modes = [...new Set(entries.filter(x => x.sev === 'P1').map(x => x.mode))].filter(m => ARSENAL.ADV_TAGS[m]);
          for (const m of p1modes) {
            const outN = await ARSENAL.nucleiForAlert(base, m, hh.authorization ? ['Authorization: ' + hh.authorization] : hh.cookie ? ['Cookie: ' + hh.cookie] : []);
            if (outN) {
              entries.push({ mode: m + ':nuclei', sev: 'SIG', payload: 'nuclei -tags ' + ARSENAL.ADV_TAGS[m], status: 0, evidence: trunc(outN, 260), ref: 'scan automatique post-alerte P1' });
            }
          }
          if (p1modes.length) { store[prog.id] = entries; try { fs.writeFileSync(ADV_REPORT_FILE, JSON.stringify(store, null, 1)); } catch (e) {} }
          sendJson(res, { ok: true, res: out, report: entries });
        }).catch(e => sendJson(res, { ok: false, err: 'advanced echec : ' + (e && e.message || e) }));
        return;
      }
      // ---- PLAN : hypotheses du RECON, exec GET only + preuve capturee ----
      if (p === '/api/planrun') {
        const h = hypProgram(body.name);
        if (!h) return sendJson(res, { ok: false, err: 'programme introuvable' });
        if (!h.surf) return sendJson(res, { ok: false, err: 'recon requis' });
        const it = PLAN.plan(h.surf, h.prog).find(x => x.k === String(body.k || ''));
        if (!it || !it.run) return sendJson(res, { ok: false, err: 'hypothesis non executable' });
        let hh = { 'user-agent': 'Mozilla/5.0 (C2FF-plan)' };
        if (h.prog.header && h.prog.header.includes(':')) { const i2 = h.prog.header.indexOf(':'); hh[h.prog.header.slice(0, i2).trim()] = h.prog.header.slice(i2 + 1).trim(); }
        for (const line of it.hdrs || []) { const i3 = line.indexOf(':'); if (i3 > 0) hh[line.slice(0, i3).trim()] = line.slice(i3 + 1).trim(); }
        const url2 = 'https://' + h.surf.host + it.u;
        https.get(url2, { headers: hh, timeout: 6000 }, r => {
          let raw = ''; let len2 = 0;
          r.on('data', d => { len2 += d.length; if (len2 <= 60000) raw += d; else r.destroy(); });
          r.on('end', () => {
            const ev = { code: r.statusCode || 0, len: len2, res: trunc(String(raw).replace(/\s+/g, ' ').trim(), 200), u: it.u, t: Date.now() };
            const s = (() => { try { return JSON.parse(fs.readFileSync(path.join(DATA, 'plan.json'), 'utf8')); } catch (e) { return {}; } })();
            s[h.prog.id] = s[h.prog.id] || {}; s[h.prog.id][it.k] = s[h.prog.id][it.k] || {};
            s[h.prog.id][it.k].ev = ev;
            try { fs.writeFileSync(path.join(DATA, 'plan.json'), JSON.stringify(s, null, 1)); } catch (e) {}
            sendJson(res, { ok: true, ev });
          });
          r.on('error', () => sendJson(res, { ok: false, err: 'injoignable' }));
        }).on('error', () => sendJson(res, { ok: false, err: 'injoignable' }));
        return;
      }
      if (p === '/api/planpatch') {
        const prog = String(body.name || ''), k = String(body.k || '');
        if (!prog || !k) return sendJson(res, { ok: false });
        const s = (() => { try { return JSON.parse(fs.readFileSync(path.join(DATA, 'plan.json'), 'utf8')); } catch (e) { return {}; } })();
        s[prog] = s[prog] || {}; s[prog][k] = s[prog][k] || {};
        if (typeof body.status === 'string') s[prog][k].status = body.status;
        try { fs.writeFileSync(path.join(DATA, 'plan.json'), JSON.stringify(s, null, 1)); } catch (e) {}
        return sendJson(res, { ok: true });
      }
      if (p === '/api/programs') {
        // purge : vide les donnees recon d'un programme, garde le programme + findings
        if (body.op === 'purge' && body.name) {
          if (rankOf(req, cleanHandle(body.by || body.name)) < 3) return sendJson(res, { ok: false, error: 'admin ou co-admin requis' });
          purgeProgData(String(body.name));
          return sendJson(res, { ok: true });
        }
        // suppression : programme + findings + toutes ses donnees recon
        if (body.op === 'delete' && body.name) {
          if (rankOf(req, cleanHandle(body.by || body.name)) < 3) return sendJson(res, { ok: false, error: 'admin ou co-admin requis' });
          const id = String(body.name);
          const progs = loadPrograms().filter(x => x.id !== id);
          try { fs.writeFileSync(PROGRAMS_FILE, JSON.stringify(progs, null, 1)); } catch (e) { return sendJson(res, { ok: false }); }
          purgeProgData(id);
          // le programme disparait : son epingle, son challenge et le chat de
          // l'event meurent avec lui (le bandeau ne peut pas epingler un mort)
          {
            const cur = teamCfg();
            const dead = (cur.news || []).filter(n => n.prog === id).map(n => n.id);
            if (dead.length) saveTeamCfg({
              ...cur,
              news: (cur.news || []).filter(n => n.prog !== id),
              chal: Object.fromEntries(Object.entries(cur.chal || {}).filter(([k]) => !dead.includes(k))),
              chats: (cur.chats || []).filter(c => !c.event || !dead.includes(c.event)),
            });
          }
          const before = state.findings.length;
          state.findings = state.findings.filter(f => f.program !== id);
          persistFindings();
          return sendJson(res, { ok: true, removed: before - state.findings.length });
        }
        // creation : tout membre valide peut creer. Deux dimensions :
        // - pub : VISIBLE de tous (true) ou reserve (false) - par defaut le
        //   poste local cree public, un membre de session cree reserve (staff)
        // - access : rang minimum pour REJOINDRE (1 = tous, 2 = hunter+,
        //   3 = co-admin+, 4 = admin). Createur et staff voient/utilisent toujours.
        if (body.op === 'create' && body.name) {
          const by = cleanHandle(body.by || body.handle || req.headers['x-c2ff-handle'] || '');
          const id = String(body.name).toLowerCase().replace(/[^a-z0-9_\-]/g, '').slice(0, 24) || ('prog' + Date.now());
          const progs = loadPrograms();
          const ex = progs.find(x => x.id === id);
          if (ex) return sendJson(res, { ok: true, id, existed: true });
          const scope = String(body.scope || '').split(/[,\s]+/).map(s => s.trim()).filter(Boolean).slice(0, 20);
          const access = [1, 2, 3, 4].includes(Number(body.access)) ? Number(body.access) : (isLoopback(req) ? 1 : 3);
          const pub = typeof body.pub === 'boolean' ? body.pub : isLoopback(req);
          progs.push({ id, name: String(body.name).slice(0, 60), scope, header: String(body.header || ''), owner: by || undefined, access, pub, t: Date.now() });
          try { fs.writeFileSync(PROGRAMS_FILE, JSON.stringify(progs, null, 1)); } catch (e) { return sendJson(res, { ok: false }); }
          return sendJson(res, { ok: true, id });
        }
        // visibilite (pub) et grade d'acces : decision du createur ou du staff
        if (body.op === 'access' && body.name) {
          const by = cleanHandle(body.by || body.handle || '');
          const progs = loadPrograms();
          const pr = progs.find(x => x.id === String(body.name));
          if (!pr) return sendJson(res, { ok: false, error: 'programme introuvable' });
          if (rankOf(req, by) < 3 && !(pr.owner && pr.owner === by)) return sendJson(res, { ok: false, error: 'admin, co-admin ou createur requis' });
          if ([1, 2, 3, 4].includes(Number(body.access))) pr.access = Number(body.access);
          if (typeof body.pub === 'boolean') pr.pub = body.pub;
          try { fs.writeFileSync(PROGRAMS_FILE, JSON.stringify(progs, null, 1)); } catch (e) { return sendJson(res, { ok: false }); }
          return sendJson(res, { ok: true });
        }
        if (Array.isArray(body.programs)) {
          if (rankOf(req, cleanHandle(body.by || body.handle || '')) < 4) return sendJson(res, { ok: false, error: 'admin only' });
          try { fs.writeFileSync(PROGRAMS_FILE, JSON.stringify(body.programs, null, 1)); return sendJson(res, { ok: true }); }
          catch (e) { return sendJson(res, { ok: false }); }
        }
        return sendJson(res, { ok: false });
      }
      // ---- FAST TARGETING : recon-lite sans programme, resultats ephemeres ----
      if (p === '/api/fast') {
        if (rankOf(req, cleanHandle(body.by)) < 1) return sendJson(res, { ok: false, err: 'membre requis' });
        let raw = String(body.target || '').trim();
        if (!raw) return sendJson(res, { ok: false, err: 'cible manquante' });
        if (!/^https?:\/\//i.test(raw)) raw = 'https://' + raw;
        let u; try { u = new URL(raw); } catch (e) { return sendJson(res, { ok: false, err: 'URL invalide' }); }
        if (!/^https?:$/.test(u.protocol) || !u.hostname || !u.hostname.includes('.')) return sendJson(res, { ok: false, err: 'cible invalide' });
        const base = u.origin;
        RECON.recon(base, {}, null).then(surf => {
          surf.host = u.hostname; surf.program = null;
          sendJson(res, { ok: true, surface: surf });
        }).catch(() => sendJson(res, { ok: false, err: 'scan echoue' }));
        return;
      }
      // ---- RECON : discovery de surface avant le hunt ----
      if (p === '/api/recon') {
        const name = String(body.name || '').toLowerCase();
        const progs = (() => { try { return JSON.parse(fs.readFileSync(PROGRAMS_FILE, 'utf8')); } catch (e) { return []; } })();
        const prog = progs.find(x => x.id === name) || progs.find(x => String(x.name || '').toLowerCase() === name);
        if (!prog) return sendJson(res, { ok: false, err: 'programme introuvable' });
        if (!progUsable(req, prog)) return sendJson(res, { ok: false, err: 'programme prive : grade requis pour le rejoindre' });
        if (isDemo(prog)) return sendJson(res, { ok: false, demo: true, err: 'programme de demonstration : cree ton programme avec ton vrai scope' });
        // header programme optionnel (X-Bug-Bounty etc), envoye a chaque requete
        let hh = AUTH.hdrsFor(prog);
        const t = fleet.targetsFor([prog], [prog.id])[0];
        if (!t) return sendJson(res, { ok: false, err: 'scope vide' });
        RECON.recon(t.base, hh, null).then(surf => {
          surf.host = t.host; surf.program = prog.id;
          const f = path.join(DATA, 'surface.json');
          let store = {}; try { store = JSON.parse(fs.readFileSync(f, 'utf8')); } catch (e) {}
          store[prog.id] = surf;
          try { fs.writeFileSync(f, JSON.stringify(store, null, 1)); } catch (e) {}
          sendJson(res, { ok: true, surface: surf });
        }).catch(() => sendJson(res, { ok: false, err: 'recon echoue' }));
        return;
      }
      if (p === '/api/surface') {
        const f = path.join(DATA, 'surface.json');
        try { return sendJson(res, JSON.parse(fs.readFileSync(f, 'utf8'))); } catch (e) { return sendJson(res, {}); }
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
          if (body.program) {
            const progs = loadPrograms();
            const pr = progs.find(x => x.id === String(body.program)) || progs.find(x => x.name === String(body.program));
            if (pr && !progUsable(req, pr)) return sendJson(res, { ok: false, err: 'programme prive : grade requis pour le rejoindre' });
          }
          const patch = { enabled: true, paused: false };
          if (body.mode) patch.mode = String(body.mode);
          fleet.apply(patch);
          fleet.cycle({ program: body.program || '' }).catch(() => {});
          return sendJson(res, { ok: true, fleet: fleet.state() });
        }
        const st = fleet.apply(body);
        return sendJson(res, { ok: true, fleet: st });
      }
      // ---- ARSENAL : bases CVE (KEV/EPSS/Exploit-DB) -> mouvements suggérés executables ----
      if (p === '/api/arsenal') {
        if (body.op === 'sync') return sendJson(res, ARSENAL.sync(String(body.what || '')));
        if (body.op === 'moves' || body.op === 'exec') {
          const name = String(body.name || '').toLowerCase();
          const progs = (() => { try { return JSON.parse(fs.readFileSync(PROGRAMS_FILE, 'utf8')); } catch (e) { return []; } })();
          const prog = progs.find(x => x.id === name) || progs.find(x => String(x.name || '').toLowerCase() === name);
          if (!prog) return sendJson(res, { ok: false, err: 'programme introuvable' });
          if (!progUsable(req, prog)) return sendJson(res, { ok: false, err: 'programme prive : grade requis pour le rejoindre' });
          if (isDemo(prog)) return sendJson(res, { ok: false, demo: true, err: 'programme de demonstration : cree ton programme avec ton vrai scope' });
          let surf = {}; try { surf = JSON.parse(fs.readFileSync(path.join(DATA, 'surface.json'), 'utf8'))[prog.id] || null; } catch (e) {}
          if (!surf) return sendJson(res, { ok: false, err: 'recon requis : lance RECON avant ARSENAL' });
          // cve deja vues dans les findings du programme (rattache les exploits)
          const cves = [...new Set(state.findings.filter(f => f.program === prog.id).flatMap(f => (String(f.text || '').match(/CVE-\d{4}-\d{4,7}/g) || [])))];
          const r = ARSENAL.movesFor(surf, cves);
          if (!r.ok) return sendJson(res, r);
          const mv = ARSENAL.topMoves(r.moves, 40);
          const stash = { ts: Date.now(), host: surf.host, program: prog.id, moves: mv, tech: r.tech };
          try { fs.writeFileSync(path.join(DATA, 'arsenal.json'), JSON.stringify(stash, null, 1)); } catch (e) {}
          if (body.op === 'moves') {
            ARSENAL.osvDetails(mv.filter(m => m.kind === 'cve' && m.kev).map(m => m.cve), 6).then(det => {
              for (const m of mv) if (det[m.cve]) { m.sum = det[m.cve].sum; m.sev = det[m.cve].sev; }
              for (const m of mv) m.cmd = ARSENAL.cmdFor(m, surf.host);
              try { fs.writeFileSync(path.join(DATA, 'arsenal.json'), JSON.stringify(stash, null, 1)); } catch (e) {}
            }).catch(() => {});
            for (const m of mv) m.cmd = ARSENAL.cmdFor(m, surf.host);
            return sendJson(res, { ok: true, tech: r.tech, moves: mv, host: surf.host });
          }
          // exec : mouvement cible, commande scope (host = celui du recon du programme)
          const m = mv.find(x => x.id === String(body.id || ''));
          if (!m) return sendJson(res, { ok: false, err: 'mouvement introuvable : recalcule MOVES' });
          m.cmd = ARSENAL.cmdFor(m, surf.host);
          const proof = { t: Date.now(), host: surf.host, id: m.id, cmd: m.cmd, out: '' };
          const fin = out => {
            proof.out = out;
            // un scan qui n a rien trouve n est PAS un P2 : messages no-match FR et EN filtres
            const sev = (m.kev && out && !/0 matches|no results|no findings|aucun match|peut-etre corrigee/i.test(out)) ? 'P2' : 'SIG';
            state.seq++;
            state.findings.unshift({
              key: 'ars:' + m.id + ':' + prog.id, id: 'F' + String(state.seq).padStart(4, '0'), t: Date.now(),
              program: prog.id, run: 'ARSENAL', agent: 'C2FF', sev, status: 'analyse',
              text: trunc('[' + m.cve + '] ' + m.title + m.why + '\nPoC (3 etapes) : 1) ' + m.cmd + ' 2) sortie : ' + out.slice(0, 200) + ' 3) confirme l exploitabilite sur la version detectee', 400),
            });
            persistFindings();
            sendJson(res, { ok: true, proof });
          };
          // cmd peut commencer par le chemin absolu du binaire (ex: /usr/local/bin/nuclei)
          if (/(^|\/)nuclei$/.test(m.cmd.trim().split(' ')[0])) {
            // scope : header chercheur du programme OBLIGATOIRE dans chaque requete
            const bin = m.cmd.trim().split(' ')[0];
            const target = m.cmd.split('-u ')[1].split(' ')[0];
            const args = ['-u', target, '-id', m.cve, '-silent', '-timeout', '8', '-rl', '40'];
            const hm = /^(?:[A-Za-z0-9-]+)\s*:\s*(.+)$/.exec(String(prog.header || '').trim());
            if (hm) args.push('-H', String(prog.header).trim());
            const pr = require('child_process').spawn(bin, args, { timeout: 120000 });
            let out = '';
            pr.stdout.on('data', d => { out += d; if (out.length > 4000) pr.kill(); });
            pr.stderr.on('data', d => { out += d; });
            pr.on('close', () => fin(trunc(out || '(aucun match - la version reelle est peut-etre corrigee)', 1000)));
          } else {
            // mouvement exploit/curl : pas d'exec auto - la commande est le livrable
            return sendJson(res, { ok: true, proof: { t: Date.now(), id: m.id, cmd: m.cmd, out: '' }, manual: true });
          }
          return;
        }
        return sendJson(res, { ok: false });
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
        // sauvegarde de la config : admin uniquement (la cle API ne change pas de main)
        if (typeof body.enabled === 'boolean' || body.baseURL || body.model || body.protocol) {
          if (rankOf(req, cleanHandle(body.by || body.handle || '')) < 4) return sendJson(res, { ok: false, error: 'admin only' });
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

  if (p === '/api/state') return apiState(res, req);
  if (p === '/api/pipeline' && req.method === 'GET') {
    // etat des 5 etapes pour un programme (ou le programme actif par defaut),
    // calcule uniquement depuis les donnees existantes
    const progs = loadPrograms();
    const name = String(url.searchParams.get('name') || '').toLowerCase();
    const progsReal = progs.filter(x => !isDemo(x));
    const prog = progsReal.find(x => x.id === name) || progsReal[0] || null;
    const rd = f => { try { return JSON.parse(fs.readFileSync(path.join(DATA, f), 'utf8')); } catch (e) { return {}; } };
    let out;
    if (!prog) {
      out = { program: null, demo: progs.length ? { id: progs[0].id, name: progs[0].name } : null, steps: null };
    } else {
      const surf0 = rd('surface.json')[prog.id] || null;
      const atk0 = rd('attack.json')[prog.id] || null;
      let ars0 = {}; try { ars0 = JSON.parse(fs.readFileSync(path.join(DATA, 'arsenal.json'), 'utf8')); } catch (e) {}
      const plan0 = rd('plan.json')[prog.id] || null;
      const has = Boolean;
      out = {
        program: { id: prog.id, name: prog.name, platform: prog.platform },
        steps: [
          { k: 'scope', n: 1, done: has((prog.scope || []).length), tab: 'programs' },
          { k: 'recon', n: 2, done: has(surf0), tab: 'hunt',
            info: surf0 ? { pages: (surf0.pages || []).length, apis: (surf0.apis || []).length, params: (surf0.params || []).length, tech: (surf0.tech || []).length, ts: surf0.ts } : null },
          { k: 'attack', n: 3, done: has(atk0), tab: 'hunt',
            info: atk0 ? { findings: (atk0.findings || []).length } : null },
          { k: 'arsenal', n: 4, done: has(ars0.program === prog.id && (ars0.moves || []).length), tab: 'hunt',
            info: ars0.program === prog.id ? { moves: (ars0.moves || []).length } : null },
          { k: 'plan', n: 5, done: has(plan0 && Object.keys(plan0).length), tab: 'hunt',
            info: plan0 ? { items: Object.keys(plan0).length } : null },
        ],
      };
      const next = out.steps.find(s => !s.done);
      out.next = next ? next.k : null;
      // findings du programme pour l'etape rapport
      out.findings = state.findings.filter(f => f.program === prog.id).length;
    }
    return sendJson(res, out);
  }
  if (p === '/api/arsenal' && req.method === 'GET') {
    let stash = null; try { stash = JSON.parse(fs.readFileSync(path.join(DATA, 'arsenal.json'), 'utf8')); } catch (e) {}
    return sendJson(res, { bases: ARSENAL.basesState(), syncing: ARSENAL.syncing(), log: ARSENAL.syncLog.slice(-8), stash });
  }
  if (p === '/api/term/cards') {
    // polling de secours des cartes de groupe : fiabilise l'affichage membre
    // si le flux SSE est bufferise/mort (tunnel, proxy). since = ts du dernier vu.
    const h = cleanHandle(url.searchParams.get('handle') || '');
    if (!termTermAllowed(req, h, true)) {
      // raison explicite : le client l'affiche, un membre bloque ne reste plus dans le noir
      const t = teamCfg();
      const why = t.blocked.includes(h) ? 'kicked' : 'pending';
      return sendJson(res, { ok: false, error: why === 'kicked'
        ? 'acces terminal refuse : ce pseudo a ete kicke de la salle (un admin peut le debloquer)'
        : 'acces terminal refuse : ta validation par un admin est en attente', why });
    }
    const since = Number(url.searchParams.get('since') || 0);
    const cards = GROUPCARDS.filter(c => c.t > since);
    return sendJson(res, { ok: true, cards, total: GROUPCARDS.length, epoch: GROUPEPOCH });
  }
  if (p === '/api/term/buf') {
    // repli polling du terminal perso (et du spy via ?who=) : le SSE est
    // bufferise/mort via tunnel ou proxy - le perso n'avait AUCUN secours,
    // d'ou l'ecran noir cote membre. since = position deja vue dans le buf.
    const who = cleanHandle(url.searchParams.get('who') || '');
    const h = cleanHandle(url.searchParams.get('handle') || '');
    let ts;
    if (who) {
      if (!termSpyAllowed(req, h, who)) return sendJson(res, { ok: false, error: 'terminal refuse', why: 'spy' });
      ts = TERMS.get(who) || termSpawn(who); // paresseux, comme le stream spy
    } else {
      if (!termTermAllowed(req, h, false)) {
        const t = teamCfg();
        const why = t.blocked.includes(h) ? 'kicked' : 'pending';
        return sendJson(res, { ok: false, error: why === 'kicked'
          ? 'acces terminal refuse : ce pseudo a ete kicke de la salle (un admin peut le debloquer)'
          : 'acces terminal refuse : ta validation par un admin est en attente', why });
      }
      ts = TERMS.get(termId(req, h)) || termSpawn(termId(req, h)); // paresseux : le SSE ne demarre plus le PTY hors localhost
    }
    const buf = ts ? ts.buf : '';
    const since = Number(url.searchParams.get('since') || 0);
    if (buf.length < since) return sendJson(res, { ok: true, buf, pos: buf.length, reset: true }); // tronque ou session neuve
    return sendJson(res, { ok: true, buf: buf.slice(since), pos: buf.length });
  }
  if (p === '/api/term/stream') {
    // SSE : replay du buffer puis output live. Groupe : cartes de commandes ;
    // perso : PTY prive ; ?who= = vue lecture seule du perso d'un membre (co-admin+).
    const who = cleanHandle(url.searchParams.get('who') || '');
    const h = cleanHandle(url.searchParams.get('handle') || '');
    const group = url.searchParams.get('term') === 'group';
    if (who) {
      if (!termSpyAllowed(req, h, who)) return send(res, 403, 'text/plain', 'terminal reserved');
      res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'keep-alive', 'X-Accel-Buffering': 'no' });
      const ts = TERMS.get(who) || termSpawn(who); // paresseux : voir le perso demarre sa session
      if (!ts) return send(res, 500, 'text/plain', 'cannot spawn shell');
      if (ts.buf) res.write('data: ' + JSON.stringify(ts.buf) + '\n\n');
      const client = { res };
      ts.clients.add(client);
      const beat = setInterval(() => { try { res.write(': ping\n\n'); } catch (e) {} }, 15000);
      req.on('close', () => { clearInterval(beat); ts.clients.delete(client); });
      return;
    }
    if (!termTermAllowed(req, h, group)) return send(res, 403, 'text/plain', 'terminal reserved');
    res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'keep-alive', 'X-Accel-Buffering': 'no' });
    if (group) {
      groupSend({ res }, { cards: GROUPCARDS });
      const client = { res };
      GROUPCLIENTS.add(client);
      const beat = setInterval(() => { try { res.write(': ping\n\n'); } catch (e) {} }, 15000);
      req.on('close', () => { clearInterval(beat); GROUPCLIENTS.delete(client); });
      return;
    }
    const id = termId(req, h);
    const ts = TERMS.get(id) || termSpawn(id);
    if (!ts) return send(res, 500, 'text/plain', 'cannot spawn shell');
    if (ts.buf) res.write('data: ' + JSON.stringify(ts.buf) + '\n\n');
    const client = { res };
    ts.clients.add(client);
    const beat = setInterval(() => { try { res.write(': ping\n\n'); } catch (e) {} }, 15000);
    req.on('close', () => { clearInterval(beat); ts.clients.delete(client); });
    return;
  }
  if (p === '/app.js') return send(res, 200, 'application/javascript; charset=utf-8', fs.readFileSync(path.join(ROOT, 'app.js')));
  if (p === '/banner.png') return send(res, 200, 'image/png', fs.readFileSync(path.join(ROOT, 'docs', 'assets', 'banner.png')));
  if (p === '/banner_app.gif') return send(res, 200, 'image/gif', fs.readFileSync(path.join(ROOT, 'docs', 'assets', 'banner_app.gif')));
  if (p === '/' || p === '/index.html') return send(res, 200, 'text/html; charset=utf-8', fs.readFileSync(path.join(ROOT, 'index.html')));
  send(res, 404, 'text/plain', 'not found');
};

const server = http.createServer(MAIN);

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