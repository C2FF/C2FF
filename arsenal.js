// ============================================================
// C2FF - arsenal.js : resolutions CVE -> mouvements suggérés
// Bases locales cachees (data/bases/) : CISA KEV, FIRST EPSS,
// Exploit-DB (files_exploits.csv). Enrichissement OSV on-demand.
// Entree = surface du RECON + findings, sortie = mouvements
// classes meilleur d'abord (KEV > EPSS > CVSS), commande prete,
// execution scope-gardee avec capture de preuve.
// Zero dependance. GET/API publics only, budget strict.
// ============================================================
const https = require('https');
const http = require('http');
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const { spawn } = require('child_process');

const BASES_DIR = path.join(__dirname, 'data', 'bases');
const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const EPSS_URL = 'https://epss.empiricalsecurity.com/epss_scores-current.csv.gz';
const SDB_URL = 'https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv';
const OSV_URL = 'https://api.osv.dev/v1/vulns/';
const DL_TIMEOUT = 30000, MAX_DL = 60 * 1024 * 1024;
// produits connus : normalisation des tokens tech recon vers les noms KEV
const PROD_MAP = { word_press: 'wordpress', wp: 'wordpress' };
function findNuclei() {
  if (process.env.NUCLEI_BIN && fs.existsSync(process.env.NUCLEI_BIN)) return process.env.NUCLEI_BIN;
  for (const p of ['/usr/local/bin/nuclei', '/usr/bin/nuclei']) if (fs.existsSync(p)) return p;
  try { return require('child_process').execSync('command -v nuclei', { encoding: 'utf8' }).trim() || null; } catch (e) { return null; }
}
const NUCLEI_BIN = findNuclei(); // chemin resolu : env NUCLEI_BIN, emplacements standards, puis PATH

function get(url, max, depth) {
  return new Promise(res => {
    const mod = url.startsWith('http:') ? http : https;
    const req = mod.get(url, { headers: { 'user-agent': 'Mozilla/5.0 (C2FF-arsenal)', accept: '*/*' }, timeout: 45000 }, r => {
      // suivi redirect (30x) : le fichier EPSS courant renvoie vers une URL datee
      if ((r.statusCode === 301 || r.statusCode === 302 || r.statusCode === 307 || r.statusCode === 308) && r.headers.location) {
        r.resume();
        if ((depth || 0) >= 3) return res({ code: r.statusCode, buf: null });
        const next = new URL(r.headers.location, url).toString();
        return res(get(next, max, (depth || 0) + 1));
      }
      if (r.statusCode !== 200) { r.resume(); return res({ code: r.statusCode, buf: null }); }
      const chunks = []; let n = 0, done = false;
      const fin = b => { if (done) return; done = true; r.destroy(); res({ code: r.statusCode, buf: b }); };
      r.on('data', d => { chunks.push(d); n += d.length; if (n > (max || MAX_DL)) fin(Buffer.concat(chunks)); });
      r.on('end', () => fin(Buffer.concat(chunks)));
      r.on('error', () => res({ code: 0, buf: null }));
 });
    req.on('timeout', () => { try { req.destroy(); } catch (e) {} res({ code: 0, buf: null }); });
    req.on('error', () => res({ code: 0, buf: null }));
  });
}
const clip = (s, n) => String(s || '').replace(/\s+/g, ' ').trim().slice(0, n);

// ---------- bases ----------
let KEV = null, KEVMAP = null;      // {cve: {v,p,d,ran,t}}, index par produit
let EPSS = null;                    // {cve: score}
let SDB = null;                     // [{id,title,type,codes}]
let SDB_VERSION = null;

function loadBases() {
  try { KEV = JSON.parse(fs.readFileSync(path.join(BASES_DIR, 'kev.json'), 'utf8')); } catch (e) { KEV = null; }
  try { EPSS = JSON.parse(fs.readFileSync(path.join(BASES_DIR, 'epss.json'), 'utf8')); } catch (e) { EPSS = null; }
  try { SDB_VERSION = JSON.parse(fs.readFileSync(path.join(BASES_DIR, 'sdb.json'), 'utf8')); SDB = SDB_VERSION.rows; } catch (e) { SDB = null; }
  KEVMAP = new Map();
  if (KEV) for (const [cve, e] of Object.entries(KEV.e)) { const k = (e.p || '').toLowerCase(); if (!KEVMAP.has(k)) KEVMAP.set(k, []); KEVMAP.get(k).push(cve); }
}
loadBases();

function basesState() {
  const st = {};
  for (const [name, o] of [['kev', KEV], ['epss', EPSS], ['sdb', SDB_VERSION]]) {
    st[name] = o ? { n: o.n, t: o.t } : null;
  }
  return st;
}

// ---- syncs (async, ecrit base.json + status) ----
let syncing = false;
const syncLog = [];

async function syncKev() {
  const r = await get(KEV_URL, 20 * 1024 * 1024);
  if (!r.buf) throw new Error('kev dl');
  const j = JSON.parse(r.buf.toString('utf8'));
  const e = {};
  for (const v of (j.vulnerabilities || [])) {
    e[v.cveID] = { v: v.vendorProject || '', p: v.product || '', d: v.dateAdded || '', ran: v.knownRansomwareCampaignUse === 'Known', cv: v.cvssV3_1 ? Number(v.cvssV3_1.baseScore) || 0 : 0, w: clip(v.shortDescription || '', 140) };
  }
  KEV = { n: Object.keys(e).length, t: Date.now(), e };
  fs.writeFileSync(path.join(BASES_DIR, 'kev.json'), JSON.stringify(KEV));
}

async function syncEpss() {
  const r = await get(EPSS_URL, 30 * 1024 * 1024);
  if (!r.buf) throw new Error('epss dl');
  const csv = zlib.gunzipSync(r.buf).toString('utf8');
  const e = {};
  for (const line of csv.split('\n')) {
    if (line.startsWith('cve,')) { const dt = line.split(',').pop().trim(); if (/^\d{4}/.test(dt)) continue; }
    const m = /^(CVE-\d{4}-\d{4,7}),([\d.]+),/.exec(line);
    if (m) e[m[1]] = Math.round(parseFloat(m[2]) * 1000) / 10;
  }
  EPSS = { n: Object.keys(e).length, t: Date.now(), e };
  fs.writeFileSync(path.join(BASES_DIR, 'epss.json'), JSON.stringify(EPSS));
}

// CSV min (les titres Exploit-DB ont des virgules entre quotes)
function csvParseRow(line) {
  const out = []; let cur = '', inq = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (inq) { if (c === '"') { if (line[i + 1] === '"') { cur += '"'; i++; } else inq = false; } else cur += c; }
    else if (c === '"') inq = true;
    else if (c === ',') { out.push(cur); cur = ''; }
    else cur += c;
  }
  out.push(cur);
  return out;
}

async function syncSdb() {
  const r = await get(SDB_URL, 40 * 1024 * 1024);
  if (!r.buf) throw new Error('sdb dl');
  const lines = r.buf.toString('utf8').split('\n').filter(l => l.trim());
  const rows = [];
  for (let i = 1; i < lines.length; i++) {
    const c = csvParseRow(lines[i]);
    if (c.length < 1) continue;
    rows.push({ id: c[0], title: clip(c[2], 120), file: c[1], type: c[5], codes: (c[11] || '').slice(0, 80) });
  }
  SDB_VERSION = { n: rows.length, t: Date.now(), rows };
  fs.writeFileSync(path.join(BASES_DIR, 'sdb.json'), JSON.stringify(SDB_VERSION));
}

function sync(what) {
  if (syncing) return { ok: false, err: 'sync en cours' };
  syncing = true; syncLog.length = 0;
  fs.mkdirSync(BASES_DIR, { recursive: true });
  const jobs = what === '' ? ['kev', 'epss', 'sdb'] : [what];
  (async () => {
    for (const j of jobs) {
      try { syncLog.push(j + '...'); await ({ kev: syncKev, epss: syncEpss, sdb: syncSdb }[j]()); loadBases(); syncLog.push(j + ' OK ' + basesState()[j].n); }
      catch (e) { syncLog.push(j + ' FAIL ' + clip(String(e && e.message || e), 60)); }
    }
    syncing = false;
  })();
  return { ok: true };
}

// ---------- parsing tech -> produits ----------
// extrait (produit, version) des chaines tech du recon ("nginx", "WordPress 6.2.1",
// "X-Powered-By: Express", "PHP/8.1.2")
function techTokens(tech) {
  const out = [];
  const seen = new Set();
  for (const raw of tech || []) {
    let s = String(raw);
    // version d'abord (sinon la regex lazy du nom coupe "nginx" en "ngi")
    let ver = '';
    const mv = /[vV]?\b(\d+(?:\.\d+){1,3})\b/.exec(s);
    if (mv) { ver = mv[1]; s = s.slice(0, mv.index) + ' ' + s.slice(mv.index + mv[0].length); }
    let name = s.toLowerCase().replace(/[^a-z0-9 +#.-]/g, ' ').replace(/\s+/g, ' ').trim()
      .replace(/^[\s./-]+/, '').replace(/[\s./_-]+$/, '');
    if (!name || name.length < 2) continue;
    name = PROD_MAP[name.replace(/ /g, '_')] || name;
    if (seen.has(name)) continue;
    seen.add(name);
    // ignore les tokens genereiques qui polluent
    if (/^(accept|text|user agent|user-agent|connection|keep-alive|transfer|encoding|application|image|charset|mozilla|gecko|applewebkit|chrome|safari|edg|edge)$/.test(name)) continue;
    out.push({ name, ver });
  }
  return out;
}

// ---------- mouvements ----------
// match KEV par produit (normalise), enrichi EPSS ; searchsploit par produit/CVE
function movesFor(surf, extraCVEs) {
  if (!KEV) return { ok: false, err: 'bases non chargees : SYNC requis' };
  const moves = [];
  const seen = new Set();
  const tokens = techTokens(surf.tech);

  for (const t of tokens) {
    const prod = t.name.replace(/[^a-z0-9]/g, '');
    // match exact par index, sinon match souple : les produits KEV sont
    // souvent plus precis que le token recon ("WordPress Core" vs "wordpress",
    // "Apache Tomcat" vs "tomcat", "NGINX Open Source" vs "nginx")
    let cves = [];
    for (const key of [prod, t.name.replace(/ /g, '_')]) if (KEVMAP.has(key)) { cves = KEVMAP.get(key); break; }
    if (!cves.length) {
      const hit = [];
      const rx = s => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const w1 = new RegExp('(^|[^a-z0-9])' + rx(prod) + '([^a-z0-9]|$)');
      for (const [key, list] of KEVMAP) {
        if (key.length < 4) continue;                 // trop court = faux positifs
        // word-boundary des deux cotes : "WordPress Manager" matche "wordpress"
        // mais "wordpress" ne doit PAS matcher le produit "Word" (Microsoft)
        if (w1.test(key)) { hit.push(...list); continue; }
        if (key.length >= 4 && new RegExp('(^|[^a-z0-9])' + rx(key) + '([^a-z0-9]|$)').test(prod)) hit.push(...list);
      }
      cves = hit.slice(0, 8);
    }
    {
      for (const cve of cves) {
        if (seen.has('cve:' + cve)) continue;
        seen.add('cve:' + cve);
        const e = KEV.e[cve];
        moves.push({
          id: 'cve:' + cve, kind: 'cve', cve,
          product: e.p, vendor: e.v, tech: t.name, ver: t.ver,
          epss: (EPSS && EPSS.e) ? (EPSS.e[cve] === undefined ? null : EPSS.e[cve]) : null,
          kev: true, ran: e.ran,
          cvss: e.cv || 0, date: e.d,
          title: clip(e.w || e.p + ' - ' + cve, 90),
          why: ' produit detecte : "' + t.name + (t.ver ? '" version ' + t.ver : '') + ' | CVE exploitee in the wild (KEV ' + e.d.slice(0, 10) + ')' + (e.ran ? ' | ransomware utilisee' : ''),
        });
      }
    }
  }
  // searchsploit : par produit + par cve (sans KEV, exploitable quand meme)
  if (SDB) {
    const cveSet = new Set([...moves.map(m => m.cve), ...(extraCVEs || [])]);
    for (const t of tokens) {
      const pat = new RegExp('(^|[^a-z])' + t.name.replace(/[.+*^$\\()[\]{}|?]/g, '.') + '([^a-z]|$)', 'i');
      let hit = 0;
      for (const r of SDB) {
        if (hit >= 4) break;
        if (!pat.test(r.title)) continue;
        if (seen.has('x:' + r.id)) continue;
        seen.add('x:' + r.id);
        // cve explicite dans codes -> on la rattache au mouvement cve si existe
        hit++;
        moves.push({ id: 'x:' + r.id, kind: 'exploit', cve: r.codes || '', tech: t.name, ver: t.ver, epss: null, kev: false, cvss: 0, date: '', title: r.title, why: ' exploit public Exploit-DB #' + r.id + ' (' + r.type + ') pour "' + t.name + '"' });
      }
    }
    for (const m of moves) {
      if (m.kind !== 'cve') continue;
      for (const r of SDB) if (r.codes && r.codes.includes(m.cve)) { m.exploit = r.id; m.exploitTitle = r.title; break; }
    }
  }
  // enrichissement OSV (resume/severity) sur les KEV du haut - 6 max, on-demand
  // (fait au moment du calcul, budget stricte : 6 GET)
  return { ok: true, moves, tech: tokens };
}

// classement : KEV d abord, puis EPSS desc, puis CVSS desc
function rank(moves) {
  return moves.slice().sort((a, b) => (b.kev - a.kev) || ((b.epss || 0) - (a.epss || 0)) || (b.cvss - a.cvss));
}
function topMoves(moves, n) {
  return rank(moves).slice(0, n || 25);
}

// commande prete a executer pour un mouvement
function cmdFor(m, host) {
  const base = host ? 'https://' + String(host).replace(/^https?:\/\//, '') : '';
  if (m.kind === 'cve') {
    if (NUCLEI_BIN) return NUCLEI_BIN + ' -u ' + base + ' -id ' + m.cve + ' -silent';
    return 'curl -si ' + base + " | head -40   # verifier manuellement l'exploitation " + m.cve;
  }
  if (m.kind === 'exploit') return '# exploit #' + m.id.slice(2) + ' : https://www.exploit-db.com/exploits/' + m.id.slice(2) + ' - lire, adapter, tester en tenant le scope';
  return base;
}

// OSV : details d'un CVE (summary + severite) - budget 6/call
async function osvDetails(cves, n) {
  const out = {};
  if (!cves.length) return out;
  await Promise.all(cves.slice(0, n || 6).map(cve => new Promise(res => {
    if (!/^CVE-/.test(cve)) return res();
    const req = https.get(OSV_URL + cve, { headers: { 'user-agent': 'C2FF-arsenal' }, timeout: 8000 }, r => {
      let raw = '';
      r.on('data', d => { raw += d; if (raw.length > 200000) r.destroy(); });
      r.on('end', () => {
        try {
          const j = JSON.parse(raw);
          const sev = (j.severity || []).find(x => x.score && x.type === 'CVSS_V3');
          const cvss = j.database_specific && j.database_specific.severity ? j.database_specific.severity : '';
          out[cve] = { sum: clip(j.summary || j.details || '', 140), sev: cvss || (sev && sev.score) || '' };
        } catch (e) {}
        res();
      });
      r.on('error', () => res());
    });
    req.on('timeout', () => { try { req.destroy(); } catch (e) {} res(); });
    req.on('error', () => res());
  })));
  return out;
}

// ---------- modes avances : nuclei auto + enrichissement ----------
// Pour une alerte P1 (NO_SQLI, JWT_ADV, BLIND_SQL) : scan nuclei automatique
// (tags dedies) sur le host du programme, header chercheur injecte.
// Sortie = preuve appendue au rapport. Pas de match = chaine vide.
const ADV_TAGS = { NO_SQLI: 'nosqli,sqli', JWT_ADV: 'jwt,token', BLIND_SQL: 'sqli' };

function nucleiForAlert(host, mode, hdrs) {
  return new Promise(res => {
    const tags = ADV_TAGS[mode];
    if (!tags || !NUCLEI_BIN || !host) return res('');
    const target = String(host).replace(/^https?:\/\//, '');
    const args = ['-u', 'https://' + target, '-tags', tags, '-silent', '-timeout', '8', '-rl', '40'];
    for (const h of hdrs || []) args.push('-H', h);
    let out = '', done = false;
    const fin = s => { if (!done) { done = true; res(s); } };
    const tmo = setTimeout(() => { try { ps.kill(); } catch (e) {} fin(out); }, 120000);
    const ps = spawn(NUCLEI_BIN, args);
    ps.on('error', () => { clearTimeout(tmo); fin(''); });
    ps.stdout.on('data', d => { out += d.toString(); if (out.length > 100000) { try { ps.kill(); } catch (e) {} } });
    ps.on('close', () => { clearTimeout(tmo); fin(out.slice(0, 4000)); });
  });
}

// autres modes : enrichissement du rapport avec les references de
// verification manuelle (methode d'exploitation + doc de payload).
const ADV_REFS = {
  HEADER_INJECT: 'ref: HTTP response splitting - https://owasp.org/www-community/attacks/HTTP_Response_Splitting',
  ACTUATOR_ADV:  'ref: Spring Boot actuator endpoints - https://github.com/p1ay873a288/spring-boot-actuator-exploit',
  AWS_META:      'ref: SSRF cloud metadata - https://cloud.hacktricks.xyz/pentesting-cloud/ssrf-server-side-request-forgery/cloud-metadata',
  OAUTH_MIS:     'ref: OAuth misconfig - https://book.hacktricks.xyz/pentesting-web/oauth',
  SESSION_FIX:   'ref: session fixation - https://owasp.org/www-community/attacks/Session_fixation',
  DNS_OOB:       'ref: OOB XXE/SSRF - https://book.hacktricks.xyz/pentesting-web/xxe-injection',
  GRAPHQL_INTRO: 'ref: GraphQL introspection - https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/graphql',
  VERSION_CRAWL: 'ref: version fingerprint -> chercher CVE sur la version exacte (arsenal MOUVEMENTS)',
  DIFF_COMPARE:  'ref: differentiel reponses -> BOLA/IDOR a confirmer avec creds (module AUTHZ)',
};
function enrichAlert(alert) {
  const ref = ADV_REFS[alert.mode];
  return ref ? { ...alert, ref } : alert;
}

module.exports = { movesFor, rank, topMoves, cmdFor, sync, basesState, syncing: () => syncing, syncLog, osvDetails, loadBases, nucleiForAlert, enrichAlert, ADV_TAGS };