// ============================================================
// C2FF - attack.js : phase ATTACK - probes ciblees sur la surface reconnee
// Zero dependance, GET only, budget strict. Entree = surface du RECON
// (data/surface.json), sortie = candidates avec preuve (requete + reponse).
// Chaque candidate : requete en 1 ligne + reponse tronquee = PoC 3 etapes.
// ============================================================
const https = require('https');

const REQ_TIMEOUT = 6000, GAP_MS = 250;
const MAX_REQ = 70, MAX_EP = 20, MAX_JS = 8, MAX_PATHS = 12, MAX_FINDINGS = 30, JS_CAP = 200000;

// chemins a fort signal testes d'office sur la racine (docs et config exposes)
const KNOWN_PATHS = [
  ['/.env', 'env'], ['/swagger.json', 'swagger'], ['/openapi.json', 'swagger'],
  ['/api-docs', 'swagger'], ['/api/swagger.json', 'swagger'], ['/api/config', 'conf'],
  ['/actuator/health', 'actuator'], ['/actuator/env', 'actuator'], ['/config.json', 'conf'],
  ['/graphql', 'graphql'], ['/server-status', 'srv'], ['/.git/config', 'git'],
];

// secrets cherche dans les bundles JS
const SECRET_RES = [
  ['cle AWS en dur', /AKIA[0-9A-Z]{16}/g, 'P2'],
  ['token GitHub en dur', /gh[pousr]_[A-Za-z0-9]{36,50}/g, 'P2'],
  ['token Slack en dur', /xox[baprs]-[A-Za-z0-9-]{20,}/g, 'P2'],
  ['cle Google en dur', /AIza[0-9A-Za-z_\-]{35}/g, 'P2'],
  ['cle privee embarquee', /-----BEGIN [A-Z ]*PRIVATE KEY-----/g, 'P2'],
  ['secret en dur dans le code', /(?:secret|passw(?:or)?d|token|api_?key)["']?\s*[:=]\s*["'][A-Za-z0-9_\-]{16,48}["']/gi, 'SIG'],
  ['bearer colle dans le bundle', /(?:bearer|authorization)["'\s:]{1,4}(eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})/gi, 'SIG'],
];

const JWT_RE = /eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{4,}\.[A-Za-z0-9_\-]{4,}/;
const EMAIL_RE = /[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/i;
const TRACE_RE = /at \/[\w./-]+:\d+|Traceback \(most recent|java\.lang\.\w+Exception|Fatal error.*\.php on line/;

function get(url, hh, max) {
  return new Promise(res => {
    let req0;
    try { req0 = https.get(url, { headers: { 'user-agent': 'Mozilla/5.0 (C2FF-attack)', accept: '*/*', ...(hh || {}) }, timeout: REQ_TIMEOUT }, r => {
      let raw = ''; let n = 0;
      r.on('data', d => { n += d.length; if (n <= (max || 150000)) raw += d; else r.destroy(); });
      r.on('end', () => res({ code: r.statusCode || 0, headers: r.headers || {}, body: raw }));
      r.on('error', () => res({ code: 0, headers: {}, body: '' }));
      r.on('aborted', () => res({ code: 0, headers: {}, body: '' }));
    }); } catch (e) { return res({ code: 0, headers: {}, body: '' }); }
    req0.on('timeout', () => { try { req0.destroy(); } catch (e) {} res({ code: 0, headers: {}, body: '' }); });
    req0.on('error', () => res({ code: 0, headers: {}, body: '' }));
  });
}
const sleep = ms => new Promise(r => setTimeout(r, ms));
const clip = (s, n) => String(s || '').replace(/\s+/g, ' ').trim().slice(0, n);

function jwtClaims(t) {
  const p = String(t).split('.');
  if (p.length < 2) return null;
  const b64d = s => { try { return JSON.parse(Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8')); } catch (e) { return null; } };
  const h = b64d(p[0]), b = b64d(p[1]);
  return (h && b) ? { h, b } : null;
}

async function attack(surf, header, log) {
  const T0 = Date.now();
  const base = 'https://' + (surf.host || '');
  const hh = { ...(header || {}) };
  const out = [], seen = new Set();
  let nreq = 0;
  const add = (sev, mod, title, req, resTxt) => {
    const k = mod + ':' + title;
    if (seen.has(k) || out.length >= MAX_FINDINGS) return;
    seen.add(k);
    out.push({ sev, mod, title: clip(title, 90), req: clip(req, 180), res: clip(resTxt, 260) });
    if (log) log('▸ [' + sev + '] ' + title);
  };

  async function probe(path, extra, max) {
    if (nreq >= MAX_REQ || !path || !path.startsWith('/')) return null;
    nreq++;
    const r = await get(base + path, { ...hh, ...(extra || {}) }, max);
    if (log) log('├ ' + (r.code || 'ERR') + ' ' + path.slice(0, 60));
    await sleep(GAP_MS);
    return r;
  }

  // ---- 1. endpoints API du RECON : auth, CORS, JWT, stack traces ----
  const eps = [...new Set((surf.apis || []).map(a => String(a).split('?')[0]))].slice(0, MAX_EP);
  for (const ep of eps) {
    const r = await probe(ep, { origin: 'https://c2ff-probe.example' });
    if (!r.code) continue;
    const acao = r.headers['access-control-allow-origin'], acac = r.headers['access-control-allow-credentials'];
    if (acao === 'https://c2ff-probe.example' && acac === 'true') add('P2', 'cors', 'CORS reflechi avec credentials sur ' + ep, 'GET ' + ep + ' | Origin: https://c2ff-probe.example', r.body);
    if (r.code === 200 && r.body) {
      const b = r.body.slice(0, 3000);
      if (EMAIL_RE.test(b) || (b[0] === '[' && b.length > 60)) add('P2', 'auth', 'endpoint API non authentifie qui expose des donnees : ' + ep, 'GET ' + ep, r.body);
      else if (r.code === 200 && !/error|denied|unauthor|forbidden/i.test(b.slice(0, 200))) add('SIG', 'auth', 'endpoint API repond 200 sans auth : ' + ep, 'GET ' + ep, r.body);
    }
    if (r.body && TRACE_RE.test(r.body)) add('SIG', 'info', 'stack trace visible sur ' + ep, 'GET ' + ep, r.body);
    const jt = (r.body.match(JWT_RE) || [])[0];
    if (jt) {
      const c = jwtClaims(jt);
      if (c) {
        if (c.h.alg === 'none' || !c.h.alg) add('P2', 'jwt', 'JWToken sans signature (alg none) emis par ' + ep, 'GET ' + ep, 'header=' + JSON.stringify(c.h));
        if (String(c.h.kid || '').includes('..') || String(c.h.kid || '').startsWith('/')) add('P2', 'jwt', 'JWToken kid manipulable (traversal) : ' + ep, 'GET ' + ep, 'kid=' + c.h.kid);
        if (!c.b.exp) add('SIG', 'jwt', 'JWT sans expiration emis : ' + ep, 'GET ' + ep, JSON.stringify(c.b).slice(0, 120));
        else if (String(c.b.role || c.b.admin || '').match(/admin|root|su/i)) add('SIG', 'jwt', 'JWT avec role eleve : ' + ep, 'GET ' + ep, JSON.stringify(c.b).slice(0, 120));
      }
    }
  }
  if (log) log('├ API probee : ' + eps.length + ' endpoints, ' + nreq + ' req');

  // ---- 2. chemins a fort signal : config et docs exposes ----
  for (const [p2, kind] of KNOWN_PATHS.slice(0, MAX_PATHS)) {
    const r = await probe(p2, null, 60000);
    if (!r.code || r.code === 404 || r.code === 403) continue;
    const b = r.body.slice(0, 4000);
    if (kind === 'env' && r.code === 200 && /[A-Z0-9_]+=/.test(b) && /(?:key|secret|pass|token|db|env)/i.test(b)) add('P1', 'exposure', 'fichier .env expose avec variables', 'GET ' + p2, b);
    else if (kind === 'git' && r.code === 200 && b.includes('[core]')) add('P2', 'exposure', 'repo git expose (.git/config)', 'GET ' + p2, b);
    else if (kind === 'swagger' && r.code === 200 && /"(?:paths|openapi|swagger)"/.test(b)) {
      const n = (b.match(/\//g) || []).length;
      add(n > 12 ? 'P2' : 'SIG', 'exposure', 'documentation API exposee : ' + p2, 'GET ' + p2, b.slice(0, 160));
    }
    else if (kind === 'actuator' && r.code === 200 && /status|env/.test(b)) add('P2', 'exposure', 'actuator expose : ' + p2, 'GET ' + p2, b.slice(0, 160));
    else if (kind === 'graphql' && r.code === 200 && /error|schema|query|missing/i.test(b)) add('SIG', 'exposure', 'endpoint graphql ouvert : ' + p2, 'GET ' + p2, b.slice(0, 160));
    else if (kind === 'srv' && r.code === 200) add('SIG', 'exposure', 'server-status expose : ' + p2, 'GET ' + p2, b.slice(0, 160));
    else if (kind === 'conf' && r.code === 200 && r.headers['content-type'].includes('json') && /key|secret|token|pass/i.test(b)) add('P2', 'exposure', 'config JSON exposee : ' + p2, 'GET ' + p2, b.slice(0, 160));
  }

  // ---- 3. secrets dans les bundles JS du RECON ----
  const files = [...new Set((surf.jsfiles || []))].slice(0, MAX_JS);
  for (const u of files) {
    const r = await probe(u.replace(/^https?:\/\/[^/]+/, '') || '/', null, JS_CAP);
    if (!r || !r.body) continue;
    for (const [name, re, sev] of SECRET_RES) {
      re.lastIndex = 0;
      const m = re.exec(r.body);
      if (m) add(sev, 'secrets', name + ' : ' + (u.split('/').pop() || u).slice(0, 40), 'GET ' + u, clip(m[0], 80));
    }
  }
  if (log) log('├ bundles scans : ' + files.length);

  return { ts: new Date().toISOString(), ms: Date.now() - T0, reqs: nreq, ep: eps.length, js: files.length, findings: out };
}

module.exports = { attack };