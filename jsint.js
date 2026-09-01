// ============================================================
// C2FF - jsint.js : intelligence des bundles JS
// Telecharge les .js de la surface, extrait :
//  - endpoints / routes d API caches dans le code
//  - secrets : cles AWS, Google, tokens, JWT, webhooks...
//  - sourcemaps exposes (.map disponibles = le code source complet)
// Le passif n est qu une etape : chaque extraction produit un tir testable.
// ============================================================
'use strict';
const https = require('https');
const http = require('http');
const { URL } = require('url');

const UA = 'Mozilla/5.0 (C2FF-jsint)';
const MAX_FILES = 12;
const MAX_BYTES = 2 * 1024 * 1024;
const TIMEOUT = 20000;

function get(url, hdrs, depth, cb) {
  depth = depth || 0;
  if (depth > 3) return cb(null, 0, Buffer.alloc(0), {});
  const u = new URL(url);
  const mod = u.protocol === 'http:' ? http : https;
  const req = mod.get(url, {
    headers: { 'user-agent': UA, accept: '*/*', ...(hdrs || {}) },
    timeout: TIMEOUT,
    rejectUnauthorized: false,
  }, r => {
    if ([301, 302, 307, 308].includes(r.statusCode) && r.headers.location) {
      r.resume();
      return get(new URL(r.headers.location, url).toString(), hdrs, depth + 1, cb);
    }
    const chunks = [];
    let n = 0;
    r.on('data', c => { n += c.length; if (n <= MAX_BYTES) chunks.push(c); else r.destroy(); });
    r.on('end', () => cb(null, r.statusCode, Buffer.concat(chunks), r.headers));
    r.on('error', e => cb(e, r.statusCode, Buffer.concat(chunks), r.headers));
  });
  req.on('timeout', () => req.destroy(new Error('timeout')));
  req.on('error', e => cb(e, 0, Buffer.alloc(0), {}));
}

const clip = (s, n) => (s || '').length > n ? s.slice(0, n) : (s || '');

// ---- extracteurs ----
const RX_ENDPOINTS = [
  /["'`](\/(?:api|v[1-9]|rest|graphql|internal|admin|private)[a-zA-Z0-9/_\-.$]{2,80})["'`]/g,
  /["'`](https?:\/\/[a-z0-9.-]+\.[a-z]{2,12}\/[a-zA-Z0-9/_.\-?&=%]{2,90})["'`]/g,
];
const RX_SECRETS = [
  { k: 'aws-key', rx: /\b(AKIA[0-9A-Z]{16})\b/g },
  { k: 'google-key', rx: /\b(AIza[0-9A-Za-z_\-]{35})\b/g },
  { k: 'github-token', rx: /\b(gh[pousr]_[A-Za-z0-9]{36})\b/g },
  { k: 'slack-token', rx: /\b(xox[baprs]-[A-Za-z0-9\-]{10,40})\b/g },
  { k: 'jwt', rx: /\b(eyJ[A-Za-z0-9_\-]{15,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})\b/g },
  { k: 'firebase', rx: /\b([a-z0-9\-]{3,24}\.firebaseio\.com)\b/g },
  { k: 'api-key-var', rx: /(?:api[_-]?key|apikey|secret|token|passwd|password)["'\s:=]{1,4}["']([A-Za-z0-9_\-./+=]{16,64})["']/gi },
];
const RX_SMAP = /sourceMappingURL=([^\s'"]+\.map)/g;

function jsint(surf, prog, done) {
  const hdrs = {};
  if (prog && prog.header) {
    const h = String(prog.header).trim();
    const m = /^([A-Za-z0-9-]+)\s*:\s*(.+)$/.exec(h);
    if (m) hdrs[m[1]] = m[2];
  }
  const host = surf.host || '';
  const pages = (surf.pages || []).slice(0, 3).map(p => /^https?:\/\//.test(p) ? p : 'https://' + host + p);
  const jsUrls = [...new Set((surf.jsfiles || []).slice(0, MAX_FILES)
    .map(p => /^https?:\/\//.test(p) ? p : 'https://' + host + p))];
  const out = { ts: Date.now(), host, files: 0, bytes: 0, endpoints: [], secrets: [], maps: [], errs: [] };
  if (!jsUrls.length) { out.errs.push('aucun .js dans la surface : relance RECON'); return done(out); }

  const seenE = new Set(), seenS = new Set();
  const harvest = (body, file) => {
    const s = body.toString('utf8');
    for (const rx of RX_ENDPOINTS) {
      rx.lastIndex = 0;
      let m;
      while ((m = rx.exec(s)) && out.endpoints.length < 200) {
        const e = m[1];
        if (!seenE.has(e)) {
          seenE.add(e);
          out.endpoints.push({ u: e, from: file });
        }
      }
    }
    for (const sp of RX_SECRETS) {
      sp.rx.lastIndex = 0;
      let m;
      while ((m = sp.rx.exec(s)) && out.secrets.length < 60) {
        const v = m[1];
        if (!seenS.has(v)) {
          seenS.add(v);
          out.secrets.push({ k: sp.k, v: clip(v, 60), from: file });
        }
      }
    }
  };

  let i = 0;
  const next = () => {
    if (i >= jsUrls.length) return nextMap(0);
    const url = jsUrls[i++];
    get(url, hdrs, 0, (err, code, body) => {
      if (err || code !== 200) { out.errs.push(url.slice(0, 80) + ' -> ' + (code || 'err')); return next(); }
      out.files++; out.bytes += body.length;
      harvest(body, url);
      // sourcemap declare dans le bundle
      RX_SMAP.lastIndex = 0;
      let sm;
      while ((sm = RX_SMAP.exec(body.toString('utf8'))) && out.maps.length < 12) {
        const mapUrl = new URL(sm[1], url).toString();
        if (out.maps.find(x => x.url === mapUrl)) continue;
        out.maps.push({ url: mapUrl, fetched: false, sources: [] });
      }
      next();
    });
  };
  // les .map declares : un 200 = le code source complet est public
  const nextMap = k => {
    if (k >= out.maps.length) return done(out);
    const mp = out.maps[k];
    get(mp.url, hdrs, 0, (err, code, body) => {
      if (!err && code === 200) {
        mp.fetched = true;
        try {
          const j = JSON.parse(body.toString('utf8'));
          mp.sources = (j.sources || []).slice(0, 20).map(s => String(s).replace(/^webpack:\/\//, ''));
        } catch (e) { mp.sources = []; }
      }
      nextMap(k + 1);
    });
  };

  // les pages servent aussi : les bundles references inline (script src) hors recon
  const findInline = pages => {
    let pend = pages.length;
    if (!pend) return findInline2();
    for (const pg of pages) {
      get(pg, hdrs, 0, (err, code, body) => {
        if (!err && code === 200) {
          const s = body.toString('utf8');
          const rx = /<script[^>]+src=["']([^"']+\.js[^"']*)["']/g;
          let m;
          while ((m = rx.exec(s)) && jsUrls.length < 24) {
            const j = new URL(m[1], pg).toString();
            if (!jsUrls.includes(j)) jsUrls.push(j);
          }
        }
        if (--pend === 0) findInline2();
      });
    }
  };
  const findInline2 = () => {
    if (jsUrls.length) { i = 0; next(); }
    else done(out);
  };
  if (pages.length) findInline(pages); else findInline2();
}

module.exports = { jsint, RX_SECRETS, RX_ENDPOINTS };