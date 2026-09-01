// ============================================================
// C2FF - urls.js : collecte passive d URLs (wayback CDX + OTX)
//  - historique d URLs du domaine : endpoints oublies, anciennes API
//  - mining de params : les noms de params existants guident les tests
//  - extensions sensibles (json/bak/xml/sql/zip) et endpoints API
// Passif 100% : aucune requete vers la cible elle-meme.
// ============================================================
'use strict';
const https = require('https');
const { URL } = require('url');

const TIMEOUT = 20000;
const MAX_URLS = 800;
const CDX_LIMIT = 3000;
const OTX_PAGES = 3;

function get(url, hdrs, cb) {
  const u = new URL(url);
  const req = https.get(url, {
    headers: { 'user-agent': 'Mozilla/5.0 (C2FF-urls)', accept: 'application/json,text/plain,*/*', ...(hdrs || {}) },
    timeout: TIMEOUT,
    rejectUnauthorized: false,
  }, r => {
    const chunks = [];
    let n = 0;
    r.on('data', c => { n += c.length; if (n <= 4 * 1024 * 1024) chunks.push(c); else r.destroy(); });
    r.on('end', () => cb(null, r.statusCode, Buffer.concat(chunks)));
    r.on('error', e => cb(e, r.statusCode || 0, Buffer.concat(chunks)));
  });
  req.on('timeout', () => req.destroy(new Error('timeout')));
  req.on('error', e => cb(e, 0, Buffer.alloc(0)));
}

// domaine de base : garde host cible + sous-domaines (foo.api.x.com garde x.com)
function baseDomain(host) {
  const p = String(host || '').split('.').filter(Boolean);
  if (p.length <= 2) return p.join('.');
  const two = ['co.uk', 'com.br', 'com.mx', 'com.ar', 'co.jp', 'com.au', 'org.uk', 'co.za', 'com.sg', 'com.tr'];
  const last2 = p.slice(-2).join('.');
  if (two.includes(last2)) return p.slice(-3).join('.');
  return last2;
}

function urls(surf, prog, done) {
  const host = String(surf.host || '').replace(/^www\./, '');
  if (!host) return done({ ts: Date.now(), host, total: 0, urls: [], params: [], endpoints: [], exts: {}, errs: ['host vide'] });
  const base = baseDomain(host);
  const out = { ts: Date.now(), host, base, total: 0, urls: [], params: [], endpoints: [], exts: {}, errs: [] };
  const seen = new Set();
  const add = u => {
    u = String(u || '').split('#')[0];
    if (!/^https?:\/\//.test(u) || seen.has(u)) return;
    let h; try { h = new URL(u).hostname; } catch (e) { return; }
    if (h !== base && !h.endsWith('.' + base)) return; // hors scope
    seen.add(u);
    if (out.urls.length < MAX_URLS) out.urls.push(u);
  };

  let pend = 1 + OTX_PAGES;
  const fin = () => {
    if (--pend > 0) return;
    // mining des params : nom -> {n, ex}
    const pm = {};
    for (const u of seen) {
      const q = u.split('?')[1];
      if (!q) continue;
      for (const kv of q.split('&')) {
        const p = decodeURIComponent(kv.split('=')[0] || '').trim();
        if (!p || p.length > 40) continue;
        if (!pm[p]) pm[p] = { p, n: 0, ex: '' };
        pm[p].n++;
        if (!pm[p].ex && kv.includes('=')) { const v = kv.split('=').slice(1).join('='); if (v) pm[p].ex = v.slice(0, 60); }
      }
    }
    out.params = Object.values(pm).sort((a, b) => b.n - a.n).slice(0, 60);
    // endpoints API + extensions
    const exts = {};
    const eps = new Set();
    for (const u of seen) {
      let uu; try { uu = new URL(u); } catch (e) { continue; }
      const m = /\/([a-z0-9_.\-]+\.(json|xml|sql|zip|bak|conf|env|yaml|yml|log|csv|txt|map))$/i.exec(uu.pathname);
      if (m) { exts[m[2].toLowerCase()] = (exts[m[2].toLowerCase()] || 0) + 1; }
      if (/\/(api|v[1-9]|rest|graphql|internal|admin|private)(\/|$)/i.test(uu.pathname)) {
        const ep = uu.origin + uu.pathname;
        if (eps.size < 150) eps.add(ep);
      }
    }
    out.exts = exts;
    out.endpoints = [...eps];
    out.total = seen.size;
    done(out);
  };

  // 1. wayback CDX
  const cdx = 'https://web.archive.org/cdx/search/cdx?url=' + base + '&matchType=domain&output=json&collapse=urlkey&fl=original&limit=' + CDX_LIMIT + '&filter=statuscode:200';
  get(cdx, null, (err, code, body) => {
    if (!err && code === 200) {
      try {
        const rows = JSON.parse(body.toString('utf8'));
        for (let i = 1; i < rows.length; i++) add(rows[i][0]);
      } catch (e) { out.errs.push('cdx: parse ' + e.message.slice(0, 40)); }
    } else out.errs.push('cdx: ' + (code || 'err'));
    fin();
  });
  // 2. OTX pages 1..3
  for (let pg = 1; pg <= OTX_PAGES; pg++) {
    const otx = 'https://otx.alienvault.com/api/v1/indicators/domain/' + base + '/url_list?limit=100&page=' + pg;
    get(otx, null, (err, code, body) => {
      if (!err && code === 200) {
        try {
          const j = JSON.parse(body.toString('utf8'));
          for (const r of (j.url_list || [])) add(r.url);
        } catch (e) { out.errs.push('otx' + pg + ': parse'); }
      } else if (pg === 1) out.errs.push('otx: ' + (code || 'err'));
      fin();
    });
  }
}

module.exports = { urls, baseDomain };