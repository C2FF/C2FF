// ============================================================
// C2FF - recon.js : discovery de la surface reelle d'une cible
// Zero dependance, GET only, budget strict. Sortie = surface.json :
// pages, endpoints API extraits des bundles JS, params, sous-domaines crt.sh.
// ============================================================
const https = require('https');
const fs = require('fs');
const path = require('path');

const REQ_TIMEOUT = 6000, GAP_MS = 300, MAX_PAGES = 15, MAX_JS = 10, MAX_TOTAL = 40, MAX_SUBS = 40;
// motifs endpoints dans les bundles JS : fetch("..."), axios.get('...'), "/api/..."
const JS_PATH = /["'`](\/[a-z0-9_][a-z0-9_\-./]{2,70})["'`]/g;
const JS_FETCH = /(?:fetch|axios\.\w+|\.open)\(\s*["'`]([^"'`]{3,90})["'`]/gi;
const HREF = /(?:href|action)\s*=\s*["']([^"']+)["']/gi;
const SCRIPT = /src\s*=\s*["']([^"']+\.(?:js|mjs)(?:\?[^"']*)?)["']/gi;
const INPUT = /<input[^>]+name\s*=\s*["']([a-zA-Z_][\w-]{1,24})["']/gi;
const QPARAM = /[?&]([a-zA-Z_][\w-]{1,20})=/g;
const ASSET_RE = /\.(png|jpe?g|gif|svg|ico|css|woff2?|ttf|eot|mp4|webm|pdf|zip|dmg|exe)(\?|$)/i;

function get(url, header, max) {
  return new Promise(res => {
    let req0;
    try { req0 = https.get(url, { headers: { 'user-agent': 'Mozilla/5.0 (C2FF-recon)', 'accept': '*/*', ...(header || {}) }, timeout: REQ_TIMEOUT }, r => {
      let raw = ''; let n = 0;
      r.on('data', d => { n += d.length; if (n <= (max || 300000)) raw += d; else r.destroy(); });
      r.on('end', () => res({ code: r.statusCode || 0, headers: r.headers || {}, body: raw }));
      r.on('error', () => res({ code: 0, headers: {}, body: '' }));
      r.on('aborted', () => res({ code: 0, headers: {}, body: '' }));
    }); } catch (e) { return res({ code: 0, headers: {}, body: '' }); }
    req0.on('timeout', () => { try { req0.destroy(); } catch (e) {} res({ code: 0, headers: {}, body: '' }); });
    req0.on('error', () => res({ code: 0, headers: {}, body: '' }));
  });
}
const sleep = ms => new Promise(r => setTimeout(r, ms));
const clean = s => String(s || '').replace(/&#x?\w+;/g, '').trim();

function onSite(host, u) { try { return new URL(u).host === host; } catch (e) { return false; } }

function abs(href, base) {
  href = clean(href);
  if (!href || href.startsWith('#') || /^(mailto|tel|javascript|data):/i.test(href)) return '';
  try { const u = new URL(href, base); return u.origin + u.pathname + (u.search || ''); } catch (e) { return ''; }
}

async function recon(base, header, log) {
  const T0 = Date.now();
  const pages = new Map(), apis = new Map(), js = new Map(), params = new Set(), subs = new Set();
  let nreq = 0;
  const queue = [base + '/'], seen = new Set();
  const tech = new Set();

  async function fetchPage(url) {
    nreq++; if (log) log('├ ' + url);
    const r = await get(url, header);
    if (!r.code) return null;
    const st = [r.headers.server, r.headers['x-powered-by'], r.headers['x-aspnet-version'], r.headers['x-generator']].filter(Boolean).join(' / ');
    if (st) tech.add(st);
    const lc = (url.split('?')[0]);
    if (lc.endsWith('.js') || lc.endsWith('.mjs')) return { js: r };
    return { html: r };
  }

  function harvestHtml(url, body) {
    for (const m of body.matchAll(HREF)) { const u = abs(m[1], url); if (u) queue.push(u.split('#')[0]); }
    for (const m of body.matchAll(SCRIPT)) { const u = abs(m[1], url); if (u && /\.m?js(\?|$)/i.test(u)) js.set(u.split('?')[0], js.get(u.split('?')[0]) || u); }
    for (const m of body.matchAll(INPUT)) if (m[1].toLowerCase() !== 'csrf') params.add(m[1].toLowerCase());
    for (const m of body.matchAll(QPARAM)) params.add(m[1].toLowerCase());
    for (const m of body.matchAll(/<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)/gi)) tech.add(m[1]);
  }

  function harvestJs(url, body) {
    const found = new Set();
    for (const m of body.matchAll(JS_PATH)) found.add(m[1]);
    for (const m of body.matchAll(JS_FETCH)) {
      const p = m[1].replace(/\$\{[^}]*\}/g, 'ID').replace(/[?&][a-z_][\w-]*=(?:\$\{[^}]*\}|null|true|\d+)?/gi, x => x);
      if (p.startsWith('/')) found.add(p.split('?')[0] + (p.split('?')[1] ? '?' + p.split('?')[1] : ''));
    }
    for (const p of found) {
      if (p.includes(' ') || /\.(html|php|jpg|png|svg|ico|css)$/i.test(p) && !p.includes('/api')) continue;
      if (p.length > 70) continue;
      const target = p.startsWith('/api') || /api|v[0-9]\//i.test(p) || p.endsWith('.json') ? apis : null;
      if (target) { target.set(p.split('?')[0], p); const q = p.split('?')[1] || ''; for (const mm of q.matchAll(QPARAM)) params.add(mm[1].toLowerCase()); }
    }
  }

  for (const q of [base + '/robots.txt', base + '/sitemap.xml']) {
    if (nreq >= MAX_TOTAL) break;
    const r = await get(q, header); nreq++;
    if (r.code === 200) {
      const sm = [...r.body.matchAll(/<loc>([^<]+)<\/loc>/gi)].map(x => clean(x[1])).filter(u => u.includes(new URL(base).host));
      for (const u of sm.slice(0, 10)) queue.push(u);
      // sous-domaines glans dans robots (sitemaps hors-domain ignores)
      for (const m of r.body.matchAll(/https?:\/\/([a-z0-9.-]+\.[a-z]{2,})/gi)) if (m[1].endsWith(new URL(base).host.replace(/^www\./, ''))) subs.add(m[1]);
    }
    await sleep(GAP_MS);
  }

  let npages = 0;
  if (log) log('├ crawl : queue=' + queue.length + ' subs=' + subs.size);
  while (queue.length && npages < MAX_PAGES && nreq < MAX_TOTAL) {
    const url = queue.shift().split('#')[0];
    if (seen.has(url) || !onSite(new URL(base).host, url)) continue;
    if (ASSET_RE.test(url)) continue;
    seen.add(url);
    const r = await fetchPage(url);
    if (!r) { await sleep(GAP_MS); continue; }
    if (r.html) {
      pages.set(url.split('?')[0], r.html.code);
      if ((r.html.headers['content-type'] || '').includes('html')) harvestHtml(url, r.html.body);
    } else if (r.js) harvestJs(url, r.js.body);
    npages++;
    await sleep(GAP_MS);
  }

  let njs = 0;
  for (const [k, u] of js) {
    if (njs >= MAX_JS || nreq >= MAX_TOTAL) break;
    if (k.startsWith('path:')) continue;
    if (seen.has(u)) continue;
    seen.add(u);
    const r = await fetchPage(u);
    if (r && r.html && (u.endsWith('.js') || u.includes('.js?'))) harvestJs(u, r.html.body);
    njs++;
    await sleep(GAP_MS);
  }

  // sous-domaines passifs via crt.sh (certificats transparence, 0 requete vers la cible)
  try {
    const host0 = new URL(base).host.replace(/^www\./, '');
    const r = await get('https://crt.sh/?q=%25.' + host0 + '&output=json', null);
    if (r.code === 200 && r.body.startsWith('[')) {
      const arr = JSON.parse(r.body).slice(0, 80);
      for (const e of arr) for (const n of String(e.name_value || '').split('\n'))
        if (n && !n.startsWith('*') && n.endsWith(host0)) subs.add(n.trim());
      if (log) log('├ crt.sh : ' + subs.size + ' sous-domaines');
    }
  } catch (e) {}
  const subList = [...subs].slice(0, MAX_SUBS);

  return {
    ts: new Date().toISOString(), ms: Date.now() - T0, reqs: nreq,
    pages: [...pages.keys()].slice(0, 40),
    apis: [...apis.entries()].slice(0, 60).map(([k, v]) => k),
    jsfiles: [...js.keys()].filter(k => !k.startsWith('path:')).slice(0, 20),
    params: [...params].slice(0, 60),
    tech: [...tech].slice(0, 5),
    subs: subList,
  };
}

module.exports = { recon };