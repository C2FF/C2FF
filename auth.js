// ============================================================
// C2FF - auth.js : creds par programme, injectees dans chaque requete
// Format libre, une ligne par entree :
//   Authorization: Bearer eyJ...      (tout header est accepte)
//   Cookie: session=abc; uid=42
//   Bearer eyJ...                     (raccourci -> Authorization)
//   user:pass                         (raccourci -> Authorization Basic)
// Le test compare une requete avec et sans creds : la difference EST la preuve.
// ============================================================
'use strict';
const https = require('https');
const http = require('http');
const { URL } = require('url');

const TIMEOUT = 15000;

function parse(creds) {
  const o = { headers: {}, cookies: {}, kinds: [] };
  for (const raw of String(creds || '').split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    if (/^Bearer\s+/i.test(line)) { o.headers['authorization'] = 'Bearer ' + line.replace(/^Bearer\s+/i, ''); continue; }
    if (/^Basic\s+/i.test(line) && !line.includes(': ') || /^[A-Za-z0-9._%+-]+:[^\s]+$/.test(line) && !line.includes(': ')) {
      const b = Buffer.from(line).toString('base64');
      o.headers['authorization'] = 'Basic ' + b; continue;
    }
    const i = line.indexOf(':');
    if (i < 1) continue;
    const k = line.slice(0, i).trim(), v = line.slice(i + 1).trim();
    if (!k || !v) continue;
    if (/^cookie$/i.test(k)) {
      for (const kv of v.split(';')) {
        const j = kv.indexOf('=');
        if (j > 0) o.cookies[kv.slice(0, j).trim()] = kv.slice(j + 1).trim();
      }
      continue;
    }
    o.headers[k.toLowerCase()] = v;
  }
  if (Object.keys(o.cookies).length) {
    o.headers['cookie'] = Object.entries(o.cookies).map(([k, v]) => k + '=' + v).join('; ');
    o.kinds.push('cookies(' + Object.keys(o.cookies).length + ')');
  }
  if (o.headers.authorization) o.kinds.push(o.headers.authorization.split(' ')[0].toLowerCase());
  for (const k of Object.keys(o.headers)) if (k !== 'authorization' && k !== 'cookie') o.kinds.push(k);
  return o;
}

// masque les valeurs : on ne montre que les 4 derniers caracteres
function mask(creds) {
  return String(creds || '').split(/\r?\n/).map(l => {
    const i = l.indexOf(':');
    if (i < 1 || l.trim().length < 8) return l;
    const v = l.slice(i + 1).trim();
    return l.slice(0, i) + ': ' + (v.length > 8 ? v.slice(0, 3) + '…' + v.slice(-4) : '…');
  }).filter(l => l.trim()).join('\n');
}

// headers complets pour une requete vers prog : header chercheur + creds
function hdrsFor(prog) {
  const h = {};
  if (prog && prog.header && prog.header.includes(':')) {
    const i = prog.header.indexOf(':');
    h[prog.header.slice(0, i).trim()] = prog.header.slice(i + 1).trim();
  }
  const p = parse(prog && prog.creds);
  return Object.assign(h, p.headers);
}

function get(url, hdrs, cb) {
  const u = new URL(url);
  const mod = u.protocol === 'http:' ? http : https;
  const req = mod.get(url, {
    headers: { 'user-agent': 'Mozilla/5.0 (C2FF-auth)', accept: '*/*', ...(hdrs || {}) },
    timeout: TIMEOUT,
    rejectUnauthorized: false,
  }, r => {
    const chunks = [];
    let n = 0;
    r.on('data', c => { n += c.length; if (n <= 1024 * 1024) chunks.push(c); else r.destroy(); });
    r.on('end', () => cb(null, r.statusCode, Buffer.concat(chunks)));
    r.on('error', e => cb(e, r.statusCode || 0, Buffer.concat(chunks)));
  });
  req.on('timeout', () => req.destroy(new Error('timeout')));
  req.on('error', e => cb(e, 0, Buffer.alloc(0)));
}

// probe : une requete avec creds, une sans - la difference est la preuve
// cible = page ou API a tester (defaut : la base du programme)
function probe(prog, target, done) {
  const host = String((prog && (prog.scope && prog.scope[0])) || '').replace(/^\*\./, '');
  const url = target || (host ? 'https://' + host : '');
  if (!url) return done({ ok: false, err: 'aucune cible (scope vide)' });
  const hh = hdrsFor(prog);
  const authd = Object.keys(parse(prog && prog.creds).headers).length > 0;
  let withR = null, withoutR = null;
  let pend = 2;
  const fin = () => {
    if (--pend > 0) return;
    const w = withR || {}, wo = withoutR || {};
    const diffStatus = (w.status || 0) !== (wo.status || 0);
    const lenA = w.len || 0, lenB = wo.len || 0;
    const diffBody = Math.abs(lenA - lenB) > 64;
    const verdict = !authd ? 'no-auth'
      : (diffStatus || diffBody) ? 'auth-effect'
      : ((w.status || 0) >= 200 && (w.status || 0) < 300 ? 'auth-200' : 'no-diff');
    done({
      ok: true,
      target: url,
      kinds: parse(prog && prog.creds).kinds,
      verdict,
      with: { status: w.status, len: lenA },
      without: { status: wo.status, len: lenB },
    });
  };
  get(url, hh, (e, s, b) => { withR = { err: e ? e.message : null, status: s, len: b ? b.length : 0 }; fin(); });
  get(url, {}, (e, s, b) => { withoutR = { err: e ? e.message : null, status: s, len: b ? b.length : 0 }; fin(); });
}

module.exports = { parse, mask, hdrsFor, probe };