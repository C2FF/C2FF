// ── fleet.js : moteur local autonome C2FF ─────────────────────────────
// Pas de tokens, pas de LLM : modules de probes deterministes en Node pur.
// Budget strict par cycle + dedupe : jamais de mass requests.
'use strict';
const fs = require('fs');
const { execFile } = require('child_process');

const fleet = {
  enabled: false, paused: false, program: 'etoro',
  intervalMin: 30, requestBudgetPerCycle: 60, gapMs: 600,
  modules: ['SECHEADERS', 'CORS', 'ERRLEAK', 'DOTFILES', 'TECHSIG', 'ROBOTS', 'OPTIONS', 'JSSECRETS'],
  activePrograms: [],
  lastCycle: null, lastResult: '', cycles: 0, busy: false,
  _file: null, _emit: null, _timer: null, _source: null,
};

// ---------- config ----------
function init(opts) { fleet._file = opts.file; fleet._emit = opts.onFinding; }
function load() {
  try {
    const f = JSON.parse(fs.readFileSync(fleet._file, 'utf8'));
    for (const k of ['enabled', 'paused', 'program', 'intervalMin', 'requestBudgetPerCycle', 'gapMs', 'modules', 'activePrograms']) {
      if (typeof f[k] !== 'undefined') fleet[k] = f[k];
    }
  } catch (e) {}
}
function save() { try { fs.writeFileSync(fleet._file, JSON.stringify(fleet, null, 1)); } catch (e) {} }
function state() {
  return {
    enabled: fleet.enabled, paused: fleet.paused, program: fleet.program, activePrograms: fleet.activePrograms,
    intervalMin: fleet.intervalMin, budget: fleet.requestBudgetPerCycle, modules: fleet.modules,
    lastCycle: fleet.lastCycle, lastResult: fleet.lastResult, cycles: fleet.cycles, busy: fleet.busy,
  };
}

// ---------- http via curl ----------
function req(url, extras, cb) {
  const args = ['-sS', '--max-time', '12', '-m', '12',
    '-A', 'Mozilla/5.0 (X11; Linux x86_64) C2FF-local/1.0 (authorized bug bounty testing)',
    ...extras, '-D', '-', '-o', '-', '-w', '\n__C2FF__%{http_code}', url];
  execFile('curl', args, { maxBuffer: 6e6 }, (err, stdout) => {
    if (!stdout) return cb({ code: 0, body: '', headers: {}, raw: '', err: err ? String(err.message || err) : 'no data' });
    const m = /__C2FF__(\d+)\s*$/.exec(stdout);
    const code = m ? parseInt(m[1], 10) : 0;
    const block = stdout.replace(/__C2FF__\d+\s*$/, '');
    let raw = block, body = '';
    const isSplit = block.indexOf('\r\n\r\n');
    const split = isSplit >= 0 ? isSplit : block.indexOf('\n\n');
    if (split > 0) {
      raw = block.slice(0, split);
      body = block.slice(split + (isSplit >= 0 ? 4 : 2));
    }
    const headers = {};
    for (const h of raw.toLowerCase().split(/\n/)) {
      const i = h.indexOf(':');
      if (i > 0) { const k = h.slice(0, i).trim(), v = h.slice(i + 1).trim(); if (!headers[k]) headers[k] = v; }
    }
    cb({ code, body, headers, raw });
  });
}
const sleep = ms => new Promise(r => setTimeout(r, ms));

function progHeader(p) {
  if (!p || !p.header || p.header === '-' || p.header === '') return null;
  const i = p.header.indexOf(':');
  if (i < 0) return null;
  return [p.header.slice(0, i).trim(), p.header.slice(i + 1).trim()];
}

// cibles : 1 hote representatif par wildcard, cap 8, jamais de mass scanning
function targetsFor(programs) {
  const list = (programs || []).filter(p => !fleet.activePrograms.length || fleet.activePrograms.includes(p.id));
  const targets = [], seen = new Set();
  for (const p of list) {
    const hh = progHeader(p);
    for (const s of p.scope || []) {
      let host = /^\*\./.test(s) ? 'www.' + s.slice(2) : (s.includes('.') ? s.replace(/^https?:\/\//, '') : null);
      if (!host) continue;
      host = host.replace(/\/.*$/, '');
      if (seen.has(host)) continue;
      seen.add(host);
      targets.push({ host, program: p.id, header: hh });
    }
  }
  return targets.slice(0, 8);
}

function addFinding(ctx, mod, cwe, sev, text) {
  if (!fleet._emit) return;
  fleet._emit({
    program: ctx.program, agent: 'LOCAL-' + mod, sev,
    text: '[CWE ' + cwe + '] ' + ctx.host + ' : ' + text,
  });
}
const autHeader = (ctx) => ctx.header ? ['-H', ctx.header[0] + ': ' + ctx.header[1]] : [];

// ---------- modules ----------
const MODULES = {
  // CWE-693 : headers de protection absents + CWE-200 stack visible
  SECHEADERS: (ctx) => new Promise(res => {
    req('https://' + ctx.host + '/', autHeader(ctx), ({ code, headers }) => {
      if (code >= 200 && code < 500) {
        const missing = [];
        for (const [h, name] of [['strict-transport-security', 'HSTS'], ['content-security-policy', 'CSP'], ['x-content-type-options', 'XCTO'], ['x-frame-options', 'XFO'], ['referrer-policy', 'Referrer-Policy'], ['cross-origin-opener-policy', 'COOP']])
          if (!headers[h]) missing.push(name);
        if (missing.length) addFinding(ctx, 'SECHEADERS', '693', 'SIG', 'headers de protection absents sur / : ' + missing.join(', '));
        const stack = [headers.server, headers['x-powered-by'], headers['x-aspnet-version']].filter(Boolean).join(' / ');
        if (stack) addFinding(ctx, 'TECHSIG', '200', 'SIG', 'stack visible : ' + stack);
      }
      res();
    });
  }),
  // CWE-614 / CWE-1004 : cookies sans Secure/HttpOnly (depuis SECHEADERS-like req)
  COOKFLAGS: (ctx) => new Promise(res => {
    req('https://' + ctx.host + '/', autHeader(ctx), ({ raw }) => {
      const cookies = raw.match(/set-cookie:([^\n]+)/gi) || [];
      for (const c of cookies.slice(0, 5)) {
        const lc = c.toLowerCase();
        if (lc.indexOf('httponly') < 0 || lc.indexOf('secure') < 0) {
          addFinding(ctx, 'COOKFLAGS', '614', 'SIG', 'cookie de session sans flag Secure/HttpOnly (' + c.slice(12, 44).trim() + '…)');
          break;
        }
      }
      res();
    });
  }),
  // CWE-942 : CORS permissif
  CORS: (ctx) => new Promise(res => {
    req('https://' + ctx.host + '/', ['-H', 'Origin: https://C2FF-probe.example', ...autHeader(ctx)], ({ headers }) => {
      const acao = headers['access-control-allow-origin'];
      if (acao && (acao === 'https://C2FF-probe.example' || acao === 'null')) {
        const creds = headers['access-control-allow-credentials'] === 'true';
        addFinding(ctx, 'CORS', '942', creds ? 'HIT' : 'SIG', 'CORS reflechit Origin arbitraire (ACAO=' + acao + (creds ? ', credentials=true' : '') + ')');
      }
      res();
    });
  }),
  // CWE-209 : leak d'erreurs sur 500
  ERRLEAK: (ctx) => new Promise(res => {
    sleep(700).then(() => req('https://' + ctx.host + '/__C2FF_404__' + (Date.now() % 100000), autHeader(ctx), ({ code, body }) => {
      if (code === 500) {
        const leak = /at [\/\w.:/-]+:\d+|Traceback|System\.\w+Exception|Microsoft \.NET|node_modules|Fatal error/i.exec(body);
        if (leak) addFinding(ctx, 'ERRLEAK', '209', 'SIG', 'stack trace / details internes dans une erreur 500');
      }
      res();
    }));
  }),
  // CWE-541 / CWE-538 : fichiers exposes
  DOTFILES: async (ctx) => {
    const files = ['/.git/config', '/.env', '/server-status', '/.DS_Store'];
    for (let i = 0; i < files.length; i++) {
      const f = files[i];
      await sleep(i * 400);
      const { code, body } = await new Promise(res => req('https://' + ctx.host + f, autHeader(ctx), ({ code, body }) => res({ code, body })));
      if (code === 200 && body.length > 20 && !/<html|<!doctype/i.test(body)) {
        addFinding(ctx, 'DOTFILES', f.includes('.git') ? '541' : '538', f.includes('.git') || f.includes('.env') ? 'HIT' : 'SIG', f + ' accessible (' + body.length + ' octets)');
      }
    }
  },
  // empreinte WordPress + REST ouvert
  TECHSIG: (ctx) => new Promise(res => {
    req('https://' + ctx.host + '/wp-json/', autHeader(ctx), ({ code, body }) => {
      if (code === 200 && /rest_route|"namespaces"|wp-content/.test(body)) {
        const names = /"namespaces":\[([^\]]*)\]/.exec(body);
        addFinding(ctx, 'TECHSIG', '718', 'SIG', 'WordPress REST ouvert, namespaces: ' + (names ? names[1].slice(0, 160) : 'inconnus'));
      }
      res();
    });
  }),
  // CWE-538 : divulgations robots.txt
  ROBOTS: (ctx) => new Promise(res => {
    req('https://' + ctx.host + '/robots.txt', autHeader(ctx), ({ code, body }) => {
      if (code === 200) {
        const hits = body.split('\n').filter(l => /admin|backup|secret|private|\.env|panel|internal|staging/i.test(l)).slice(0, 4);
        if (hits.length) addFinding(ctx, 'ROBOTS', '538', 'SIG', 'robots.txt reference des chemins sensibles: ' + hits.map(h => h.trim().slice(0, 80)).join(' | '));
      }
      res();
    });
  }),
  // CWE-942 : preflight permissif
  OPTIONS: (ctx) => new Promise(res => {
    req('https://' + ctx.host + '/', ['-X', 'OPTIONS', '-H', 'Origin: https://C2FF-probe.example', '-H', 'Access-Control-Request-Method: POST', ...autHeader(ctx)], ({ headers }) => {
      const allow = headers['access-control-allow-methods'] || headers.allow || '';
      if (headers['access-control-allow-origin'] === '*' && /delete|put/i.test(allow)) {
        addFinding(ctx, 'OPTIONS', '942', 'SIG', 'preflight CORS accepte DELETE/PUT (ACAO=*, Allow: ' + allow.slice(0, 80) + ')');
      }
      res();
    });
  }),
  // CWE-798 : secrets dans les bundles JS
  JSSECRETS: (ctx) => new Promise(res => {
    req('https://' + ctx.host + '/', autHeader(ctx), ({ code, body }) => {
      if (code !== 200) return res();
      const srcs = [...body.matchAll(/<script[^>]+src=["']([^"']+)["']/g)].map(m => m[1]).filter(s => s.startsWith('/') && /\.js[?"]/.test(s)).slice(0, 4);
      (function next(i) {
        if (i >= srcs.length) return res();
        req('https://' + ctx.host + srcs[i], autHeader(ctx), ({ code: c2, body: jb }) => {
          if (c2 === 200) {
            const SIGS = [
              [/AKIA[0-9A-Z]{16}/, '798', 'AWS access key'], [/sk_live_[A-Za-z0-9]{10,}/, '798', 'cle Stripe live'],
              [/AIza[A-Za-z0-9_-]{30,}/, '798', 'cle API Google'], [/ghp_[A-Za-z0-9]{20,}/, '798', 'token GitHub'],
              [/-----BEGIN (RSA |EC )?PRIVATE KEY-----/, '321', 'cle privee embarquee'],
              [/sk-[A-Za-z0-9]{20,}/, '798', 'cle API sk-'],
            ];
            for (const [re, cwe, label] of SIGS) {
              const m = re.exec(jb);
              if (m) { addFinding(ctx, 'JSSECRETS', cwe, 'HIT', label + ' dans ' + srcs[i] + ' : ' + m[0].slice(0, 50)); break; }
            }
          }
          next(i + 1);
        });
      })(0);
    });
  }),
};

// ---------- cycle ----------
async function cycle() {
  if (!fleet.enabled || fleet.paused || fleet.busy) return 0;
  fleet.busy = true;
  let budget = fleet.requestBudgetPerCycle, hits = 0, hosts = 0;
  try {
    const targets = targetsFor(fleet._source ? fleet._source() : []);
    for (const t of targets) {
      for (const m of fleet.modules) {
        if (budget <= 0) break;
        const mod = MODULES[m];
        if (!mod) continue;
        try { await mod({ host: t.host, program: t.program, header: t.header }); hits += 6; }
        catch (e) {}
        budget -= 6;
        await sleep(fleet.gapMs);
      }
      if (budget <= 0) break;
    }
    fleet.cycles++;
    fleet.lastCycle = new Date().toISOString();
    fleet.lastResult = 'cycle ' + fleet.cycles + ' : modules sur ' + targets.length + ' cible(s)';
  } catch (e) {
    fleet.lastResult = 'erreur cycle: ' + (e.message || e);
  }
  fleet.busy = false;
  save();
}
function startLoop() {
  if (fleet._timer) clearInterval(fleet._timer);
  fleet._timer = setInterval(() => { cycle().catch(() => {}); }, Math.max(5, fleet.intervalMin) * 60000);
}

module.exports = {
  init, load, save, state, targetsFor, cycle, startLoop,
  setSource: fn => { fleet._source = fn; },
  apply: patch => {
    for (const k of ['enabled', 'paused', 'program', 'intervalMin', 'requestBudgetPerCycle', 'gapMs', 'modules', 'activePrograms'])
      if (typeof patch[k] !== 'undefined') fleet[k] = patch[k];
    save();
    if (fleet.enabled && !fleet._timer) startLoop();
    return state();
  },
};