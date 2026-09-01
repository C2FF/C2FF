// ── fleet.js : moteur local autonome C2FF ─────────────────────────────
// Pas de tokens, pas de LLM : modules de probes deterministes en Node pur.
// Budget strict par cycle + dedupe : jamais de mass requests.
// Chaque module couvre une famille CWE ; les MODES regroupent les modules.
'use strict';
const fs = require('fs');
const { execFile } = require('child_process');

const fleet = {
  enabled: false, paused: false, program: '',
  intervalMin: 30, requestBudgetPerCycle: 60, gapMs: 600,
  mode: 'FULL',
  modules: ['SECHEADERS', 'COOKFLAGS', 'CORS', 'ERRLEAK', 'DOTFILES', 'TECHSIG', 'ROBOTS', 'OPTIONS', 'JSSECRETS',
            'XSSDUST', 'SQLIMAP', 'TRAVFILE', 'SSRFPROBE', 'REDIRCHECK', 'SSTIMARK', 'CMDIMARK',
            'XMLSPOT', 'JWTSPOT', 'IDORSCAN', 'UPLOADSPOT', 'EXPOSED'],
  activePrograms: [],
  lastCycle: null, lastResult: '', cycles: 0, busy: false,
  _file: null, _emit: null, _timer: null, _source: null,
};

// ---------- config ----------
function init(opts) { fleet._file = opts.file; fleet._emit = opts.onFinding; }
function load() {
  try {
    const f = JSON.parse(fs.readFileSync(fleet._file, 'utf8'));
    for (const k of ['enabled', 'paused', 'program', 'intervalMin', 'requestBudgetPerCycle', 'gapMs', 'mode', 'modules', 'activePrograms']) {
      if (typeof f[k] !== 'undefined') fleet[k] = f[k];
    }
    if (typeof fleet.mode !== 'string' || !fleet.mode) fleet.mode = 'FULL';
  } catch (e) {}
}
function save() { try { fs.writeFileSync(fleet._file, JSON.stringify(fleet, null, 1)); } catch (e) {} }
function state() {
  return {
    enabled: fleet.enabled, paused: fleet.paused, program: fleet.program, mode: fleet.mode,
    activePrograms: fleet.activePrograms,
    intervalMin: fleet.intervalMin, budget: fleet.requestBudgetPerCycle, modules: fleet.modules,
    lastCycle: fleet.lastCycle, lastResult: fleet.lastResult, cycles: fleet.cycles, busy: fleet.busy,
  };
}
// catalogue des modes, pour l'UI
function catalog() {
  return Object.entries(MODES).map(([key, m]) => ({
    key, label: m.label, cwes: m.cwes, desc: m.desc, n: m.modules.length,
  }));
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
// version Promise de req
function pReq(url, extras) { return new Promise(res => req(url, extras, r => res(r))); }

function progHeader(p) {
  if (!p || !p.header || p.header === '-' || p.header === '') return null;
  const i = p.header.indexOf(':');
  if (i < 0) return null;
  return [p.header.slice(0, i).trim(), p.header.slice(i + 1).trim()];
}

// cibles : 1 hote representatif par wildcard, cap 8, jamais de mass scanning.
// un scope peut porter un scheme complet (http://localhost:8080) pour cibler
// un service precis - le scheme est respecte, sinon https par defaut.
function targetsFor(programs, forceActive) {
  const active = forceActive && forceActive.length ? forceActive : fleet.activePrograms;
  const list = (programs || []).filter(p => !p.demo && (!active.length || active.includes(p.id)));
  const targets = [], seen = new Set();
  for (const p of list) {
    const hh = progHeader(p);
    for (const s of p.scope || []) {
      let host = '', scheme = 'https';
      const m = /^(https?):\/\/([^/]+)/.exec(s);
      if (m) { scheme = m[1]; host = m[2]; }
      else if (/^\*\./.test(s)) host = 'www.' + s.slice(2);
      else if (s.includes('.')) host = s.replace(/\s+only$/i, '');
      if (!host) continue;
      host = host.replace(/\/.*$/, '');
      if (seen.has(host)) continue;
      seen.add(host);
      targets.push({ host, base: scheme + '://' + host, program: p.id, header: hh });
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

// ============================================================
// MODULES - chaque module = 1 famille CWE, probes GET only,
// markers benigns, jamais plus de ~6 reqs.
// ============================================================
const MODULES = {
  // ---- configuration / durcissement ----
  // CWE-693 : headers de protection absents + CWE-200 stack visible
  SECHEADERS: (ctx) => new Promise(res => {
    req(ctx.base + '/', autHeader(ctx), ({ code, headers }) => {
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
  // CWE-614 / CWE-1004 : cookies sans Secure/HttpOnly
  COOKFLAGS: (ctx) => new Promise(res => {
    req(ctx.base + '/', autHeader(ctx), ({ raw }) => {
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
    req(ctx.base + '/', ['-H', 'Origin: https://C2FF-probe.example', ...autHeader(ctx)], ({ headers }) => {
      const acao = headers['access-control-allow-origin'];
      if (acao && (acao === 'https://C2FF-probe.example' || acao === 'null')) {
        const creds = headers['access-control-allow-credentials'] === 'true';
        addFinding(ctx, 'CORS', '942', creds ? 'HIT' : 'SIG', 'CORS reflechit Origin arbitraire (ACAO=' + acao + (creds ? ', credentials=true' : '') + ')');
      }
      res();
    });
  }),
  // CWE-942 : preflight permissif
  OPTIONS: (ctx) => new Promise(res => {
    req(ctx.base + '/', ['-X', 'OPTIONS', '-H', 'Origin: https://C2FF-probe.example', '-H', 'Access-Control-Request-Method: POST', ...autHeader(ctx)], ({ headers }) => {
      const allow = headers['access-control-allow-methods'] || headers.allow || '';
      if (headers['access-control-allow-origin'] === '*' && /delete|put/i.test(allow)) {
        addFinding(ctx, 'OPTIONS', '942', 'SIG', 'preflight CORS accepte DELETE/PUT (ACAO=*, Allow: ' + allow.slice(0, 80) + ')');
      }
      res();
    });
  }),

  // ---- injection ----
  // CWE-79 : reflection user-input sans encodage (XSS candidat)
  XSSDUST: async (ctx) => {
    const { code: c0, body: html } = await pReq(ctx.base + '/', autHeader(ctx));
    if (c0 < 200 || c0 >= 500) return;
    const names = new Set(['q', 's', 'search', 'query', 'keyword']);
    for (const m of html.matchAll(/<input[^>]+name=["']([^"']{1,24})["']/gi)) names.add(m[1].toLowerCase());
    for (const p of [...names].slice(0, 4)) {
      const { code, body } = await pReq(ctx.base + '/?' + p + '=' + encodeURIComponent('c2ff"\'><svg onload=c2ff>'), autHeader(ctx));
      if (code >= 200 && code < 500 && body.includes('<svg onload=c2ff>')) {
        addFinding(ctx, 'XSSDUST', '79', 'SIG', 'parametre ?' + p + ' reflechi sans encodage sur / - XSS a confirmer');
      }
      await sleep(400);
    }
  },
  // CWE-89 : erreurs SQL au quote simple (SQLI candidat)
  SQLIMAP: async (ctx) => {
    const { code: c0, body: html } = await pReq(ctx.base + '/', autHeader(ctx));
    if (c0 < 200 || c0 >= 500) return;
    const names = new Set(['id', 'q', 'page', 'cat', 'user']);
    for (const m of html.matchAll(/<input[^>]+name=["']([^"']{1,24})["']/gi)) names.add(m[1].toLowerCase());
    const SQLERR = /(SQL syntax|SQLSTATE\[?\w*|ORA-\d{5}|psql:.*(ERROR|FATAL)|SQLite3?::|mysqli?_|unterminated quoted string|ODBC SQL|System\.Data\.SqlClient|PG::\w+Error)/i;
    for (const p of [...names].slice(0, 4)) {
      const { code, body } = await pReq(ctx.base + '/?' + p + '=c2ff%27', autHeader(ctx));
      if (code >= 200 && code < 600 && SQLERR.test(body)) {
        addFinding(ctx, 'SQLIMAP', '89', 'SIG', 'erreur SQL au quote simple sur ?' + p + ' - injection a confirmer');
      }
      await sleep(400);
    }
  },
  // CWE-22 / CWE-98 : path traversal / LFI via params de fichiers
  TRAVFILE: async (ctx) => {
    const names = ['file', 'path', 'page', 'include', 'template', 'view', 'lang', 'doc'];
    const seen = new Set();
    for (const p of names) {
      if (seen.has(p)) continue;
      seen.add(p);
      const { code, body } = await pReq(ctx.base + '/?' + p + '=..%2f..%2f..%2f..%2fetc%2fpasswd', autHeader(ctx));
      if (code >= 200 && code < 500 && body.includes('root:') && /\/bin\/(bash|sh|nologin)/.test(body)) {
        addFinding(ctx, 'TRAVFILE', '22', 'HIT', 'traversal/LFI via ?' + p + ' : /etc/passwd lu');
        break;
      }
      await sleep(400);
    }
  },
  // CWE-918 : SSRF candidats via params de fetch d'urls
  SSRFPROBE: async (ctx) => {
    const names = ['url', 'src', 'uri', 'img', 'fetch', 'remote', 'target', 'load', 'feed'];
    for (const p of names.slice(0, 4)) {
      const { code, body } = await pReq(ctx.base + '/?' + p + '=http%3A%2F%2Fc2ff-ssrf.invalid%2F', autHeader(ctx));
      if (code >= 200 && code < 500 && /c2ff-ssrf\.invalid/i.test(body)) {
        addFinding(ctx, 'SSRFPROBE', '918', 'SIG', 'parametre ?' + p + ' traite une url arbitraire (erreur reflechie) - SSRF a confirmer');
        break;
      }
      await sleep(400);
    }
  },
  // CWE-601 : open redirect
  REDIRCHECK: async (ctx) => {
    const names = ['redirect', 'next', 'url', 'return', 'returnTo', 'continue', 'dest', 'rurl', 'target'];
    for (const p of names.slice(0, 5)) {
      const { code, headers } = await pReq(ctx.base + '/?' + p + '=//c2ff-probe.invalid', autHeader(ctx));
      if (code >= 300 && code < 400 && (headers.location || '').includes('c2ff-probe.invalid')) {
        addFinding(ctx, 'REDIRCHECK', '601', 'HIT', 'open redirect via ?' + p + ' : Location=' + headers.location.slice(0, 80));
        break;
      }
      await sleep(400);
    }
  },
  // CWE-1336 : SSTI (evaluation de template)
  SSTIMARK: async (ctx) => {
    const names = ['name', 'template', 'view', 'msg', 'content', 'subject'];
    for (const p of names.slice(0, 4)) {
      const { code, body } = await pReq(ctx.base + '/?' + p + '=C2FF%7B%7B7%2A7%7D%7DZ', autHeader(ctx));
      if (code >= 200 && code < 500 && body.includes('C2FF49Z')) {
        addFinding(ctx, 'SSTIMARK', '1336', 'HIT', 'SSTI confirme sur ?' + p + ' : {{7*7}} evalue en 49');
        break;
      }
      await sleep(400);
    }
  },
  // CWE-78 : execution de commande (probe douce, detection uid= seulement)
  CMDIMARK: async (ctx) => {
    const names = ['cmd', 'exec', 'host', 'ip', 'ping', 'domain'];
    for (const p of names.slice(0, 3)) {
      const { code, body } = await pReq(ctx.base + '/?' + p + '=C2FF%3Bid', autHeader(ctx));
      if (code >= 200 && code < 500 && /uid=\d+\(\w+\)/.test(body)) {
        addFinding(ctx, 'CMDIMARK', '78', 'HIT', 'RCE possible sur ?' + p + ' : sortie de id() visible');
        break;
      }
      await sleep(400);
    }
  },
  // CWE-611 : surfaces XML/SOAP - XXE a tester hors bande par l'agent
  XMLSPOT: async (ctx) => {
    const { code, body } = await pReq(ctx.base + '/', autHeader(ctx));
    if (code >= 200 && code < 500 && /xmlns:soap|<wsdl|<soapenv/i.test(body)) {
      addFinding(ctx, 'XMLSPOT', '611', 'SIG', 'surface SOAP/WSDL detectee sur / - XXE a tester manuellement (out-of-band requis)');
      return;
    }
    for (const path of ['/wsdl', '/soap', '/service?wsdl']) {
      const r2 = await pReq(ctx.base + path, autHeader(ctx));
      if (r2.code === 200 && /<wsdl|<soapenv|xmlns:soap/i.test(r2.body)) {
        addFinding(ctx, 'XMLSPOT', '611', 'SIG', 'surface SOAP/WSDL detectee sur ' + path + ' - XXE a tester manuellement');
        break;
      }
      await sleep(350);
    }
  },
  // CWE-347 / CWE-287 : JWT rencontres a envoyer au lab auth
  JWTSPOT: async (ctx) => {
    const { code, raw, body } = await pReq(ctx.base + '/', autHeader(ctx));
    if (code < 200 || code >= 500) return;
    const jwt = /eyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*/.exec(raw + ' ' + body);
    if (jwt) {
      const head = (() => { try { return JSON.parse(Buffer.from(jwt[0].split('.')[0], 'base64url').toString()); } catch (e) { return {}; } })();
      const alg = head.alg || 'inconnu';
      addFinding(ctx, 'JWTSPOT', '287/347', 'SIG', 'JWT rencontre (alg : ' + alg + ') - lab auth a mener : alg none, kid injection, confusion HS/RS, claims');
    }
  },
  // CWE-639 / BOLA : references d'objets exposees cote client
  IDORSCAN: async (ctx) => {
    const { code, body } = await pReq(ctx.base + '/', autHeader(ctx));
    if (code !== 200) return;
    const refs = new Set();
    for (const m of body.matchAll(/["'`](\/[a-z0-9_./-]{3,60}\/(?:\d{3,}|[0-9a-f]{8}-[0-9a-f-]{27}))["'`]/gi)) {
      refs.add(m[1]);
      if (refs.size >= 4) break;
    }
    if (refs.size) {
      addFinding(ctx, 'IDORSCAN', '639', 'SIG', 'references d\'objets exposees cote client (IDOR/BOLA a tester avec creds) : ' + [...refs].join(' | '));
    }
  },
  // CWE-434 : surfaces d'upload detectees - test manuel requis
  UPLOADSPOT: async (ctx) => {
    const { code, body } = await pReq(ctx.base + '/', autHeader(ctx));
    if (code < 200 || code >= 500) return;
    const spots = [];
    if (/type=["']?file/i.test(body)) spots.push('input type=file');
    for (const m of body.matchAll(/action=["']([^"']*upload[^"']*)["']/gi)) { spots.push('action=' + m[1].slice(0, 60)); break; }
    if (spots.length) addFinding(ctx, 'UPLOADSPOT', '434', 'SIG', 'surface d\'upload detectee (' + spots.join(', ') + ') - bypass filtre a tester avec creds');
  },

  // ---- fichiers exposes / info leak ----
  // CWE-209 : leak d'erreurs sur 500
  ERRLEAK: (ctx) => new Promise(res => {
    sleep(700).then(() => req(ctx.base + '/__C2FF_404__' + (Date.now() % 100000), autHeader(ctx), ({ code, body }) => {
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
      const { code, body } = await pReq(ctx.base + f, autHeader(ctx));
      if (code === 200 && body.length > 20 && !/<html|<!doctype/i.test(body)) {
        addFinding(ctx, 'DOTFILES', f.includes('.git') ? '541' : '538', f.includes('.git') || f.includes('.env') ? 'HIT' : 'SIG', f + ' accessible (' + body.length + ' octets)');
      }
    }
  },
  // empreinte WordPress + REST ouvert
  TECHSIG: (ctx) => new Promise(res => {
    req(ctx.base + '/wp-json/', autHeader(ctx), ({ code, body }) => {
      if (code === 200 && /rest_route|"namespaces"|wp-content/.test(body)) {
        const names = /"namespaces":\[([^\]]*)\]/.exec(body);
        addFinding(ctx, 'TECHSIG', '718', 'SIG', 'WordPress REST ouvert, namespaces: ' + (names ? names[1].slice(0, 160) : 'inconnus'));
      }
      res();
    });
  }),
  // CWE-538 : divulgations robots.txt
  ROBOTS: (ctx) => new Promise(res => {
    req(ctx.base + '/robots.txt', autHeader(ctx), ({ code, body }) => {
      if (code === 200) {
        const hits = body.split('\n').filter(l => /admin|backup|secret|private|\.env|panel|internal|staging/i.test(l)).slice(0, 4);
        if (hits.length) addFinding(ctx, 'ROBOTS', '538', 'SIG', 'robots.txt reference des chemins sensibles: ' + hits.map(h => h.trim().slice(0, 80)).join(' | '));
      }
      res();
    });
  }),
  // CWE-798 / CWE-321 : secrets dans les bundles JS
  JSSECRETS: (ctx) => new Promise(res => {
    req(ctx.base + '/', autHeader(ctx), ({ code, body }) => {
      if (code !== 200) return res();
      const srcs = [...body.matchAll(/<script[^>]+src=["']([^"']+)["']/g)].map(m => m[1]).filter(s => s.startsWith('/') && /\.js[?"]/.test(s)).slice(0, 4);
      (function next(i) {
        if (i >= srcs.length) return res();
        req(ctx.base + srcs[i], autHeader(ctx), ({ code: c2, body: jb }) => {
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
  // CWE-284 : consoles / admins exposes
  EXPOSED: async (ctx) => {
    for (const path of ['/admin', '/console', '/manager', '/administrator']) {
      const { code, body } = await pReq(ctx.base + path, autHeader(ctx));
      if (code === 200 && body.length > 200 && !/<form[^>]*password|sign ?in|log ?in/i.test(body)) {
        addFinding(ctx, 'EXPOSED', '284', 'SIG', 'reponse 200 non-auth sur ' + path + ' (' + body.length + ' octets) - acces a verifier');
      }
      await sleep(350);
    }
  },
};

// ============================================================
// MODES - un mode = un paquet de modules sur une famille CWE.
// FULL SWEEP = tous les modules. C'est la liste proposee en UI ;
// GO lance le mode LOCALEMENT, sans aucun agent ni IA.
// ============================================================
const MODES = {
  FULL:     { label: 'FULL SWEEP',  cwes: 'toutes',     desc: 'tous les modules : sweep complet de la surface', modules: Object.keys(MODULES) },
  'SEC-CFG':{ label: 'SEC-CFG',     cwes: '693/614/942',desc: 'headers, cookies, CORS, preflight', modules: ['SECHEADERS', 'COOKFLAGS', 'CORS', 'OPTIONS'] },
  XSS:      { label: 'XSS',         cwes: '79',         desc: 'reflection user-input sans encodage sur les params', modules: ['XSSDUST'] },
  SQLI:     { label: 'SQLI',        cwes: '89',         desc: 'erreurs SQL au quote simple sur les params', modules: ['SQLIMAP'] },
  LFI:      { label: 'LFI',         cwes: '22/98',      desc: 'traversal / include de fichiers via params', modules: ['TRAVFILE', 'DOTFILES'] },
  SSRF:     { label: 'SSRF',        cwes: '918',        desc: 'params de fetch d\'urls arbitraires', modules: ['SSRFPROBE'] },
  REDIR:    { label: 'OPEN-REDIR',  cwes: '601',        desc: 'redirect ouverts sur les params de navigation', modules: ['REDIRCHECK'] },
  'SSTI-RCE':{ label: 'SSTI/RCE',   cwes: '1336/78',    desc: 'evaluation de template puis commande', modules: ['SSTIMARK', 'CMDIMARK'] },
  XXE:      { label: 'XXE',         cwes: '611',        desc: 'surfaces XML/SOAP a tester hors bande', modules: ['XMLSPOT'] },
  AUTH:     { label: 'AUTH/JWT',    cwes: '287/347',    desc: 'JWT rencontres + axes de lab tokens', modules: ['JWTSPOT'] },
  IDOR:     { label: 'BOLA/IDOR',   cwes: '639',        desc: 'references d\'objets exposees cote client', modules: ['IDORSCAN'] },
  UPLOAD:   { label: 'UPLOAD',      cwes: '434',        desc: 'surfaces d\'upload a bypasser', modules: ['UPLOADSPOT'] },
  SECRETS:  { label: 'SECRETS',     cwes: '798/321',    desc: 'cles et secrets dans les bundles JS', modules: ['JSSECRETS'] },
  INFO:     { label: 'INFO-LEAK',   cwes: '209/200/538/541/718', desc: 'stack traces, dotfiles, robots, empreintes', modules: ['ERRLEAK', 'DOTFILES', 'ROBOTS', 'TECHSIG'] },
  EXPOSED:  { label: 'EXPOSED',     cwes: '284',        desc: 'consoles et interfaces d\'admin non protegees', modules: ['EXPOSED'] },
};

// ---------- cycle ----------
async function cycle(opts) {
  if (!fleet.enabled || fleet.paused || fleet.busy) return 0;
  fleet.busy = true;
  let budget = fleet.requestBudgetPerCycle, hits = 0, hosts = 0;
  try {
    const targets = targetsFor(fleet._source ? fleet._source() : [], opts && opts.program ? [opts.program] : null);
    const mode = MODES[fleet.mode] || MODES.FULL;
    const mods = fleet.mode && fleet.mode !== 'FULL' ? mode.modules : fleet.modules;
    for (const t of targets) {
      hosts++;
      for (const m of mods) {
        if (budget <= 0) break;
        const mod = MODULES[m];
        if (!mod) continue;
        try { await mod({ host: t.host, base: t.base, program: t.program, header: t.header }); hits += 6; }
        catch (e) {}
        budget -= 6;
        await sleep(fleet.gapMs);
      }
      if (budget <= 0) break;
    }
    fleet.cycles++;
    fleet.lastCycle = new Date().toISOString();
    fleet.lastResult = 'cycle ' + fleet.cycles + ' : mode ' + fleet.mode + ' sur ' + hosts + ' cible(s)';
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
  init, load, save, state, targetsFor, cycle, startLoop, catalog,
  setSource: fn => { fleet._source = fn; },
  apply: patch => {
    for (const k of ['enabled', 'paused', 'program', 'intervalMin', 'requestBudgetPerCycle', 'gapMs', 'mode', 'modules', 'activePrograms'])
      if (typeof patch[k] !== 'undefined') fleet[k] = patch[k];
    save();
    if (fleet.enabled && !fleet._timer) startLoop();
    return state();
  },
};