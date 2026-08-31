// ── C2//FLEET client ─────────────────────────────────────────────────────
'use strict';
const $ = id => document.getElementById(id);
const esc = s => String(s == null ? '' : s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
const HL = [
  [/\bP1\b/g, 'p1'], [/\bP2\b/g, 'p2'], [/\bP3\b/g, 'p3'],
  [/(secret|credential|passwd|token)/gi, 'hl-c'],
  [/(bypass|bola|idor|sqli|traversal|injection|ssrf|ssti|lfi|unauthorized|redirect|race)/gi, 'hl-x'],
];
function hl(t) {
  let s = esc(t);
  for (const [r, c] of HL) s = s.replace(r, '<span class="' + c + '">$&</span>');
  return s;
}

const PLAYBOOKS = [
  ['RECON-HORIZON', 'Recon large : axes BIZLOGIC / AUTH-JWT / JS / N-DAY / subs / etoroX / mobile (7 axes + judge)'],
  ['SQLI-DUO', 'Pipeline SQLI : recon params injectables -> offensive ciblee (boolean/time/error)'],
  ['SSRF-DUO', 'Pipeline SSRF : surfaces de fetch d URL -> offensive (metadata, redirect chaines)'],
  ['LFI-WAVE', 'Vague LFI : traversals, include, file read sur la surface cible'],
  ['JACKPOT-SITE', '1 agent effort max sur un site/hote cible : carte exhaustive + chaines'],
  ['RCE-SSTI-DUO', 'Pipeline RCE/SSTI : detect moteur -> probes {{7*7}} / php-format'],
  ['BOLA-IDOR-SWEEP', 'Balayage BOLA/IDOR : identifiants numeriques et UUID croises (auth necessaire)'],
  ['JWT-JWE-LAB', 'Lab token : JWE/JWT universels, claims, audience cross-service (creds requis)'],
  ['N-DAY-DORK', 'N-day + dorking : CVE publiees du stack detectee + dorks Google/GitHub'],
  ['JUDGE-TOP6', 'Judge : tri les hypotheses de la flotte, TOP actions par severite defendable'],
];

const state = { tab: 'live', chatSeen: 0, fndSeen: 0, firstLoad: true, unread: 0, data: { runs: [], findings: [], programs: [], chat: [] } };
const expanded = new Set();

const TABS = { live: 'FLOTTE', findings: 'FINDINGS', programs: 'PROGRAMMES', chat: 'COORDINATION' };
function setTab(t) {
  state.tab = t;
  document.querySelectorAll('.navbtn').forEach(b => b.classList.toggle('active', b.dataset.tab === t));
  document.querySelectorAll('.view').forEach(v => v.classList.toggle('active', v.id === 'v-' + t));
  if (t === 'chat') { state.unread = 0; }
}

// ---------- toasts ----------
function toast(title, text, cls) {
  const el = document.createElement('div');
  el.className = 'toast ' + (cls || '');
  el.innerHTML = '<div class="th">' + esc(title) + '</div><div class="tt">' + hl(text) + '</div>';
  if (cls === 'P1' || cls === 'P2') {
    el.addEventListener('click', () => { setTab('findings'); document.querySelectorAll('.navbtn').forEach(x => { if (x.dataset.tab === 'findings') x.click(); }); });
  }
  $('toasts').appendChild(el);
  setTimeout(() => { el.classList.add('gone'); setTimeout(() => el.remove(), 350); }, cls === 'P1' ? 14000 : 8000);
}

// ---------- rendu flux ----------
function drawRuns(runs) {
  $('nRun').textContent = String(runs.length);
  const act = runs.reduce((s, r) => s + (r.n - r.done), 0);
  $('sRuns').textContent = String(runs.length);
  $('sAct').textContent = String(act);
  $('sSig').textContent = String(state.data.findings.length);
  $('runList').innerHTML = runs.map(r => {
    const live = r.n - r.done;
    const cards = r.list.map(a =>
      '<div class="acard st-' + esc(a.status) + '"><span class="nm"><span class="dot ' + (a.status === 'running' ? 'run' : '') + '"></span>' + esc(a.name) + '</span>' +
      ' <span class="pill ' + (a.status === 'running' ? 'p-live' : 'p-done') + '">' + esc(a.status) + '</span>' +
      '<div class="last">' + esc(a.last || '…') + '</div>' +
      (expanded.has(r.id + ':' + a.base) ? '<div class="feed">' + a.events.slice(-10).reverse().map(e => '<div>' + esc(e.text) + '</div>').join('') + '</div>' : '') +
      '<div class="more" data-k="' + esc(r.id + ':' + a.base) + '">' + (expanded.has(r.id + ':' + a.base) ? '△ replier' : '▽ flux (' + a.total + ' ev)') + '</div></div>'
    ).join('');
    return '<div class="card glow"><div class="fh" style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">' +
      '<span class="pill p-prog">' + esc((r.program || '?').toUpperCase()) + '</span>' +
      '<b style="color:var(--cyan);letter-spacing:1px">' + esc(r.label) + '</b>' +
      '<span class="pill ' + (live > 0 ? 'p-live' : 'p-done') + '">' + (live > 0 ? live + ' EN COURSE' : 'TERMINE') + '</span>' +
      '<small style="color:var(--dim);margin-left:auto">' + esc(r.id) + '</small></div>' + cards + '</div>'.replace('{{CARDS}}', '');
  }).join('') || '<div class="card">aucun run detecte</div>';
  // wire expanders
  document.querySelectorAll('.more').forEach(m => m.addEventListener('click', () => {
    const k = m.dataset.k;
    if (expanded.has(k)) expanded.delete(k); else expanded.add(k);
    drawRuns(state.data.runs);
  }));
}

// ---------- findings ----------
const FND_STATUS = ['signal', 'analyse', 'soumis', 'dup', 'refuse', 'ferme'];
function drawFindings() {
  $('nFnd').textContent = String(state.data.findings.length);
  const progs = [...new Set(['etoro', 'blockchain', 'bullish', 'rapyd', 'nubank', 'wise', ...state.data.programs.map(p => p.id)])];
  if ($('nfProg').options.length !== progs.length) {
    $('nfProg').innerHTML = progs.map(p => '<option>' + p + '</option>').join('');
  }
  $('fndList').innerHTML = state.data.findings.slice(0, 120).map(f => {
    const sel = FND_STATUS.map(s => '<option' + (f.status === s ? ' selected' : '') + '>' + s + '</option>').join('');
    return '<div class="fnd S-' + esc(f.sev) + '"><div class="fh">' +
      '<span class="sev">' + esc(f.sev) + '</span>' +
      '<span class="pill p-prog">' + esc((f.program || '?').toUpperCase()) + '</span>' +
      '<small style="color:var(--dim)">' + esc(f.id) + ' · ' + esc(f.run) + ' · ' + esc(f.agent) + '</small>' +
      '<small style="color:var(--dim);margin-left:auto">' + new Date(f.t).toLocaleTimeString('fr-FR') + '</small>' +
      '<select data-k="' + esc(f.key) + '" class="fstat">' + sel + '</select></div>' +
      '<div class="txt">' + hl(f.text) + '</div></div>';
  }).join('') || '<div class="fnd">aucun signal encore</div>';
  document.querySelectorAll('.fnd select').forEach(s => s.addEventListener('change', () => {
    fetch('/api/findings', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ op: 'patch', key: s.dataset.k, status: s.value }) });
  }));
}

// ---------- moteur fleet ----------
function drawFleet() {
  const f = state.data.fleet || {};
  const st = $('fleetSt');
  st.textContent = f.enabled ? (f.paused ? 'FLEET : EN PAUSE' : 'FLEET : ACTIF (' + f.cycles + ' cycles)') : 'FLEET : ARRETE';
  st.className = 'pill ' + (!f.enabled ? 'p-done' : f.paused ? 'p-done' : 'p-live');
  $('fleetInfo').textContent = (f.lastCycle ? 'dernier cycle ' + new Date(f.lastCycle).toLocaleTimeString('fr-FR') + ' - ' : '') + (f.lastResult || 'aucun cycle encore') + ' - intervalle ' + f.intervalMin + ' min, budget ' + f.budget + ' req/cycle';
}
function fleetReq(body, txt) { drawFleetLater(body, txt); }
$('fleetStart').addEventListener('click', () => drawFleetLater({ enabled: true, paused: false }, 'FLEET-MODE ACTIF : cycles locaux toutes 30 min, 0 token.'));
$('fleetPause').addEventListener('click', () => drawFleetLater({ paused: true }, 'FLEET EN PAUSE - reprends quand tu veux.'));
$('fleetCycle').addEventListener('click', () => drawFleetLater({ op: 'test' }, 'Cycle immediat lance (budget 60 req).'));
function drawFleetLater(body, txt) { fetch('/api/fleet', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) }).then(() => setTimeout(refresh, 300)); if (txt) toast('FLEET', txt, 'HIT'); }

// ---------- programmes ----------
function drawPrograms() {
  $('nProg').textContent = String(state.data.programs.length);
  $('progList').innerHTML = state.data.programs.map(p =>
    '<div class="card"><h3>' + esc(p.name) + (p.veille ? ' <small style="color:var(--amber)">(veille)</small>' : '') + '</h3>' +
    '<div class="subtle" style="color:var(--dim);font-size:10.5px">' + esc(p.platform || '') + '</div>' +
    '<div class="scope">' + esc((p.scope || []).join(' · ')) + '</div>' +
    (p.header ? '<div class="hdr">⧉ ' + esc(p.header) + '</div>' : '') +
    (p.regle ? '<div class="hdr">⌦ regle : ' + esc(p.regle) + '</div>' : '') +
    '<div style="display:flex;gap:6px;margin-top:8px;flex-wrap:wrap;align-items:center">' +
    '<select class="pb" data-p="' + esc(p.id) + '">' + PLAYBOOKS.map(x => '<option value="' + x[0] + '">' + x[0] + '</option>').join('') + '</select>' +
    '<button class="go launch" data-p="' + esc(p.id) + '">GO ›</button>' +
    '<small style="color:var(--dim);flex:1;min-width:160px">Choisis un playbook puis GO</small></div>' +
    '<div class="subtle" style="color:var(--dim);font-size:10.5px" id="pbdesc-' + esc(p.id) + '"></div></div>'
  ).join('');
  document.querySelectorAll('.prog .pb').forEach(sel => {
    const upd = () => { const pb = PLAYBOOKS.find(x => x[0] === sel.value); const d = $('pbdesc-' + sel.dataset.p); if (d && pb) d.textContent = '▸ ' + pb[1]; };
    sel.addEventListener('change', upd); upd();
  });
  document.querySelectorAll('.launch').forEach(b => b.addEventListener('click', () => {
    const p = b.dataset.p;
    const sel = document.querySelector('.pb[data-p="' + p + '"]');
    const note = prompt('note d activation pour CLAUDE (cible, creds, contraintes) :', '');
    if (note === null) return;
    fetch('/api/queue', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ playbook: sel.value, program: p, note: note }) });
    toast('LANCHEMENT', '[GO] ' + sel.value + ' sur ' + p.toUpperCase() + ' - transmission a CLAUDE…', 'HIT');
  }));
}

// nouveau programme
$('progForm').addEventListener('submit', e => {
  e.preventDefault();
  const id = $('npId').value.trim().toLowerCase().replace(/[^a-z0-9_-]/g, '');
  const list = state.data.programs.slice();
  list.push({
    id, name: $('npName').value.trim(), platform: 'manuel', header: $('npHeader').value.trim(),
    scope: $('npScope').value.split(',').map(s => s.trim()).filter(Boolean),
    creds: '', runs: [],
  });
  fetch('/api/programs', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ programs: list }) }).then(refresh);
  $('progForm').reset();
});

// nouveau finding
$('newFinding').addEventListener('submit', e => {
  e.preventDefault();
  fetch('/api/findings', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ sev: $('nfSev').value, program: $('nfProg').value, text: $('nfText').value }) }).then(refresh);
  $('nfText').value = '';
});

// ---------- chat ----------
function drawChat() {
  const c = state.data.chat;
  $('nChat').textContent = String(c.length);
  const log = $('chatlog');
  log.innerHTML = c.map(m =>
    '<div class="msg ' + esc(m.from) + (m.kind === 'queue' ? ' queue' : '') + '"><div class="who">' +
    (m.kind === 'queue' ? '⚡ LANCEMENT ' : '') + esc(m.from === 'user' ? 'OPERATOR' : 'CLAUDE') + ' · ' + new Date(m.t).toLocaleTimeString('fr-FR') + '</div>' +
    esc(m.text || (m.playbook ? m.playbook + ' › ' + (m.program || '?') : '')) + '</div>'
  ).join('') || '<div class="msg claude">Le canal est ouvert. Tape ici, le monitor me revele a l instant.</div>';
  log.scrollTop = log.scrollHeight;
}
$('chatform').addEventListener('submit', e => {
  e.preventDefault();
  const t = $('chatinput').value.trim();
  if (!t) return;
  fetch('/api/chat', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ text: t }) });
  state.chatSeen++; // optimiste : on affiche au prochain refresh de toute facon
  $('chatinput').value = '';
  setTimeout(refresh, 250);
});

// ---------- nav / poll ----------
document.querySelectorAll('.navbtn').forEach(b => b.addEventListener('click', () => setTab(b.dataset.tab)));
document.addEventListener('keydown', e => {
  if (e.target.tagName === 'INPUT' || e.target.tagName === 'SELECT' || e.target.tagName === 'TEXTAREA') { if (e.key === 'Escape') e.target.blur(); return; }
  const m = { '1': 'live', '2': 'findings', '3': 'programs', '4': 'chat' }[e.key];
  if (m) setTab(m);
});
setInterval(() => { $('clock').textContent = new Date().toLocaleTimeString('fr-FR'); }, 1000);

let inflight = false;
async function refresh() {
  if (inflight) return; inflight = true;
  try {
    const d = await (await fetch('/api/state')).json();
    const prevChat = state.firstLoad ? null : state.data.chat.length;
    const prevFnd = state.data.findings.length;
    state.data = d;
    const topChat = d.chat[d.chat.length - 1];
    if (!state.firstLoad && d.chat.length > prevChat && topChat && topChat.kind === 'chat') {
      toast('COORDINATION', (topChat.from === 'claude' ? 'CLAUDE : ' : 'OPERATOR : ') + (topChat.text || ''), '');
    }
    if (!state.firstLoad) {
      d.findings.slice(0, Math.max(0, d.findings.length - prevFnd)).forEach(f => {
        if (['P1', 'P2', 'HIT'].includes(f.sev)) toast('[' + (f.program || '').toUpperCase() + '] ' + f.run + ' · ' + f.agent, f.text, f.sev === 'P1' ? 'P1' : f.sev);
      });
    }
    drawRuns(d.runs); drawFindings(); drawPrograms(); drawChat(); drawFleet();
    state.firstLoad = false;
  } catch (e) { /* serveur occupe */ }
  inflight = false;
}
setInterval(refresh, 1500);
refresh();