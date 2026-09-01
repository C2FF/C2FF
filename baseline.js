// ============================================================
// C2FF - baseline.js : cache de baseline par endpoint
// Stocke les reponses PROPRES (sans payload) dans data/baseline.json :
//   { "<programme>": { "<endpoint>": { code, len, ms, ct, hash, t } } }
// Regles :
//  - DIFF_COMPARE lit le cache et ne refait JAMAIS une requete de
//    reference : un endpoint sans baseline est ignore (note).
//  - la capture d'une baseline est une operation explicite (op
//    'baseline' depuis l'UI, ou capture automatique avant les modes
//    differentiels) - jamais un effet de bord d'un module d'attaque.
// Zero dependance. Contrat HTTP des wrappers : docs/core.md.
// ============================================================
'use strict';
const fs = require('fs');
const path = require('path');

const FILE = path.join(__dirname, 'data', 'baseline.json');
const MAX_ENTRIES = 400;      // par programme : suffisant, le fichier reste lisible
const MAX_BODY = 4096;        // corps propre garde tronque (comparaison de contenu)

let cache = null;

function load() {
  if (cache) return cache;
  try { cache = JSON.parse(fs.readFileSync(FILE, 'utf8')); } catch (e) { cache = {}; }
  return cache;
}

function save() {
  try { fs.writeFileSync(FILE, JSON.stringify(cache, null, 1)); } catch (e) {}
}

// lit une entree : getBaseline(progId, endpoint) -> {code,len,ms,ct,hash,body} | null
function getBaseline(progId, endpoint) {
  const c = load();
  return (c[progId] && c[progId][endpoint]) || null;
}

// ecrit / rafraichit une entree a partir d'une reponse {code, body, ms, headers}
function setBaseline(progId, endpoint, resp) {
  const c = load();
  if (!c[progId]) c[progId] = {};
  const body = String(resp.body || '').slice(0, MAX_BODY);
  c[progId][endpoint] = {
    code: resp.code || 0,
    len: String(resp.body || '').length,
    ms: resp.ms || 0,
    ct: (resp.headers && resp.headers['content-type'] || '').split(';')[0],
    ck: ((resp.headers && resp.headers['set-cookie']) || []).length,   // cookies de la reponse propre
    hash: simpleHash(body),
    body,
    t: Date.now(),
  };
  // eviction : les plus vieux d'abord si le programme explose
  const keys = Object.keys(c[progId]);
  if (keys.length > MAX_ENTRIES) {
    keys.sort((a, b) => (c[progId][a].t || 0) - (c[progId][b].t || 0));
    for (const k of keys.slice(0, keys.length - MAX_ENTRIES)) delete c[progId][k];
  }
  save();
  return c[progId][endpoint];
}

// capture une baseline propre (GET sans payload) via le wrapper passe.
// wrapper(url) -> Promise { code, body, headers, ms } (contrat docs/core.md)
async function capture(progId, url, endpoint, wrapper) {
  const r = await wrapper(url);
  const entry = setBaseline(progId, endpoint, r);
  return entry;
}

function simpleHash(s) {
  let h = 5381;
  for (let i = 0; i < s.length; i++) h = ((h << 5) + h + s.charCodeAt(i)) >>> 0;
  return h.toString(16);
}

// ecart de longueur relatif entre une reponse et la baseline (>0 = plus grand)
function lenDelta(len, baseline) {
  if (!baseline || !baseline.len) return null;
  return Math.abs(len - baseline.len) / baseline.len;
}

// stat resumé pour l'UI : { prog, n } et liste des endpoints
function stats(progId) {
  const c = load();
  const p = c[progId] || {};
  return { n: Object.keys(p).length, endpoints: Object.keys(p).slice(0, 50) };
}

function clear(progId) {
  const c = load();
  if (progId) delete c[progId]; else cache = {};
  save();
}

module.exports = { load, getBaseline, setBaseline, capture, lenDelta, stats, clear, simpleHash };