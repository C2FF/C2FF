// check-i18n.js - audit complet i18n (dicts évalués par Node, pas de parse regex)
'use strict';
const fs = require('fs');
const src = fs.readFileSync(__dirname + '/app.js', 'utf8');
const html = fs.readFileSync(__dirname + '/index.html', 'utf8');

// extraire le littéral const I18N = { ... }; et l'évaluer (c'est un objet pur)
const START = src.indexOf('const I18N = {');
const END = src.indexOf('\n};', START);
if (START < 0 || END < 0) throw new Error('I18N non trouvé');
const I18N = new Function(src.slice(START, END + 2) + '\nreturn I18N;')();
const LANGS_RE = /const LANGS = \[([\s\S]*?)\];/.exec(src)[1];
const menuLangs = [...LANGS_RE.matchAll(/'([a-z]{2})'/g)].map(m => m[1]);
const langs = Object.keys(I18N);
const ref = I18N.fr;

console.log('=== 0. registre ===');
console.log('menu LANGS: ' + menuLangs.length + ' langues | dicts I18N: ' + langs.length + ' (' + langs.join(',') + ')');
console.log('langues du menu SANS dict: ' + menuLangs.filter(l => !(l in I18N)).join(','));
console.log('ref fr: ' + Object.keys(ref).length + ' clés');

console.log('\n=== 1. clés par langue vs fr ===');
for (const L of langs) {
  const miss = Object.keys(ref).filter(k => !(k in I18N[L]));
  const extra = Object.keys(I18N[L]).filter(k => !(k in ref));
  console.log(L.padEnd(3) + ': ' + Object.keys(I18N[L]).length + ' clés' +
    (miss.length ? '  MANQUANTES: ' + miss.join(', ') : '') +
    (extra.length ? '  EXTRA: ' + extra.join(', ') : '  OK'));
}

// clés appelées : T('k') / TF('k') + data-i / data-ip
const used = new Set();
let um;
for (const re of [/\bT\(['"]([^'"]+)['"]\)/g, /\bTF\(['"]([^'"]+)['"]/g]) {
  while ((um = re.exec(src))) used.add(um[1]);
}
for (const str of [src, html]) {
  const reA = /data-i[p]?="([^"]+)"/g;
  while ((um = reA.exec(str))) used.add(um[1]);
}

console.log('\n=== 2. vs code (clés appelées: ' + used.size + ') ===');
const absent = [...used].filter(k => !(k in ref));
const never = Object.keys(ref).filter(k => !used.has(k));
console.log('appelées mais absentes du dict fr: ' + (absent.length ? absent.join(', ') : 'aucune'));
console.log('déclarées jamais appelées: ' + (never.length ? never.join(', ') : 'aucune'));
for (const L of langs) {
  if (L === 'fr') continue;
  const miss = [...used].filter(k => !(k in I18N[L]));
  console.log(L + ': manquantes = ' + (miss.length ? miss.join(', ') : 'aucune'));
}

console.log('\n=== 3. valeurs vides / non traduites ===');
let n = 0;
for (const L of langs) {
  if (L === 'fr') continue;
  const empty = [], sameEn = [], sameFr = [];
  for (const k of Object.keys(ref)) {
    if (!(k in I18N[L])) continue;
    const v = I18N[L][k];
    if (!v || !String(v).trim()) empty.push(k);
    else if (v === I18N.en[k] && ref[k] !== I18N.en[k]) sameEn.push(k);
    else if (v === ref[k] && ref[k] !== I18N.en[k] && String(v).length > 5) sameFr.push(k);
  }
  const parts = [];
  if (empty.length) parts.push('VIDES: ' + empty.join(', '));
  if (sameEn.length) parts.push('= en (pas traduit): ' + sameEn.join(', '));
  if (sameFr.length) parts.push('= fr (pas traduit ?): ' + sameFr.join(', '));
  if (parts.length) { console.log(L + ': ' + parts.join(' | ')); n++; }
}
if (!n) console.log('aucune valeur vide ou copiée détectée');

const phRe = /\{[a-zA-Z0-9_]+\}/g;
console.log('\n=== 4. placeholders {var} divergents vs fr ===');
let p = 0;
for (const L of langs) {
  if (L === 'fr') continue;
  const bad = Object.keys(ref).filter(k => k in I18N[L] &&
    (String(ref[k]).match(phRe) || []).sort().join() !== (String(I18N[L][k]).match(phRe) || []).sort().join());
  if (bad.length) { console.log(L + ': ' + bad.join(', ')); p++; }
}
if (!p) console.log('placeholders cohérents partout');

console.log('\n=== 5. textes UI en dur dans index.html (hors dicts, suspect) ===');
const hard = (html.match(/>([A-ZÉÈ][a-zA-Zéèàêôûç'!? «»,;\/-]{5,60})</g) || []).filter(s =>
  !/<scri/.test(s));
if (hard.length) console.log([...new Set(hard)].map(s => s.replace(/^>|<$/g, '')).join(' | '));
else console.log('aucun');

console.log('\n=== 6. prod (C2FF_PROD_DIR) vs repo ===');
try {
  const ps = fs.readFileSync(process.env.C2FF_PROD_DIR + '/app.js', 'utf8');
  const ph = fs.readFileSync(process.env.C2FF_PROD_DIR + '/index.html', 'utf8');
  console.log('app.js    : ' + (ps === src ? 'identique' : '!! DIFFERENT'));
  console.log('index.html: ' + (ph === html ? 'identique' : '!! DIFFERENT'));
} catch (e) { console.log('prod: ' + e.message); }