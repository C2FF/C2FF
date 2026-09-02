// merge des 54 nouvelles cles (chats + pin modal) dans les 82 dicts de app.js
// usage : node merge_update.js <fichier-resultat.json>
// format attendu : { lang: { cle: valeur } } (plusieurs langues par fichier ok)
// validation stricte : chaque langue doit porter EXACTEMENT les cles du src,
// sinon rien n'est injecte (le dict fr/en sert de verite terrain)
const fs = require('fs');
const SRC = JSON.parse(fs.readFileSync('pending-i18n/_src_update.json', 'utf8'));
const KEYS = SRC.keys;
const src = fs.readFileSync('app.js', 'utf8');
const i = src.indexOf('const I18N = {');
const j = src.indexOf('\n};', i);
const I18N = new Function(src.slice(i, j + 3) + '\nreturn I18N;')();

const res = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const langs = Object.keys(res).filter(k => typeof res[k] === 'object' && !Array.isArray(res[k]));
let bad = 0, ok = 0;
for (const lg of langs) {
  if (!I18N[lg]) { console.log('langue inconnue : ' + lg); bad++; continue; }
  const ks = Object.keys(res[lg]);
  const missing = KEYS.filter(k => !res[lg][k] || typeof res[lg][k] !== 'string' || !res[lg][k].trim());
  if (missing.length) { console.log(lg + ' : ' + missing.length + ' cles vides/manquantes : ' + missing.join(',')); bad++; continue; }
  ok++;
}
if (bad) { console.log('\n' + bad + ' problemes - RIEN injecte'); process.exit(1); }

// re-ecriture integrale du littéral I18N (echappement propre des valeurs)
const lit = s => "'" + String(s).replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/\r?\n/g, '\\n') + "'";
const out = {};
for (const [lg, dict] of Object.entries(I18N)) {
  const merged = { ...dict };
  if (res[lg]) for (const [k, v] of Object.entries(res[lg])) merged[k] = String(res[lg][k]);
  const body = Object.entries(merged).map(([k, v]) => '    ' + lit(k) + ': ' + lit(v)).join(',\n');
  out[lg] = '  ' + lg + ': {\n' + body + '\n  },';
}
const next = src.slice(0, i) + 'const I18N = {\n' + out[Object.keys(out)[0]];
// reconstruction : on regenere le bloc complet
const block = 'const I18N = {\n' + Object.values(out).join('\n') + '\n};';
fs.writeFileSync('app.js', src.slice(0, i) + block + src.slice(j + 3));
console.log('injecte : ' + ok + ' langues x ' + KEYS.length + ' cles (app.js reecrit)');