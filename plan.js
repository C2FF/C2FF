// ============================================================
// C2FF - plan.js : le plan de travail de la chasse
// Transforme la surface du RECON en hypotheses concretes, chacune avec :
//  - why   : une ligne qui dit pourquoi on la teste
//  - curl  : la commande prete a coller dans le terminal (header du programme inclus)
//  - run   : true si le framework peut l executer lui-meme (GET only) et capturer la preuve
// Le plan persiste : chaque hypothesis a un statut, la chasse s accumule sur la duree.
// ============================================================

const CANARY = 'c2ff9q81Z';

// hypotheses executables par le framework (GET only, sans auth)
function plan(surf, prog) {
  const host = surf.host || '';
  const H = prog.header || '';
  const curl = (u, extra) => {
    let c = "curl -si 'https://" + host + u + "'";
    if (H) c = "curl -si -H '" + H + "' 'https://" + host + u + "'";
    for (const e of extra || []) c += " -H '" + e + "'";
    return c;
  };
  const out = [];
  let n = 0;
  const push = (cat, why, u, hdrs) => {
    n++;
    out.push({ k: String(n), cat, why, curl: curl(u, hdrs), run: true, u, hdrs: hdrs || [] });
  };
  const pushManual = (cat, why, cu) => { n++; out.push({ k: String(n), cat, why, curl: cu, run: false }); };

  // ---- 1. API : CORS reflechi (executable) ----
  for (const ep of [...new Set(surf.apis || [])].slice(0, 12)) {
    const e = String(ep).split('?')[0];
    if (!e.startsWith('/')) continue;
    push('cors', 'endpoint API : un CORS reflechi avec credentials donne du poids a un rapport ORB', e, ['Origin: https://evil.example']);
  }

  // ---- 2. IDOR : ids sequentiels dans les endpoints (comparaison sans auth) ----
  for (const ep of [...new Set(surf.apis || [])].slice(0, 12)) {
    const e = String(ep).split('?')[0];
    const m = /(\d{3,})/.exec(e);
    if (!m || e.length > 80) continue;
    const idN = m[1];
    const e2 = e.replace(idN, String(parseInt(idN, 10) + 1));
    out.push({ k: String(++n), cat: 'idor',
      why: 'id ' + idN + ' dans ' + e + ' : compare la reponse de ' + idN + ' et ' + (parseInt(idN, 10) + 1) + ' avec TON token - un 200 sur le voisin = acces non autorise a tester',
      curl: 'curl -si -H \'' + (H || 'Authorization: <ton-token>') + '\' \'https://' + host + e + '\' ; curl -si -H \'' + (H || 'Authorization: <ton-token>') + '\' \'https://' + host + e2 + '\'',
      run: false });
    break;
  }

  // ---- 3. params : reflection (executable) ----
  for (const prm of (surf.params || []).slice(0, 8)) {
    if (/^__cf|csrf/.test(prm)) continue;
    push('reflect', 'param ' + prm + ' : sa reflexion dans la reponse ouvre la porte XSS/SQLi a confirmer a la main', '/?' + prm + '=' + CANARY, []);
  }

  // ---- 4. graphql : introspection (manuel, POST) ----
  if ((surf.apis || []).some(a => String(a).includes('graphql')) || (surf.pages || []).some(p => String(p).includes('graphql'))) {
    pushManual('gql', 'graphql detecte : l introspection liste tout le schema - si elle passe c est une fuite documentee',
      "curl -s -X POST '" + host.replace(/^w{2}\./, '') + "' -H 'content-type: application/json' -d '{\"query\":\"{ __schema { types { name } } }\"}'");
  }

  // ---- 5. headers de securite de la racine (executable) ----
  push('cfg', 'racine : absence de CSP/HSTS et cookies sans flags - signaux a empiler, jamais un rapport seul', '/', []);
  return out.slice(0, 40);
}

module.exports = { plan, CANARY };