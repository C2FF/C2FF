# docs/core.md - contrat des wrappers HTTP (C2FF)

A LIRE AVANT DE MODIFIER LES WRAPPERS HTTP. Tout module qui envoie une
requete reseau passe par l'un de ces chemins, jamais par un require direct
de http/https dans le module.

## 1. areq(url, opts) - attack.js

Wrapper HTTP bas niveau (http + https, TLS non verifie, corps cappe 1 Mo).

```js
const ATTACK = require('./attack.js');
const r = await ATTACK.areq(url, { hdrs, timeout, method, body });
// r = { code, headers, body, ms, timedOut }
//   code     : statusCode HTTP, 0 si echec reseau
//   headers  : objet (set-cookie = tableau)
//   body     : string tronquee
//   ms       : latence reelle
//   timedOut : true si le timeout a coupe la reponse
```

- `timeout` en ms (default 10000). Utiliser config.advanced_hacks.timeouts.
- areq ne boucle PAS, ne reessaie PAS : la repetition est le job du
  rateLimiter (voir 3).

## 2. ctx.probe(url, opts) - SEUL chemin reseau d'un mode avance

Un mode avance (modules.js ADV_MODES, execute dans attack.js EXEC) ne
doit JAMAIS appeler areq directement. Il recoit un ctx (mkCtx) :

```js
const r = await ctx.probe(url, { hdrs, method, body });
// url absolue ("https://host/x") OU chemin relatif ("/api/item?id=1",
// prefixes automatiquement par la base du programme)
```

probe fait exactement 3 choses, dans cet ordre :
1. decremente le budget de priorite du mode (env.remaining[P1|P2|P3])
2. passe par env.rl.request() (delai adaptatif, voir 3)
3. appelle areq avec les headers du programme (env.hh) fusionnes
   + timeout du mode (config.advanced_hacks.timeouts)

Un probe dont le pool de priorite est epuise n'est pas envoye :
advancedRun skippe le mode avec une note.

## 3. rateLimiter - core/rateLimiter.js

```js
const RL = require('./core/rateLimiter.js');
const rl = RL.create({ baseGapMs: 1000 });
const r = await rl.request(() => areq(url, opts));
rl.record(r.code, r.timedOut);   // deja fait par request()
```

- `record(429, false)` ou `record(code, true)` : gapMs x2 (max 30 s)
- 8 reponses propres de suite : gapMs x0.75 (min = base)
- UN SEUL rl par run (cree dans advancedRun) : le recreeer par requete
  casse le delai adaptatif.
- MIN_GAP 250 ms, MAX_GAP 30000 ms.

## 4. baseline - baseline.js

Cache data/baseline.json : reponses PROPRES par endpoint, par programme.

```js
BASELINE.setBaseline(progId, endpoint, r);          // r = reponse areq
BASELINE.getBaseline(progId, endpoint);             // { code, len, ms, ct, ck, hash, body, t } | null
BASELINE.lenDelta(len, base);                       | ecart relatif de taille
BASELINE.stats(progId);                             // { n, endpoints }
```

Regles :
- la capture est une operation explicite (POST /api/advanced op
  'baseline', max 8 endpoints) - jamais un effet de bord d'un mode.
- DIFF_COMPARE lit le cache et ne refait JAMAIS une requete de
  reference : endpoint sans baseline = note + skip.
- `ck` = nombre de Set-Cookie de la reponse propre : c'est ce qui
  permet a HEADER_INJECT de detecter un cookie injecte (base 0 -> N).

## 5. timeouts par mode - config.json

```json
"advanced_hacks": { "timeouts": { "BLIND_SQL": 15000, "DNS_OOB": 8000, "default": 10000 } }
```

BLIND_SQL doit rester > duree du SLEEP teste (5 s -> 15 s) : un timeout
plus court transforme une vraie injection en faux negatif. DNS_OOB est
court parce que le serveur externe repond ou pas. Ajouter un mode =
ajouter sa cle timeout (ou heriter default).

## 6. budget - fleet.js

```js
FLEET.planBudget(60);   // { P1: 30, P2: 18, P3: 12 }  (50% / 30% / 20%)
FLEET.planOrder(keys, MODULES.ADV_MODES);  // tri stable P1 > P2 > P3
```

Le budget est global au run, reparti par priorite. ctx.probe est le seul
endroit ou il se depense. Le total envoye ne depasse jamais le budget :
les modes demandent plus que les pools, l'ordre P1>P2>P3 arbitre.

## 7. arsenal - post-alerte

- P1 (NO_SQLI, JWT_ADV, BLIND_SQL) : ARSENAL.nucleiForAlert(host, mode,
  hdrs) scanne automatiquement (tags ADV_TAGS), sortie appendue au
  rapport comme entree `mode:nuclei` (sev SIG).
- autres modes : ARSENAL.enrichAlert(alert) ajoute `ref` (doc de
  verification manuelle).