# TEST_LOG.md - modes avances (12) - lab local 2026-09-01

Environnement : cible de lab locale node http sur 127.0.0.1:8897
(/tmp/c2ff-lab/target.js, comportements calibres : echo desactive, corps
constants, endpoint /api/slow qui hang 30 s) + instance C2FF isolee sur
port 4196, 3 programmes lab (labsingle, labfull, labslow), config
budget 60, gap 200 ms, timeouts BLIND_SQL 15000 / DNS_OOB 8000.
Aucun vrai programme touche.

## Bugs trouves et corriges pendant les tests

1. `ctx.params is not iterable` - l'objet env du runner (attack.js
   advancedRun) ne passait pas params/endpoints a mkCtx. Corrige :
   env embarque params + endpoints.
2. Probes silencieuses (code 0) - les modes construisent des URLs
   relatives depuis ctx.endpoints, probe les envoyait telles quelles.
   Corrige dans mkCtx.probe : chemin relatif prefixes par la base du
   programme (contrat documente dans docs/core.md).
3. Cles de baseline incoherentes - la capture baseline strippait les
   query strings alors que DIFF_COMPARE/NO_SQLI cherchent la baseline
   sous l'endpoint exact (query incluse). Corrige : cle = endpoint
   exact tel que reference par les modes.

## Test 1 - NO_SQLI seul : 4 requetes, arret propre - PASS

POST /api/advanced {op:"run", name:"labsingle", modes:["NO_SQLI"]}
1 param × 2 endpoints × 2 payloads, aucune alerte (echo desactive,
corps constants).
Resultat : used 4, modes[0].reqs 4, alerts 0, remaining P1 26/30.
Arret propre : la boucle s'arrete apres le dernier payload, run rendu
en 1 s.

## Test 2 - BLIND_SQL sur cible lente : timeout 15 s sans bloquer - PASS

POST /api/advanced {op:"run", name:"labslow", modes:["BLIND_SQL"]}
Cible : /api/slow qui attend 30 s avant de repondre.
Resultat : areq coupe a 15 s (timeout du mode BLIND_SQL), alerte P1 :
"latence 15.7s sur ?delay : SQLi temporisee (MySQL)", ms 15749,
evidence "baseline 0ms -> 15749ms". Run total 16 s (pas 30 s+), la
reponse revient et le serveur reste reactif. Le scan nuclei auto a ete
declenche par l'alerte P1 et termine sous son cap de 120 s.

## Test 3 - Budget : 60 requetes exactes en P1+P2+P3 - PASS

POST /api/advanced {op:"run", name:"labfull", modes:[12 modes]}
priority_filter ["P1","P2","P3"], pools calcules par fleet.planBudget(60)
= {P1: 30, P2: 18, P3: 12} (50% / 30% / 20%).
Resultat : used 60 EXACT, remaining {P1:0, P2:0, P3:0}.
Repartition observee : NO_SQLI 8, JWT_ADV 0 (aucun JWT en baseline),
BLIND_SQL 22 (pool P1 epuise), HEADER_INJECT 6, ACTUATOR_ADV 4,
AWS_META 6, SESSION_FIX 1, OAUTH_MIS 1, DNS_OOB skip (P2 epuise),
GRAPHQL_INTRO 2, VERSION_CRAWL 5, DIFF_COMPARE 5 (pool P3 epuise).
Aucune requete au-dela du budget, aucun pool negatif.

## Test 4 - DIFF_COMPARE : cache baseline, aucune requete de reference - PASS

Baseline capturee au prealable (6 endpoints, cles avec query). Run
DIFF_COMPARE seul : used 6 = 3 endpoints × 2 valeurs (id=1, id=2), ni
plus ni moins - si une reference avait ete refetch, used aurait depasse 6.
Baseline intakte apres le run : timestamp t identique (1788296649239),
hash identique (be2be31e), len identique (101).
Alertes generees : "ecart 198% vs baseline sur /api/item?id=1 (id=2)"
(baseline 101 o -> 301 o) et "ecart 66% (id=1)" sur /api/item?id=2.
Un endpoint SANS baseline est note et saute (jamais fetch).

## Test 5 - Export data/advanced_report.json - PASS

Une entree par alerte avec mode, payload, status, evidence (+ sev, cwe,
ms, ref d'enrichissement arsenal pour les modes non P1) :
- labslow : BLIND_SQL / "delay=1'||PG_SLEEP(5)--" / status 0 (timeout) /
  evidence "baseline 0ms -> 15749ms"
- labfull : 2 × DIFF_COMPARE / status 200 / evidence ecart baseline
Les alertes P1/P2 sont aussi injectees dans findings.jsonl (run ADV)
et le rapport est relisible via GET /api/advanced.

## Verdict

5/5 PASS. Le cycle budget/gap/baseline tient sur les 12 modes ; le
delai adaptatif double bien le gap sur timeout (record(0, true) vu
pendant le test 2), et le run ne bloque jamais au-dela du timeout
declare.