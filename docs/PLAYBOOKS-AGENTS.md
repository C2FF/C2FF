# Modes & integration IA optionnelle

Le moteur FLEET de C2FF couvre nativement les familles CWE testables par probes deterministes - **sans aucune IA, sans token, sans dependance**. L'IA est un booster optionnel, branchable dans l'onglet `IA` de l'UI.

## Modes locaux (lances depuis l'UI, 0 IA)

Onglet PROGRAMMES : choisis un mode, clique `GO ›`. Le moteur fleet enchaine les modules du mode immediatement, localement, avec le budget requests fixe. Chaque module passe par le header chercheur du programme s'il en declare un.

| Mode | CWE couverts | Ce que font les probes |
|---|---|---|
| FULL SWEEP | toutes | tous les modules - sweep complet de la surface |
| SEC-CFG | 693 / 614 / 942 | headers de protection, cookies sans Secure/HttpOnly, CORS reflechi, preflight |
| XSS | 79 | reflection user-input sans encodage sur les params |
| SQLI | 89 | erreurs SQL au quote simple sur les params |
| LFI | 22 / 98 | traversals via params + dotfiles exposes |
| SSRF | 918 | params qui traitent une url arbitraire |
| OPEN-REDIR | 601 | redirects ouverts sur les params de navigation |
| SSTI/RCE | 1336 / 78 | evaluation de template ({{7*7}}) puis commande |
| XXE | 611 | surfaces XML/SOAP a tester hors bande |
| AUTH/JWT | 287 / 347 | JWT rencontres (headers, cookies, bundles) + axes de lab |
| BOLA/IDOR | 639 | references d'objets exposees cote client |
| UPLOAD | 434 | surfaces d'upload a bypasser |
| SECRETS | 798 / 321 | cles AWS/Stripe/Google/GitHub, cles privees dans les JS |
| INFO-LEAK | 209/200/538/541/718 | stack traces, dotfiles, robots.txt, empreintes |
| EXPOSED | 284 | consoles et interfaces d'admin non protegees |

Familles non couvertes nativement (elles demandent creds ou interaction active : CSPT mass, CSRF sur action authentifiee, logic metier, race condition multi-requetes) : c'est la que l'IA optionnelle prend le relais.

## Brancher une IA (optionnel)

Onglet `IA` de l'UI :

1. `activee` + protocole : OpenAI-compatible / Ollama / Anthropic
2. base URL + model + cle API (vide si serveur local)
3. `Enregistrer` puis `Tester la connexion`

Une fois connectee : bouton `IA »` sur chaque finding de l'onglet FINDINGS - l'IA rend un verdict defendable, l'impact et la prochaine probe curl, publie dans COORDINATION. Config stockee dans `data/ai.json`.

## Piloter le moteur par fichier (pour scripts)

Le canal `data/chat.jsonl` reste lisible a chaud :

```json
{"t":1690000000,"from":"user","kind":"chat","text":"passe sur progammes/X, mode SQLI"}
```

```bash
echo '{"t":'"$(date +%s000)"',"from":"claude","kind":"chat","text":"verdict : ..."}' >> data/chat.jsonl
```

## Regles pour l'agent (a copier dans son prompt)

- lire `data/programs.json` pour scope exact et header requis du programme
- ne jamais toucher un domaine hors scope
- respecter le header chercheur (`X-Bug-Bounty`, ...) sur CHAQUE requete
- GET lecture-seule par defaut ; aucune ecriture sans GO explicite de l'operateur
- PoC = 3 etapes max reproductibles ; pas de mass scanning (1 hote par wildcard, budget fixe)