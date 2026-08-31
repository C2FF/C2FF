# C2FF

> **Poste de chasse bug bounty autonome - 100% local, sans tokens.**
> Un seul process Node : flotte de surveillance, moteur de probes deterministe (cycles infinis), base de findings persistante, coordination temps reel avec un agent IA optionnel (Claude Code).

```
 ██████╗  ██╗  ██╗ ██╗  ██╗ ██████╗  ██████╗  ██████╗  ██╗
 ██╔══██╗ ██║  ██║ ██║  ██║ ██╔══██╗ ██╔══██╗ ██╔══██╗ ██║
 ██║  ██║ ███████║ ██║  ██║ ██████╔╝ ██████╦╝ ██║  ██║ ██║
 ██║  ██║ ██╔══██║ ╚██╗ ██╔╝ ██╔══██╗ ██╔══██╗ ██║  ██║ ██║
 ██████╔╝ ██║  ██║  ╚████╔╝  ██║  ██║ ██████╦╝ ██████╔╝ ██████╗
 ╚═════╝  ╚═╝  ╚═╝   ╚═══╝   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝  ╚═════╝
              POSTE DE CHASSE AUTONOME  ·  C2FF v1.0
```

## Ce que c'est

C2FF est un **poste de commandement local** pour chasse aux vulnerabilites Bugcrowd/HackerOne/privee :

- **FLOTTE (LIVE)** : suivi temps reel de tes agents/agregateurs (les runs Claude Code si presents, sinon les cycles locaux)
- **FINDINGS** : base persistante de signaux, triage `signal -> analyse -> soumis -> dup/refuse`, ajout manuel
- **PROGRAMMES** : declares une fois (scope + header requis type `X-Bug-Bounty`), puis jouables
- **MOTEUR FLEET** : le coeur autonome - cycles de probes **deterministes, sans token, sans LLM**, aussi longtemps que tu ne pauses pas
- **COORDINATION** : canal prive direct avec un agent IA branché (optionnel - tout marche sans)

## Le moteur FLEET (le point cle)

Tout est **dans ton PC** : le moteur est du Node pur qui envoie quelques requetes curl calculees par cycle, deduplique ses resultats et ecrit tes findings sur disque. Aucune API payante, aucun quota de tokens.

9 modules de probes, tous en lecture seule :

| Module | Cible | CWE |
|---|---|---|
| `SECHEADERS` | headers de protection absents, stack visible | 693, 200 |
| `COOKFLAGS` | cookies sans Secure/HttpOnly | 614, 1004 |
| `CORS` | ACAO reflechit un Origin arbitraire | 942 |
| `OPTIONS` | preflight CORS permissif (DELETE/PUT) | 942 |
| `ERRLEAK` | stack traces dans les 500 | 209 |
| `DOTFILES` | .git/config, .env, server-status exposes | 541, 538 |
| `TECHSIG` | WordPress REST ouvert, empreintes serveur | 718 |
| `ROBOTS` | chemins sensibles dans robots.txt | 538 |
| `JSSECRETS` | cles AWS/Stripe/Google/GitHub/privees dans les bundles | 798, 321 |

Garde-fous integres :
- **1 hote representatif par wildcard** du scope - jamais de mass scanning
- **budget strict 60 requetes/cycle** (configurable), gap de 500 ms entre requetes
- **deduplication** : un signal identique n'est stocke qu'une fois
- respect du **header anti-403 de ton programme** (declares dans PROGRAMMES)

## Installation

```bash
git clone https://github.com/C2FF/C2FF.git
cd C2FF
./install.sh          # verifie node + curl, cree data/, lance le serveur + watchdog
```

Ou a la main :

```bash
node server.js 4181   # http://localhost:4181
```

Requis : Node >= 18, curl. C'est tout.

## Utilisation

```text
1. ouvre http://localhost:4181
2. onglet PROGRAMMES   -> + NOUVEAU PROGRAMME (id, nom, header requis, scope)
3. panneau MOTEUR      -> ▶ DEMARRER   (les cycles tournent seuls, 0 token)
4. ⚡ CYCLE MAINTENANT  -> un cycle instantane si tu ne veux pas attendre
5. onglet FINDINGS     -> les signaux arrivent, tu tries (signal/analyse/soumis…)
6. ⏸ PAUSE / reprise quand tu veux. Le watchdog relance le serveur si jamais il meurt.
```

### Le watchdog

`watchdog.sh` surveille le port toutes les 20 s et relance le serveur si besoin. Resultat : **C2FF tourne de facon illimitee** tant que tu ne kill pas le watchdog. Pour tout arreter proprement :

```bash
pkill -f 'C2FF/watchdog.sh' ; pkill -f 'C2FF/server.js'
```

### Integration IA (optionnel)

Sans agent IA : tout, du moteur FLEET au triage, fonctionne deja (c'est la vocation du projet).

Si tu veux en plus des **vagues agentiques profondeur** (duos pipeline recon->offensive, judge multi-hypotheses) branche ton agent Claude Code : passe les messages du canal COORDINATION a ton agent, il ecrit ses reponses dans `data/chat.jsonl` :

```json
{"t":1690000000,"from":"claude","kind":"chat","text":"verdict : ..."}
{"t":1690000000,"from":"user","kind":"queue","playbook":"SQLI-DUO","program":"cible","note":"..."}
```

Templates de playbooks agents : voir [docs/PLAYBOOKS-AGENTS.md](docs/PLAYBOOKS-AGENTS.md).

## Structure

```
C2FF/
├── server.js          # coeur : API, flotte, findings, chat, endpoints
├── fleet.js           # moteur autonome : 9 modules de probes, cycles, budget
├── app.js             # client : 4 onglets, toasts, triage
├── index.html         # interface
├── watchdog.sh        # garde-vie : relance automatic du serveur
├── install.sh         # installation + demarrage
└── data/              # programmes.json, findings.jsonl, chat.jsonl, fleet.json (crees a l'usage)
```

## L'ethique (non negociable)

C2FF est fait pour des programmes de **bug bounty autorises** (Bugcrowd, HackerOne, YesWeHack, programmes prives).

- Ne lances des cycles que sur des domaines **dans le scope officiel** de ton programme
- Respecte le **header/token d'authentification chercheur** quand le programme en exige un
- Les modules sont tous des GET lecture-seule a cadence lente, sous les seuils anti-flood
- Toute ecriture / interaction de session / requete mass-scanner **n'est pas implementee, volontairement**

Tu es responsable du respect des regles de chaque programme. Teste uniquement ce que tu es autorise a tester.

## License

MIT - cf. [LICENSE](LICENSE)