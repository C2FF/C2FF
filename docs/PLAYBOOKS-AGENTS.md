# Playbooks agents (integration IA optionnelle)

Le moteur FLEET de C2FF tourne **sans aucun LLM**. Cette page decrit comment brancher en plus un agent IA (Claude Code ou autre) pour des vagues profondes, via le canal `COORDINATION`.

## Principe

1. Depuis l'UI, onglet PROGRAMMES : choisis un playbook, clique `GO ›`, ecris ta note d'activation.
2. Le lancement est appendu dans `data/chat.jsonl` :
   ```json
   {"t":1690000000,"from":"user","kind":"queue","playbook":"SQLI-DUO","program":"etoro","note":"..."}
   ```
3. Ton agent lit ce fichier (ex : `tail -F data/chat.jsonl`) et execute le playbook.
4. L'agent publie ses verdicts en ecrivant dans le meme fichier :
   ```bash
   echo '{"t":'"$(date +%s000)"',"from":"claude","kind":"chat","text":"verdict : ..."}' >> data/chat.jsonl
   ```
   Ils apparaissent instantanement dans l'UI.

## Playbooks disponibles dans l'UI

| Playbook | Shape d'agent |
|---|---|
| RECON-HORIZON | 7 agents axes (BIZLOGIC, AUTH-JWT, JS, N-DAY, SUBS, API, MOBILE) + 1 juge |
| SQLI-DUO | recon params injectables -> duoffensif boolean/time/error |
| SSRF-DUO | cartographie surfaces fetch -> offensive metadata/redirects |
| LFI-WAVE | vague parallèle traversals/include/file-read |
| JACKPOT-SITE | 1 agent effort max sur un hote, carte exhaustive + chaines |
| RCE-SSTI-DUO | detection moteur templates -> probes {{7*7}} / php-format |
| BOLA-IDOR-SWEEP | balayage identifiants numeriques/UUID croises (auth requis) |
| JWT-JWE-LAB | lab tokens JWE/JWT, claims, audience cross-service |
| N-DAY-DORK | CVE du stack detecte + dorks Google/GitHub |
| JUDGE-TOP6 | tri des hypotheses de flotte, TOP actions par severite |

## Regles pour l'agent (a copier dans son prompt)

- lire `data/programs.json` pour scope exact et header requis du programme
- ne jamais toucher un domaine hors scope
- respecter le header chercheur (`X-Bug-Bounty`, ...) sur CHAQUE requete
- GET lecture-seule par defaut ; aucune ecriture sans GO explicite de l'operateur
- PoC = 3 etapes max reproductibles ; pas de mass scanning (1 hote par wildcard, budget fixe)
- publier chaque signal dans `data/chat.jsonl` avec sev defendable, ou dans l'UI via `POST /api/findings`

## Exemple de boucle agent

```bash
tail -F data/chat.jsonl | grep --line-buffered '"kind":"queue"' | while read -r L; do
  # extraire playbook/program/note, lancer l'agent correspondant...
  echo "queue recue : $L"
done
```