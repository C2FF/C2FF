#!/usr/bin/env bash
# ── C2FF install.sh : verifie, prepare, demarre ─────────────────────────
set -u
DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR" || exit 1

echo "[*] C2FF - installation"

# 1) dependances
if ! command -v node >/dev/null 2>&1; then
  echo "[!] node manquant : installe Node >= 18 (https://nodejs.org) puis relance."; exit 1
fi
NODE_MAJOR="$(node -e 'console.log(process.versions.node.split(".")[0])')"
if [ "${NODE_MAJOR:-0}" -lt 18 ]; then
  echo "[!] node trop ancien ($(node -v)) : 18+ requis."; exit 1
fi
if ! command -v curl >/dev/null 2>&1; then
  echo "[!] curl manquant : reques pour le moteur et le watchdog."; exit 1
fi
echo "[+] node $(node -v) - curl OK"

# 2) espace de donnees
mkdir -p data
[ -f data/programs.json ]  || echo '[]' > data/programs.json
[ -f data/findings.jsonl ] || : > data/findings.jsonl
[ -f data/chat.jsonl ]     || echo '{"t":'$(date +%s000)',"from":"claude","kind":"chat","text":"C2FF en ligne. Moteur FLEET pret : PROGRAMMES -> DEMARRER."}' > data/chat.jsonl
[ -f data/fleet.json ]     || echo '{"enabled":false,"paused":false,"intervalMin":30,"budget":60}' > data/fleet.json
echo "[+] data/ pret"

# 3) test syntaxe puis lancement
if ! node --check server.js >/dev/null 2>&1; then echo "[!] server.js invalide."; exit 1; fi

PORT="${1:-4181}"

# si ce port sert deja une console, on n'installe pas un doublon dessus
if curl -sS -m 3 "http://localhost:${PORT}/api/state" >/dev/null 2>&1; then
  echo "[=] une console C2FF repond deja sur le port ${PORT}."
  echo "    si c'est pas celle voulue : ./install.sh <autre-port>"
  echo "    (cette installation n'a rien modifie)"
  exit 0
fi

nohup bash "$DIR/watchdog.sh" "$PORT" > /tmp/C2FF-watchdog.log 2>&1 &
sleep 3
if curl -sS -m 5 "http://localhost:${PORT}/api/state" >/dev/null 2>&1; then
  echo "[+] C2FF EN LIGNE : http://localhost:${PORT}  (dossier : $DIR)"
  echo "    arret de CETTE instance : pkill -f 'watchdog.sh ${PORT}' ; pkill -f 'server.js ${PORT}'"
else
  echo "[!] pas encore de reponse (le watchdog fait son travail dans ~20 s)."
  echo "    log : /tmp/C2FF-watchdog.log et /tmp/C2FF-server.log"
fi