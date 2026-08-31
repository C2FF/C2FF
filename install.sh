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

# si un watchdog tourne deja, on ne double pas
if pgrep -f "C2FF/watchdog.sh" >/dev/null 2>&1 || pgrep -f "watchdog.sh ${PORT:-4181}" >/dev/null 2>&1; then
  echo "[=] watchdog deja actif - rien a faire. UI : http://localhost:4181"
  exit 0
fi

PORT="${1:-4181}"
nohup bash "$DIR/watchdog.sh" "$PORT" > /tmp/C2FF-watchdog.log 2>&1 &
sleep 3
if curl -sS -m 5 "http://localhost:${PORT}/api/state" >/dev/null 2>&1; then
  echo "[+] C2FF EN LIGNE : http://localhost:${PORT}"
  echo "    arret propre : pkill -f watchdog.sh ; pkill -f C2FF/server.js"
else
  echo "[!] pas encore de reponse (le watchdog fait son travail dans ~20 s)."
  echo "    log : /tmp/C2FF-watchdog.log et /tmp/C2FF-server.log"
fi