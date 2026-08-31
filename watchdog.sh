#!/bin/bash
# ── C2FF watchdog : le serveur NE MEURT JAMAIS ─────────────────────────
# Boucle de surveillance : si le port repond plus, relance le serveur.
# Tant que celui-ci tourne, C2FF tourne. Stop definitif = kill watchdog.
PORT="${1:-4181}"
DIR="$(cd "$(dirname "$0")" && pwd)"
while true; do
  if ! curl -sS -m 3 "http://localhost:${PORT}/" >/dev/null 2>&1; then
    # serveur absent -> relance
    cd "$DIR" || exit 1
    nohup node server.js "$PORT" >> /tmp/C2FF-server.log 2>&1 &
    sleep 4
  fi
  sleep 20
done