#!/usr/bin/env bash
# Envoie de faux événements syslog au SOC pour tester détection et alertes.
# Usage : ./scripts/simulate-attack.sh [ip_attaquant] [nb_tentatives]
set -euo pipefail

HOST="${SYSLOG_HOST:-localhost}"
PORT="${SYSLOG_PORT:-9000}"
ATTACKER="${1:-203.0.113.66}"
COUNT="${2:-8}"

send() {
  # Format RFC 3164 : <PRI>Mmm dd hh:mm:ss hostname app[pid]: message
  printf '<%s>%s srv-web-01 %s: %s\n' "$1" "$(LC_ALL=C date '+%b %e %H:%M:%S')" "$2" "$3"
}

{
  for i in $(seq 1 "$COUNT"); do
    send 38 "sshd[$((4000 + i))]" "Failed password for invalid user admin$i from $ATTACKER port $((50000 + i)) ssh2"
  done
  send 38 "sshd[4100]" "Invalid user oracle from $ATTACKER port 50999"
  send 38 "sshd[4101]" "Accepted publickey for euloge from 192.168.1.20 port 50022 ssh2"
  send 85 "sudo"       "euloge : TTY=pts/0 ; PWD=/home/euloge ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow"
} | nc -w 2 "$HOST" "$PORT"

echo "Événements envoyés à $HOST:$PORT ($COUNT échecs SSH depuis $ATTACKER)."
