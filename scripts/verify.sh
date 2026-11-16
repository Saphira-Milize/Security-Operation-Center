#!/usr/bin/env bash
# Vérification automatique du SOC, en cinq étapes :
#   1. fichiers de configuration (sans rien démarrer)
#   2. sécurité (secrets, privilèges des comptes, exposition réseau)
#   3. santé des services
#   4. provisionnement (index, rétention, alertes, tableau de bord)
#   5. bout en bout : attaques simulées → détection → alerte
#
#   ./scripts/verify.sh            toutes les étapes (pile démarrée)
#   ./scripts/verify.sh --static   étape 1 seulement (utilisable en CI)
#
# Code de retour : 0 si tout passe, 1 sinon.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
MODE="${1:-all}"

if [[ -f "$ROOT/.env" ]]; then
  set -a; source "$ROOT/.env"; set +a
fi

OS_URL="${OS_URL:-https://localhost:9200}"
OSD_URL="${OSD_URL:-http://localhost:5601}"
VECTOR_API_URL="${VECTOR_API_URL:-http://localhost:8686}"
ADMIN="admin:${OPENSEARCH_INITIAL_ADMIN_PASSWORD:-}"

if [[ -t 1 ]]; then G=$'\033[32m'; R=$'\033[31m'; B=$'\033[1;34m'; N=$'\033[0m'; else G=""; R=""; B=""; N=""; fi
PASSED=0; FAILED=0
stage() { printf '\n%s== %s ==%s\n' "$B" "$1" "$N"; }
pass()  { printf '  %s✔%s %s\n' "$G" "$N" "$1"; PASSED=$((PASSED + 1)); }
fail()  { printf '  %s✘%s %s\n' "$R" "$N" "$1"; [[ -n "${2:-}" ]] && printf '      %s\n' "$2"; FAILED=$((FAILED + 1)); }
# check <libellé> <commande…> : réussit si la commande réussit
check() { local label=$1; shift; if "$@" >/dev/null 2>&1; then pass "$label"; else fail "$label"; fi; }
# expect <libellé> <attendu> <obtenu>
expect() { if [[ "$2" == "$3" ]]; then pass "$1"; else fail "$1" "attendu : $2 — obtenu : $3"; fi; }

os()  { curl -sk -m 20 -u "$ADMIN" "$@"; }
osd() { curl -s -m 20 -u "$ADMIN" -H 'osd-xsrf: true' -H 'securitytenant: global' "$@"; }
code() { curl -sk -m 20 -o /dev/null -w '%{http_code}' "$@"; }
# jget <expression Python sur d> : lit du JSON sur l'entrée standard
jget() { python3 -c "import json,sys
try:
    d=json.load(sys.stdin); print($1)
except Exception:
    print('')"; }
# count <requête Lucene> : nombre de documents soc-* correspondants
count() { os -G "$OS_URL/soc-*/_count" --data-urlencode "q=$1" | jget 'd.get("count", 0)'; }

summary() {
  printf '\n%s== Bilan ==%s\n  réussis : %d    échoués : %d\n' "$B" "$N" "$PASSED" "$FAILED"
  if [[ $FAILED -eq 0 ]]; then printf '\n%s✔ Toutes les vérifications passent.%s\n' "$G" "$N"; exit 0; fi
  printf '\n%s✘ %d vérification(s) en échec.%s\n' "$R" "$FAILED" "$N"; exit 1
}

# =============================================================================
stage "1. Configuration"
# En CI il n'y a pas de .env : des valeurs factices suffisent à valider la syntaxe
if [[ -z "${OPENSEARCH_INITIAL_ADMIN_PASSWORD:-}" ]]; then
  export OPENSEARCH_INITIAL_ADMIN_PASSWORD=x VECTOR_PASSWORD=x ANALYST_PASSWORD=x
fi
check "docker-compose.yaml valide" docker compose config -q
for script in scripts/*.sh; do
  check "syntaxe shell : $(basename "$script")" bash -n "$script"
done
for file in OpenSearch/*.json OpenSearch/monitors/*.json; do
  check "JSON valide : ${file#OpenSearch/}" python3 -m json.tool "$file"
done
check "tableau de bord : Dashboards/soc.ndjson valide" python3 -c '
import json, sys
objs = [json.loads(l) for l in open("Dashboards/soc.ndjson")]
ids = {(o["type"], o["id"]) for o in objs}
missing = [r for o in objs for r in o["references"] if (r["type"], r["id"]) not in ids]
sys.exit(1 if missing or not objs else 0)'
check "pot de miel : honeypot.py compile" python3 -c 'import ast,sys; ast.parse(open("Honeypot/honeypot.py").read())'
if out=$(./scripts/test-vector.sh 2>&1); then
  pass "pipeline Vector valide, $(grep -c '\.\.\. passed' <<<"$out") tests unitaires réussis"
else
  fail "pipeline Vector" "$(grep -E 'failed|error' <<<"$out" | head -3)"
fi

[[ "$MODE" == "--static" ]] && summary

# =============================================================================
stage "2. Sécurité"
if [[ -f .env ]]; then
  check ".env exclu de git" git check-ignore -q .env
  expect ".env lisible par son seul propriétaire" "-rw-------" "$(ls -l .env | cut -c1-10)"
else
  fail ".env absent" "cp .env.example .env, puis renseignez les mots de passe"
fi
strong() { [[ ${#1} -ge 8 && "$1" =~ [A-Z] && "$1" =~ [a-z] && "$1" =~ [0-9] && "$1" =~ [^a-zA-Z0-9] ]]; }
for var in OPENSEARCH_INITIAL_ADMIN_PASSWORD VECTOR_PASSWORD ANALYST_PASSWORD; do
  check "$var robuste (8+ caractères, majuscule, minuscule, chiffre, spécial)" strong "${!var:-}"
done
expect "socket Docker monté en lecture seule dans Vector" "ro" \
  "$(docker inspect vector --format '{{range .Mounts}}{{if eq .Destination "/var/run/docker.sock"}}{{.Mode}}{{end}}{{end}}' 2>/dev/null)"
expect "Vector ne détient pas le mot de passe admin" "0" \
  "$(docker inspect vector --format '{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null | grep -c '^OPENSEARCH_INITIAL_ADMIN_PASSWORD=')"
V="vector:${VECTOR_PASSWORD:-}"; A="analyste:${ANALYST_PASSWORD:-}"
expect "compte vector : authentification" "200" "$(code -u "$V" "$OS_URL/_cluster/health")"
expect "compte vector : suppression d'index refusée" "403" "$(code -u "$V" -X DELETE "$OS_URL/soc-verification-interdite")"
expect "compte vector : accès à la configuration de sécurité refusé" "403" "$(code -u "$V" "$OS_URL/_plugins/_security/api/internalusers")"
expect "compte analyste : lecture des événements" "200" "$(code -u "$A" "$OS_URL/soc-*/_search?size=0")"
expect "compte analyste : écriture refusée" "403" \
  "$(code -u "$A" -H 'Content-Type: application/json' -X POST "$OS_URL/soc-verification-interdite/_doc" -d '{}')"
expect "compte analyste : tableau de bord visible" "200" \
  "$(code -u "$A" -H 'securitytenant: global' "$OSD_URL/api/saved_objects/dashboard/soc-overview")"
expect "compte analyste : modification du tableau de bord refusée" "403" \
  "$(code -u "$A" -H 'securitytenant: global' -H 'osd-xsrf: true' -H 'Content-Type: application/json' \
       -X PUT "$OSD_URL/api/saved_objects/dashboard/soc-overview" -d '{"attributes":{"description":"x"}}')"
for svc in opensearch-node1:9200 opensearch-dashboards:5601 vector:8686; do
  expect "port ${svc#*:} (${svc%:*}) accessible depuis cette machine uniquement" "127.0.0.1" \
    "$(docker port "${svc%:*}" "${svc#*:}" 2>/dev/null | cut -d: -f1 | sort -u | tr '\n' ' ' | sed 's/ $//')"
done
expect "pot de miel : système de fichiers en lecture seule" "true" "$(docker inspect honeypot --format '{{.HostConfig.ReadonlyRootfs}}' 2>/dev/null)"
expect "pot de miel : isolé du réseau d'OpenSearch" "0" \
  "$(docker inspect honeypot --format '{{range $k, $v := .NetworkSettings.Networks}}{{println $k}}{{end}}' 2>/dev/null | grep -c opensearch-net)"

# =============================================================================
stage "3. Santé des services"
for c in opensearch-node1 opensearch-node2 opensearch-dashboards vector; do
  expect "$c en bonne santé" "running healthy" \
    "$(docker inspect "$c" --format '{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{else}}sans-healthcheck{{end}}' 2>/dev/null)"
done
expect "honeypot démarré" "running" "$(docker inspect honeypot --format '{{.State.Status}}' 2>/dev/null)"
for c in soc-setup soc-setup-dashboards; do
  expect "$c terminé sans erreur" "exited 0" "$(docker inspect "$c" --format '{{.State.Status}} {{.State.ExitCode}}' 2>/dev/null)"
done
health=$(os "$OS_URL/_cluster/health")
status=$(jget 'd["status"]' <<<"$health")
if [[ "$status" == "green" || "$status" == "yellow" ]]; then pass "cluster OpenSearch : $status"; else fail "cluster OpenSearch" "état : ${status:-injoignable}"; fi
expect "cluster à 2 nœuds" "2" "$(jget 'd["number_of_nodes"]' <<<"$health")"
expect "OpenSearch Dashboards répond" "200" "$(code -u "$ADMIN" "$OSD_URL/api/status")"
check "API Vector : ok" bash -c "curl -s -m 5 '$VECTOR_API_URL/health' | grep -q '\"ok\":true'"

# =============================================================================
stage "4. Provisionnement"
check "modèle d'index soc" bash -c "curl -sk -u '$ADMIN' '$OS_URL/_index_template/soc' | grep -q '\"soc-\\*\"'"
expect "politique de rétention soc-retention" "200" "$(code -u "$ADMIN" "$OS_URL/_plugins/_ism/policies/soc-retention")"
monitors=$(os -H 'Content-Type: application/json' "$OS_URL/_plugins/_alerting/monitors/_search" -d '{"size":50,"query":{"match_all":{}}}')
for file in OpenSearch/monitors/*.json; do
  name=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["name"])' "$file")
  expect "moniteur actif : $name" "True" \
    "$(NAME="$name" jget 'any(h["_source"]["name"] == __import__("os").environ["NAME"] and h["_source"]["enabled"] for h in d["hits"]["hits"])' <<<"$monitors")"
done
expect "tableau de bord « SOC - Vue d'ensemble » (espace global)" "200" "$(osd -o /dev/null -w '%{http_code}' "$OSD_URL/api/saved_objects/dashboard/soc-overview")"
expect "index patterns soc-*" "5" "$(osd "$OSD_URL/api/saved_objects/_find?type=index-pattern&search=soc&search_fields=title&per_page=50" | jget 'sum(1 for o in d["saved_objects"] if o["attributes"]["title"].startswith("soc-"))')"

# =============================================================================
stage "5. Bout en bout : attaque simulée → détection → alerte"
# IP attaquante unique par exécution (plage de documentation RFC 5737)
IP="198.51.100.$((RANDOM % 200 + 20))"
before_honeypot=$(count 'event.dataset:honeypot AND event.kind:alert')
check "campagne d'attaque simulée depuis $IP" ./scripts/simulate-attack.sh tout "$IP"

# Sonde UDP : vérifie aussi l'entrée syslog UDP
TOKEN="sonde-$(date +%s)-$RANDOM"
printf '<38>1 %s srv-verif sshd 1 - - Failed password for %s from %s port 22 ssh2\n' \
  "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$TOKEN" "$IP" | nc -u -w 1 "${SYSLOG_HOST:-localhost}" "${SYSLOG_PORT:-9000}" 2>/dev/null

# Attente de l'indexation (Vector envoie par lots)
for _ in $(seq 1 20); do
  [[ "$(count "user.name:\"$TOKEN\"")" == "1" && "$(count "source.ip:\"$IP\" AND rule.id:web_xss")" -ge 1 ]] && break
  sleep 1
done
expect "syslog UDP : événement indexé" "1" "$(count "user.name:\"$TOKEN\"")"

rule() { # <identifiant de règle> <nombre minimal attendu>
  local n; n=$(count "source.ip:\"$IP\" AND rule.id:$1")
  if [[ "${n:-0}" -ge "$2" ]]; then pass "règle $1 ($n)"; else fail "règle $1" "attendu : au moins $2 — obtenu : ${n:-0}"; fi
}
rule ssh_auth_failure 8
rule ssh_invalid_user 1
rule ssh_root_login 1
rule web_sqli 2
rule web_traversal 1
rule web_xss 1
rule web_cmd_injection 1
rule web_sensitive_file 2
rule web_scanner 1
expect "pare-feu : 15 ports bloqués enregistrés" "15" "$(count "source.ip:\"$IP\" AND event.action:firewall_block")"
for id in user_created admin_group_added sudo_denied sudo_root; do
  n=$(count "rule.id:$id AND @timestamp:[now-2m TO now]")
  if [[ "${n:-0}" -ge 1 ]]; then pass "règle $id ($n)"; else fail "règle $id" "aucun événement récent"; fi
done
after_honeypot=$(count 'event.dataset:honeypot AND event.kind:alert')
if [[ $((after_honeypot - before_honeypot)) -ge 5 ]]; then
  pass "pot de miel : $((after_honeypot - before_honeypot)) contacts détectés (HTTP, SSH, Telnet)"
else
  fail "pot de miel" "attendu : au moins 5 nouveaux contacts — obtenu : $((after_honeypot - before_honeypot))"
fi
expect "horodatage correct (événements datés de moins de 2 minutes)" "True" \
  "$(os -G "$OS_URL/soc-*/_count" --data-urlencode "q=source.ip:\"$IP\" AND @timestamp:[now-2m TO now]" | jget 'd["count"] >= 20')"
expect "technique MITRE ATT&CK renseignée sur les alertes" "0" "$(count "source.ip:\"$IP\" AND event.kind:alert AND NOT _exists_:threat.technique.id")"

# Exécution à blanc des moniteurs : le déclencheur doit désigner l'IP attaquante
dryrun() { # <nom du moniteur>
  local id
  id=$(NAME="$1" jget 'next((h["_id"] for h in d["hits"]["hits"] if h["_source"]["name"] == __import__("os").environ["NAME"]), "")' <<<"$monitors")
  if os -X POST "$OS_URL/_plugins/_alerting/monitors/$id/_execute?dryrun=true" | grep -q "$IP"; then
    pass "alerte « $1 » déclenchée pour $IP"
  else
    fail "alerte « $1 »" "le déclencheur ne désigne pas $IP"
  fi
}
dryrun "SOC - Brute force SSH"
dryrun "SOC - Attaque web"
dryrun "SOC - Scan de ports"
dryrun "SOC - IP à haut risque"

expect "aucun événement rejeté par OpenSearch pendant le test" "0" "$(docker logs --since 90s vector 2>&1 | grep -c 'Events dropped')"

summary
