#!/usr/bin/env bash
# Provisionne le SOC. Idempotent : peut être relancé sans risque.
#
#   ./scripts/setup.sh              tout (par défaut)
#   ./scripts/setup.sh opensearch   comptes, rôles, index, rétention, alertes
#   ./scripts/setup.sh dashboards   index patterns et tableau de bord
#
# Lancé automatiquement par `docker compose up` (services soc-setup*).
# Les ressources sont dans OpenSearch/ et Dashboards/ : modifiez-les puis
# relancez ce script pour les appliquer.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
STAGE="${1:-all}"

if [[ -z "${OPENSEARCH_INITIAL_ADMIN_PASSWORD:-}" && -f "$ROOT/.env" ]]; then
  set -a; source "$ROOT/.env"; set +a
fi

OS_URL="${OS_URL:-https://localhost:9200}"
OSD_URL="${OSD_URL:-http://localhost:5601}"
RETENTION_DAYS="${RETENTION_DAYS:-30}"
SOC_WEBHOOK_URL="${SOC_WEBHOOK_URL:-}"
AUTH="admin:${OPENSEARCH_INITIAL_ADMIN_PASSWORD:?OPENSEARCH_INITIAL_ADMIN_PASSWORD manquant (voir .env.example)}"

TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

step() { printf '→ %s\n' "$1"; }
ok()   { printf '  ✔ %s\n' "$1"; }
die()  { printf '  ✘ %s\n' "$1" >&2; exit 1; }

# Échappe une valeur pour l'insérer dans une chaîne JSON
json_escape() { local s=$1; s=${s//\\/\\\\}; s=${s//\"/\\\"}; printf '%s' "$s"; }

# call <libellé> <args curl…> : exécute la requête, corps dans $TMP, code dans $CODE
call() {
  local label=$1; shift
  CODE=$(curl -sk -u "$AUTH" -o "$TMP" -w '%{http_code}' "$@") || die "$label : connexion impossible"
}
# must <libellé> <args curl…> : comme call, mais échoue si le code n'est pas 2xx
must() {
  call "$@"
  [[ $CODE == 2* ]] || die "$1 : HTTP $CODE — $(head -c 400 "$TMP")"
}
os_json() { local label=$1; shift; must "$label" -H 'Content-Type: application/json' "$@"; }

wait_for() { # <libellé> <url> <motif attendu>
  local label=$1 url=$2 pattern=$3
  step "Attente de ${label}..."
  for _ in $(seq 1 90); do
    if curl -sk -u "$AUTH" "$url" 2>/dev/null | grep -q "$pattern"; then
      ok "$label disponible"; return
    fi
    sleep 4
  done
  die "$label injoignable sur $url"
}

# ===========================================================================
setup_opensearch() {
  wait_for "OpenSearch" "$OS_URL/_cluster/health" '"status":"\(green\|yellow\)"'

  # --- Comptes à privilèges réduits ---------------------------------------
  step "Rôles et comptes"
  os_json "rôle soc_ingest" -X PUT "$OS_URL/_plugins/_security/api/roles/soc_ingest" -d '{
    "description": "Écriture des événements dans les index soc-* (Vector)",
    "cluster_permissions": ["cluster_monitor", "indices:data/write/bulk"],
    "index_permissions": [ { "index_patterns": ["soc-*"], "allowed_actions": ["create_index", "write"] } ]
  }'
  ok "rôle soc_ingest (écriture sur soc-* uniquement)"

  os_json "rôle soc_analyst" -X PUT "$OS_URL/_plugins/_security/api/roles/soc_analyst" -d '{
    "description": "Lecture seule des événements SOC et des tableaux de bord",
    "cluster_permissions": ["cluster_composite_ops_ro"],
    "index_permissions": [
      { "index_patterns": ["soc-*"], "allowed_actions": ["read", "indices:admin/mappings/get", "indices:admin/resolve/index"] },
      { "index_patterns": [".kibana", ".kibana_*", ".opensearch_dashboards", ".opensearch_dashboards_*"], "allowed_actions": ["read"] }
    ],
    "tenant_permissions": [ { "tenant_patterns": ["global_tenant"], "allowed_actions": ["kibana_all_read"] } ]
  }'
  ok "rôle soc_analyst (lecture seule)"

  create_user vector "${VECTOR_PASSWORD:-}" '"soc_ingest"' "Compte de service du pipeline Vector"
  create_user analyste "${ANALYST_PASSWORD:-}" '"soc_analyst", "alerting_ack_alerts"' "Analyste SOC (lecture seule)"

  # --- Index ---------------------------------------------------------------
  step "Modèle d'index soc-*"
  os_json "modèle d'index" -X PUT "$OS_URL/_index_template/soc" -d @"$ROOT/OpenSearch/index-template.json"
  ok "champs typés (IP, dates, scores)"

  step "Rétention : $RETENTION_DAYS jours"
  sed "s/__RETENTION_DAYS__/$RETENTION_DAYS/g" "$ROOT/OpenSearch/retention-policy.json" > "$TMP.policy"
  call "politique ISM" "$OS_URL/_plugins/_ism/policies/soc-retention"
  local suffix=""
  if [[ $CODE == 200 ]]; then
    local seq term
    seq=$(jq -r '._seq_no // empty' "$TMP" 2>/dev/null || python3 -c "import sys, json; print(json.load(sys.stdin).get('_seq_no', ''))" < "$TMP" 2>/dev/null \
      || grep -oE '"_seq_no":[0-9]+' "$TMP" | head -1 | cut -d: -f2 || true)
    term=$(jq -r '._primary_term // empty' "$TMP" 2>/dev/null || python3 -c "import sys, json; print(json.load(sys.stdin).get('_primary_term', ''))" < "$TMP" 2>/dev/null \
      || grep -oE '"_primary_term":[0-9]+' "$TMP" | head -1 | cut -d: -f2 || true)
    if [[ -n "$seq" && -n "$term" ]]; then
      suffix="?if_seq_no=$seq&if_primary_term=$term"
    fi
  fi
  os_json "politique ISM" -X PUT "$OS_URL/_plugins/_ism/policies/soc-retention$suffix" -d @"$TMP.policy"
  rm -f "$TMP.policy"
  ok "politique soc-retention"

  # --- Notifications -------------------------------------------------------
  local bucket_action="" query_action=""
  if [[ -n "$SOC_WEBHOOK_URL" ]]; then
    step "Canal de notification"
    local kind=webhook
    [[ "$SOC_WEBHOOK_URL" == *hooks.slack.com* ]] && kind=slack
    local config='{ "name": "SOC", "description": "Alertes du SOC", "config_type": "'$kind'", "is_enabled": true,
      "'$kind'": { "url": "'"$(json_escape "$SOC_WEBHOOK_URL")"'" } }'
    call "canal" "$OS_URL/_plugins/_notifications/configs/soc-webhook"
    if [[ $CODE == 200 ]]; then
      os_json "canal de notification" -X PUT "$OS_URL/_plugins/_notifications/configs/soc-webhook" -d '{ "config": '"$config"' }'
    else
      os_json "canal de notification" -X POST "$OS_URL/_plugins/_notifications/configs" -d '{ "config_id": "soc-webhook", "config": '"$config"' }'
    fi
    ok "canal « SOC » ($kind)"
    local common='"destination_id": "soc-webhook",
      "subject_template": { "source": "[SOC] {{ctx.monitor.name}}", "lang": "mustache" }'
    # Moniteurs par IP : une notification par nouvelle IP en alerte
    bucket_action='{ "name": "Notifier", '"$common"', "throttle_enabled": false,
      "message_template": { "lang": "mustache", "source": "[SOC] {{ctx.monitor.name}} : {{ctx.trigger.name}}. IP concernée(s) : {{#ctx.newAlerts}}{{bucket_keys}} {{/ctx.newAlerts}}" },
      "action_execution_policy": { "action_execution_scope": { "per_alert": { "actionable_alerts": ["NEW"] } } } }'
    # Moniteur simple : au plus une notification toutes les 10 minutes
    query_action='{ "name": "Notifier", '"$common"', "throttle_enabled": true, "throttle": { "value": 10, "unit": "MINUTES" },
      "message_template": { "lang": "mustache", "source": "[SOC] {{ctx.monitor.name}} : {{ctx.trigger.name}} ({{ctx.results.0.hits.total.value}} événement(s))" } }'
  fi

  # --- Moniteurs d'alerte --------------------------------------------------
  step "Moniteurs d'alerte"
  local file name id body action
  for file in "$ROOT"/OpenSearch/monitors/*.json; do
    name=$(grep -oE '"name": *"[^"]+"' "$file" | head -1 | sed -E 's/"name": *"(.*)"/\1/')
    body=$(cat "$file")
    action=$bucket_action
    grep -q '"query_level_monitor"' "$file" && action=$query_action
    body=${body//\"actions\": \[\]/\"actions\": [ $action ]}

    os_json "recherche du moniteur" "$OS_URL/_plugins/_alerting/monitors/_search" \
      -d '{ "size": 1, "query": { "term": { "monitor.name.keyword": "'"$(json_escape "$name")"'" } } }'
    id=$(jq -r '.hits.hits[0]._id // empty' "$TMP" 2>/dev/null || python3 -c "import sys, json; h=json.load(sys.stdin).get('hits',{}).get('hits',[]); print(h[0]['_id'] if h else '')" < "$TMP" 2>/dev/null || true)
    if [[ -n "$id" ]]; then
      os_json "moniteur $name" -X PUT "$OS_URL/_plugins/_alerting/monitors/$id" -d "$body"
    else
      os_json "moniteur $name" -X POST "$OS_URL/_plugins/_alerting/monitors" -d "$body"
    fi
    ok "$name"
  done
  if [[ -z "$SOC_WEBHOOK_URL" ]]; then
    # Webhook retiré du .env : le canal devenu inutile est supprimé
    call "canal" "$OS_URL/_plugins/_notifications/configs/soc-webhook"
    if [[ $CODE == 200 ]]; then
      os_json "suppression du canal" -X DELETE "$OS_URL/_plugins/_notifications/configs/soc-webhook"
    fi
    echo "  (notifications désactivées : définissez SOC_WEBHOOK_URL dans .env pour être prévenu)"
  fi
}

create_user() { # <nom> <mot de passe> <rôles JSON> <description>
  local user=$1 password=$2 roles=$3 description=$4
  local pass="${password:-${OPENSEARCH_INITIAL_ADMIN_PASSWORD:-}}"
  [[ -n "$pass" ]] || die "mot de passe du compte « $user » manquant (voir .env.example)"
  os_json "compte $user" -X PUT "$OS_URL/_plugins/_security/api/internalusers/$user" -d '{
    "password": "'"$(json_escape "$pass")"'",
    "description": "'"$description"'",
    "opendistro_security_roles": ['"$roles"']
  }'
  ok "compte $user"
}

# ===========================================================================
setup_dashboards() {
  wait_for "OpenSearch Dashboards" "$OSD_URL/api/status" '"state":"green"'

  step "Tableau de bord et index patterns"
  # « securitytenant: global » : sans cet en-tête, l'API range les objets dans
  # l'espace privé du compte admin, invisible pour les autres utilisateurs.
  must "import des objets" -H 'osd-xsrf: true' -H 'securitytenant: global' \
    -F "file=@$ROOT/Dashboards/soc.ndjson" "$OSD_URL/api/saved_objects/_import?overwrite=true"
  grep -q '"success":true' "$TMP" || die "import incomplet — $(head -c 400 "$TMP")"
  ok "$(grep -oE '"successCount":[0-9]+' "$TMP" | cut -d: -f2) objets importés"

  must "index pattern par défaut" -H 'osd-xsrf: true' -H 'securitytenant: global' -H 'Content-Type: application/json' \
    -X POST "$OSD_URL/api/opensearch-dashboards/settings" \
    -d '{ "changes": { "defaultIndex": "soc-all", "defaultRoute": "/app/dashboards#/view/soc-overview" } }'
  ok "page d'accueil : tableau de bord « SOC - Vue d'ensemble »"
}

# ===========================================================================
case "$STAGE" in
  opensearch) setup_opensearch ;;
  dashboards) setup_dashboards ;;
  all)        setup_opensearch; setup_dashboards ;;
  *)          die "étape inconnue : $STAGE (all | opensearch | dashboards)" ;;
esac

echo
echo "SOC prêt → $OSD_URL"
