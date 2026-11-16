#!/usr/bin/env bash
# Provisionne le SOC : template d'index, rétention, index patterns et alerte.
# Idempotent : peut être relancé sans risque.
set -euo pipefail
cd "$(dirname "$0")/.."

if [[ -z "${OPENSEARCH_INITIAL_ADMIN_PASSWORD:-}" ]]; then
  set -a; source .env; set +a
fi

OS_URL="${OS_URL:-https://localhost:9200}"
OSD_URL="${OSD_URL:-http://localhost:5601}"
RETENTION_DAYS="${RETENTION_DAYS:-30}"
AUTH="admin:${OPENSEARCH_INITIAL_ADMIN_PASSWORD}"

os()  { curl -sk -u "$AUTH" -H 'Content-Type: application/json' "$@"; }
osd() { curl -s  -u "$AUTH" -H 'Content-Type: application/json' -H 'osd-xsrf: true' "$@"; }
ok()  { printf '  \033[32m✔\033[0m %s\n' "$1"; }
die() { printf '  \033[31m✘\033[0m %s\n' "$1" >&2; exit 1; }

echo "→ Attente d'OpenSearch…"
for _ in $(seq 1 60); do
  os "$OS_URL/_cluster/health" 2>/dev/null | grep -q '"status":"\(green\|yellow\)"' && break
  sleep 5
done || true
os "$OS_URL/_cluster/health" | grep -q '"status":"\(green\|yellow\)"' || die "OpenSearch injoignable sur $OS_URL"
ok "OpenSearch disponible"

# ---------------------------------------------------------------------------
echo "→ Template d'index soc-*"
os -X PUT "$OS_URL/_index_template/soc" -d '{
  "index_patterns": ["soc-*"],
  "priority": 100,
  "template": {
    "settings": {
      "number_of_shards": 1,
      "number_of_replicas": 1,
      "plugins.index_state_management.policy_id": "soc-retention"
    },
    "mappings": {
      "dynamic_templates": [
        { "strings_as_keyword": {
            "match_mapping_type": "string",
            "mapping": { "type": "keyword", "ignore_above": 1024 } } }
      ],
      "properties": {
        "@timestamp": { "type": "date" },
        "message":    { "type": "text" },
        "source":     { "properties": { "ip": { "type": "ip" } } },
        "host":       { "properties": { "ip": { "type": "ip" }, "name": { "type": "keyword" } } },
        "json":       { "type": "flat_object" }
      }
    }
  }
}' | grep -q '"acknowledged":true' && ok "template soc" || die "échec du template"

# ---------------------------------------------------------------------------
echo "→ Politique de rétention (${RETENTION_DAYS} jours)"
POLICY='{
  "policy": {
    "description": "Suppression des logs SOC après '"$RETENTION_DAYS"' jours",
    "default_state": "hot",
    "states": [
      { "name": "hot",
        "actions": [],
        "transitions": [ { "state_name": "delete", "conditions": { "min_index_age": "'"$RETENTION_DAYS"'d" } } ] },
      { "name": "delete", "actions": [ { "delete": {} } ], "transitions": [] }
    ],
    "ism_template": [ { "index_patterns": ["soc-*"], "priority": 100 } ]
  }
}'
existing=$(os "$OS_URL/_plugins/_ism/policies/soc-retention")
if echo "$existing" | grep -q '"_seq_no"'; then
  seq=$(echo "$existing" | sed -E 's/.*"_seq_no":([0-9]+).*/\1/')
  term=$(echo "$existing" | sed -E 's/.*"_primary_term":([0-9]+).*/\1/')
  os -X PUT "$OS_URL/_plugins/_ism/policies/soc-retention?if_seq_no=$seq&if_primary_term=$term" -d "$POLICY" >/dev/null
  ok "politique soc-retention mise à jour"
else
  os -X PUT "$OS_URL/_plugins/_ism/policies/soc-retention" -d "$POLICY" | grep -q '"_id"' \
    && ok "politique soc-retention créée" || die "échec de la politique ISM"
fi

# ---------------------------------------------------------------------------
echo "→ Attente d'OpenSearch Dashboards…"
for _ in $(seq 1 60); do
  [[ "$(osd -o /dev/null -w '%{http_code}' "$OSD_URL/api/status")" == "200" ]] && break
  sleep 5
done
[[ "$(osd -o /dev/null -w '%{http_code}' "$OSD_URL/api/status")" == "200" ]] || die "Dashboards injoignable sur $OSD_URL"
ok "Dashboards disponible"

echo "→ Index patterns"
for name in docker syslog; do
  osd -X POST "$OSD_URL/api/saved_objects/index-pattern/soc-$name?overwrite=true" -d '{
    "attributes": { "title": "soc-'"$name"'-*", "timeFieldName": "@timestamp" }
  }' | grep -q '"id":"soc-'"$name"'"' && ok "soc-$name-*" || die "échec index pattern soc-$name"
done
osd -X POST "$OSD_URL/api/opensearch-dashboards/settings" \
  -d '{"changes":{"defaultIndex":"soc-syslog"}}' >/dev/null && ok "soc-syslog-* par défaut"

# ---------------------------------------------------------------------------
echo "→ Alerte : brute force SSH"
MONITOR_NAME="SOC - Brute force SSH"
MONITOR='{
  "type": "monitor",
  "monitor_type": "bucket_level_monitor",
  "name": "'"$MONITOR_NAME"'",
  "enabled": true,
  "schedule": { "period": { "interval": 1, "unit": "MINUTES" } },
  "inputs": [ { "search": {
    "indices": ["soc-syslog-*"],
    "query": {
      "size": 0,
      "query": { "bool": { "filter": [
        { "term":  { "event.action": "ssh_login" } },
        { "term":  { "event.outcome": "failure" } },
        { "range": { "@timestamp": { "gte": "{{period_end}}||-5m", "lte": "{{period_end}}", "format": "epoch_millis" } } }
      ] } },
      "aggregations": { "par_source": {
        "composite": { "sources": [ { "source_ip": { "terms": { "field": "source.ip" } } } ] }
      } }
    }
  } } ],
  "triggers": [ { "bucket_level_trigger": {
    "name": "5 échecs SSH ou plus en 5 minutes depuis une même IP",
    "severity": "2",
    "condition": {
      "buckets_path": { "nb": "_count" },
      "parent_bucket_path": "par_source",
      "script": { "source": "params.nb >= 5", "lang": "painless" }
    },
    "actions": []
  } } ]
}'
found=$(os "$OS_URL/_plugins/_alerting/monitors/_search" -d '{"query":{"term":{"monitor.name.keyword":"'"$MONITOR_NAME"'"}}}')
mid=$(echo "$found" | grep -oE '"_id":"[^"]+"' | head -1 | cut -d'"' -f4 || true)
if [[ -n "$mid" ]]; then
  os -X PUT "$OS_URL/_plugins/_alerting/monitors/$mid" -d "$MONITOR" | grep -q '"_id"' \
    && ok "moniteur mis à jour" || die "échec de mise à jour du moniteur"
else
  os -X POST "$OS_URL/_plugins/_alerting/monitors" -d "$MONITOR" | grep -q '"_id"' \
    && ok "moniteur créé" || die "échec de création du moniteur"
fi

echo
echo "SOC prêt → $OSD_URL (Discover : soc-syslog-* / soc-docker-*, Alerting : $MONITOR_NAME)"
