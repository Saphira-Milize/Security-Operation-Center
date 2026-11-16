#!/usr/bin/env python3
"""Génère Dashboards/soc.ndjson (index patterns, visualisations, tableau de bord).

    python3 Dashboards/build.py && ./scripts/setup.sh dashboards

Le fichier généré est versionné : Python n'est nécessaire que pour le modifier.
On peut aussi éditer le tableau de bord dans l'interface puis l'exporter
(Dashboards Management → Saved objects → Export) vers Dashboards/soc.ndjson.
"""
import json
from pathlib import Path

VERSION = "3.9.0"
ALL = "soc-all"
ALERTS = "event.kind:alert"
objects = []


def add(type_, id_, attributes, references=()):
    objects.append({"type": type_, "id": id_, "attributes": attributes,
                    "references": list(references)})


def search_source(query=""):
    return {"kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({
        "query": {"query": query, "language": "kuery"}, "filter": [],
        "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index"})}}


INDEX_REF = [{"name": "kibanaSavedObjectMeta.searchSourceJSON.index",
              "type": "index-pattern", "id": ALL}]


def vis(id_, title, type_, params, aggs, query="", description=""):
    state = {"title": title, "type": type_, "params": params, "aggs": aggs}
    attributes = {"title": title, "description": description, "version": 1,
                  "visState": json.dumps(state, ensure_ascii=False), "uiStateJSON": "{}"}
    if type_ == "markdown":  # pas de données : aucun index pattern associé
        attributes["kibanaSavedObjectMeta"] = {"searchSourceJSON": json.dumps(
            {"query": {"query": "", "language": "kuery"}, "filter": []})}
        add("visualization", id_, attributes)
    else:
        attributes.update(search_source(query))
        add("visualization", id_, attributes, INDEX_REF)
    return id_


# --- Agrégations ------------------------------------------------------------
def count(label="Nombre"):
    return {"id": "1", "enabled": True, "type": "count", "schema": "metric",
            "params": {"customLabel": label}}


def metric(id_, type_, field, label):
    return {"id": id_, "enabled": True, "type": type_, "schema": "metric",
            "params": {"field": field, "customLabel": label}}


def terms(id_, field, label, schema="bucket", size=10, order_by="1"):
    return {"id": id_, "enabled": True, "type": "terms", "schema": schema, "params": {
        "field": field, "orderBy": order_by, "order": "desc", "size": size,
        "otherBucket": False, "otherBucketLabel": "Autres",
        "missingBucket": False, "missingBucketLabel": "Inconnu", "customLabel": label}}


def over_time(id_="2"):
    return {"id": id_, "enabled": True, "type": "date_histogram", "schema": "segment", "params": {
        "field": "@timestamp", "useNormalizedOpenSearchInterval": True, "scaleMetricValues": False,
        "interval": "auto", "drop_partials": False, "min_doc_count": 1, "extended_bounds": {},
        "customLabel": " "}}


# --- Types de visualisation -------------------------------------------------
def big_number(id_, title, agg, query, font=48):
    return vis(id_, title, "metric", {
        "addTooltip": True, "addLegend": False, "type": "metric",
        "metric": {"percentageMode": False, "useRanges": False, "colorSchema": "Green to Red",
                   "metricColorMode": "None", "colorsRange": [{"from": 0, "to": 1000000}],
                   "labels": {"show": True}, "invertColors": False,
                   "style": {"bgFill": "#000", "bgColor": False, "labelColor": False,
                             "subText": "", "fontSize": font}}}, [agg], query)


def table(id_, title, aggs, query="", per_page=8):
    return vis(id_, title, "table", {
        "perPage": per_page, "showPartialRows": False, "showMetricsAtAllLevels": False,
        "sort": {"columnIndex": None, "direction": None}, "showTotal": False,
        "totalFunc": "sum", "percentageCol": ""}, aggs, query)


def donut(id_, title, aggs, query=""):
    return vis(id_, title, "pie", {
        "type": "pie", "addTooltip": True, "addLegend": True, "legendPosition": "right",
        "isDonut": True, "labels": {"show": False, "values": True, "last_level": True,
                                    "truncate": 100}}, aggs, query)


def stacked_bars(id_, title, split_field, split_label, query="", y_label="Événements"):
    return vis(id_, title, "histogram", {
        "type": "histogram", "grid": {"categoryLines": False},
        "categoryAxes": [{"id": "CategoryAxis-1", "type": "category", "position": "bottom",
                          "show": True, "style": {}, "scale": {"type": "linear"},
                          "labels": {"show": True, "filter": True, "truncate": 100}, "title": {}}],
        "valueAxes": [{"id": "ValueAxis-1", "name": "LeftAxis-1", "type": "value", "position": "left",
                       "show": True, "style": {}, "scale": {"type": "linear", "mode": "normal"},
                       "labels": {"show": True, "rotate": 0, "filter": False, "truncate": 100},
                       "title": {"text": y_label}}],
        "seriesParams": [{"show": True, "type": "histogram", "mode": "stacked",
                          "data": {"label": y_label, "id": "1"}, "valueAxis": "ValueAxis-1",
                          "drawLinesBetweenPoints": True, "lineWidth": 2, "showCircles": True}],
        "addTooltip": True, "addLegend": True, "legendPosition": "right", "times": [],
        "addTimeMarker": False, "labels": {"show": False},
        "thresholdLine": {"show": False, "value": 10, "width": 1, "style": "full", "color": "#E7664C"}},
        [count(y_label), over_time(), terms("3", split_field, split_label, schema="group")], query)


# --- Index patterns ---------------------------------------------------------
for id_, title in [(ALL, "soc-*"), ("soc-syslog", "soc-syslog-*"), ("soc-web", "soc-web-*"),
                   ("soc-honeypot", "soc-honeypot-*"), ("soc-docker", "soc-docker-*")]:
    add("index-pattern", id_, {"title": title, "timeFieldName": "@timestamp"})

# --- Visualisations ---------------------------------------------------------
panels = []  # (id, x, y, largeur, hauteur) sur une grille de 48 colonnes


def place(id_, x, y, w, h, kind="visualization"):
    panels.append((id_, kind, x, y, w, h))


place(vis("soc-intro", "SOC - Mode d'emploi", "markdown", {
    "fontSize": 12, "openLinksInNewTab": False,
    "markdown": (
        "### Centre des opérations de sécurité\n"
        "Chaque alerte porte une **règle** (`rule.name`), une **gravité**, un **score de menace** "
        "et une technique **MITRE ATT&CK**. Le tableau *Attaquants* additionne les scores par IP, "
        "toutes sources confondues : une IP qui échoue en SSH, scanne le site web *et* touche "
        "le pot de miel remonte en tête.\n\n"
        "Cliquez sur une valeur pour filtrer tout le tableau de bord. "
        "Alertes déclenchées : menu **Alerting**.")}, []), 0, 0, 16, 9)

place(big_number("soc-m-alerts", "Alertes", count("Alertes"), ALERTS), 16, 0, 8, 9)
place(big_number("soc-m-ips", "IP à l'origine d'alertes",
                 metric("1", "cardinality", "source.ip", "IP attaquantes"), ALERTS), 24, 0, 8, 9)
place(big_number("soc-m-score", "Score de menace cumulé",
                 metric("1", "sum", "rule.score", "Score de menace"), ALERTS), 32, 0, 8, 9)
place(big_number("soc-m-events", "Événements collectés", count("Événements"), ""), 40, 0, 8, 9)

place(stacked_bars("soc-alerts-time", "Alertes dans le temps, par gravité",
                   "rule.severity", "Gravité", ALERTS, "Alertes"), 0, 9, 30, 14)
place(donut("soc-alerts-rule", "Répartition des alertes par règle",
            [count("Alertes"), terms("2", "rule.name", "Règle", schema="segment", size=15)], ALERTS),
      30, 9, 18, 14)

place(table("soc-attackers", "Attaquants : classement par score de menace", [
    metric("1", "sum", "rule.score", "Score de menace"),
    {"id": "2", "enabled": True, "type": "count", "schema": "metric", "params": {"customLabel": "Alertes"}},
    metric("3", "cardinality", "rule.id", "Règles distinctes"),
    metric("4", "cardinality", "event.dataset", "Sources de logs"),
    terms("5", "source.ip", "IP source", size=20)], ALERTS, per_page=10), 0, 23, 24, 16)
place(table("soc-mitre", "Techniques MITRE ATT&CK observées", [
    count("Alertes"),
    terms("2", "threat.tactic.name", "Tactique", size=15),
    terms("3", "threat.technique.id", "ID", size=15),
    terms("4", "threat.technique.name", "Technique", size=15)], ALERTS, per_page=10), 24, 23, 24, 16)

place(donut("soc-ssh", "Connexions SSH : réussites et échecs",
            [count("Connexions"), terms("2", "event.outcome", "Résultat", schema="segment")],
            "event.action:ssh_login"), 0, 39, 12, 13)
place(table("soc-users", "Comptes visés par des échecs d'authentification", [
    count("Tentatives"), terms("2", "user.name", "Compte", size=20)],
    "event.outcome:failure and user.name:*"), 12, 39, 12, 13)
place(table("soc-honeypot", "Pot de miel : qui a mordu ?", [
    count("Contacts"),
    terms("2", "source.ip", "IP source", size=20),
    terms("3", "network.protocol", "Service", size=5),
    terms("4", "rule.name", "Type", size=5)], "event.dataset:honeypot"), 24, 39, 24, 13)

place(stacked_bars("soc-web-status", "Web : requêtes par code HTTP",
                   "http.response.status_code", "Code HTTP", "event.dataset:web", "Requêtes"),
      0, 52, 24, 13)
place(table("soc-web-urls", "Web : URL attaquées", [
    count("Requêtes"),
    terms("2", "rule.name", "Règle", size=10),
    terms("3", "url.original", "URL", size=20)],
    "event.dataset:web and event.kind:alert"), 24, 52, 24, 13)

place(stacked_bars("soc-volume", "Volume d'événements par source de logs",
                   "event.dataset", "Source", "", "Événements"), 0, 65, 30, 13)
place(table("soc-containers", "Conteneurs : erreurs et avertissements", [
    count("Lignes"),
    terms("2", "container.name", "Conteneur", size=20),
    terms("3", "log.level", "Niveau", size=5)],
    "event.dataset:docker and log.level:(error or critical or warning)"), 30, 65, 18, 13)

# --- Recherche enregistrée : dernières alertes -------------------------------
add("search", "soc-latest-alerts", {
    "title": "SOC - Dernières alertes", "description": "",
    "columns": ["rule.severity", "rule.name", "source.ip", "user.name", "host.name", "message"],
    "sort": [["@timestamp", "desc"]], "version": 1,
    "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({
        "query": {"query": ALERTS, "language": "kuery"}, "filter": [],
        "highlightAll": True, "version": True,
        "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index"})}}, INDEX_REF)
place("soc-latest-alerts", 0, 78, 48, 20, kind="search")

# --- Tableau de bord ---------------------------------------------------------
add("dashboard", "soc-overview", {
    "title": "SOC - Vue d'ensemble",
    "description": "Alertes, attaquants, techniques MITRE ATT&CK, pot de miel et santé de la collecte",
    "panelsJSON": json.dumps([
        {"version": VERSION, "panelIndex": str(i), "panelRefName": f"panel_{i}", "embeddableConfig": {},
         "gridData": {"x": x, "y": y, "w": w, "h": h, "i": str(i)}}
        for i, (_, _, x, y, w, h) in enumerate(panels)]),
    "optionsJSON": json.dumps({"hidePanelTitles": False, "useMargins": True}),
    "version": 1, "timeRestore": True, "timeFrom": "now-24h", "timeTo": "now",
    "refreshInterval": {"pause": False, "value": 30000},
    "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps(
        {"query": {"language": "kuery", "query": ""}, "filter": []})}},
    [{"name": f"panel_{i}", "type": kind, "id": id_} for i, (id_, kind, *_) in enumerate(panels)])

out = Path(__file__).with_name("soc.ndjson")
out.write_text("".join(json.dumps(o, ensure_ascii=False) + "\n" for o in objects))
print(f"{out.name} : {len(objects)} objets")
