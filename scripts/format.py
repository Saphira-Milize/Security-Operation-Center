#!/usr/bin/env python3
"""Mise en forme des réponses d'OpenSearch pour la commande ./soc.

    … | python3 scripts/format.py alertes
    … | python3 scripts/format.py rapport <heures>

Compatible Python 3.8+, bibliothèque standard uniquement.
"""
import json
import sys
from datetime import datetime


def load():
    try:
        return json.load(sys.stdin)
    except ValueError:
        sys.exit("OpenSearch injoignable : le SOC est-il démarré ? (./soc demarrer)")


def buckets(agg):
    return agg.get("buckets", [])


def alertes():
    alerts = load().get("alerts", [])
    if not alerts:
        print("Aucune alerte active.")
        return
    print("{} alerte(s) active(s) :".format(len(alerts)))
    for a in sorted(alerts, key=lambda a: (a["severity"], a["monitor_name"])):
        target = ", ".join(a.get("agg_alert_content", {}).get("bucket_keys", [])) or "-"
        print("  [gravité {}] {:<40} {}".format(a["severity"], a["monitor_name"], target))


def rapport(hours):
    data = load()
    if "aggregations" not in data:
        sys.exit("Rapport impossible : aucun index soc-* (./soc etat)")
    aggs = data["aggregations"]
    al = aggs["alertes"]
    sev = {b["key"]: b["doc_count"] for b in buckets(al["gravite"])}
    sources = ", ".join("{} {}".format(b["key"], b["doc_count"]) for b in buckets(aggs["sources"]))

    print("# Rapport SOC — {} dernières heures".format(hours))
    print("_Généré le {:%d/%m/%Y à %H:%M}_\n".format(datetime.now()))
    print("## Synthèse\n")
    print("- Événements collectés : **{}** ({})".format(data["hits"]["total"]["value"], sources or "aucun"))
    print("- Alertes : **{}** (élevée {}, moyenne {}, faible {})".format(
        al["doc_count"], sev.get("high", 0), sev.get("medium", 0), sev.get("low", 0)))
    print("- Score de menace cumulé : **{}**".format(int(al["score"]["value"])))
    if not al["doc_count"]:
        print("\nAucune alerte sur la période.")
        return

    print("\n## Attaquants (classés par score de menace)\n")
    print("| IP | Score | Alertes | Sources de logs | Règles principales |")
    print("|---|---:|---:|---:|---|")
    for b in buckets(al["attaquants"]):
        print("| {} | {} | {} | {} | {} |".format(
            b["key"], int(b["score"]["value"]), b["doc_count"], b["sources"]["value"],
            ", ".join(r["key"] for r in buckets(b["regles"]))))

    print("\n## Alertes par règle\n")
    for b in buckets(al["regles"]):
        print("- {} : {}".format(b["key"], b["doc_count"]))

    print("\n## Techniques MITRE ATT&CK\n")
    for b in buckets(al["techniques"]):
        print("- {} {} : {}".format(b["key"][0], b["key"][1], b["doc_count"]))

    accounts = buckets(al["comptes"]["noms"])
    if accounts:
        print("\n## Comptes visés\n")
        print(", ".join("{} ({})".format(b["key"], b["doc_count"]) for b in accounts))


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else ""
    if mode == "alertes":
        alertes()
    elif mode == "rapport":
        rapport(sys.argv[2] if len(sys.argv) > 2 else "24")
    else:
        sys.exit(__doc__)
