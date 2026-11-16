# Security Operation Center

Un SOC léger, basé sur Docker, qui collecte, normalise et analyse des logs de sécurité :

- **OpenSearch** (cluster de 2 nœuds) : stockage et recherche ;
- **OpenSearch Dashboards** : exploration, visualisation, alertes ;
- **Vector** : collecte (logs Docker + syslog), normalisation et détection.

```
 Serveurs / équipements ──syslog :9000──┐
                                         ├──► Vector ──► OpenSearch (2 nœuds) ──► Dashboards :5601
 Conteneurs Docker ─────docker.sock──────┘     │
                                               └─ détection SSH / sudo
```

## Prérequis

- Docker et Docker Compose ;
- environ 4 Go de RAM disponibles pour Docker.

Sous **Windows (WSL via Docker Desktop)**, configurez `vm.max_map_count` dans la distribution WSL de Docker Desktop :

    wsl -d docker-desktop
    sysctl -w vm.max_map_count=262144

## Démarrage

```bash
cp .env.example .env        # puis choisissez un mot de passe robuste
docker compose up -d        # démarre OpenSearch, Dashboards et Vector
./scripts/setup.sh          # provisionne index, rétention, index patterns et alertes
```

| Service               | Adresse                     | Identifiants                          |
|-----------------------|-----------------------------|---------------------------------------|
| OpenSearch Dashboards | http://localhost:5601       | `admin` / mot de passe du `.env`      |
| API OpenSearch        | https://localhost:9200      | idem (certificat auto-signé)          |
| API Vector (santé)    | http://localhost:8686/health | —                                    |
| Syslog (TCP et UDP)   | `localhost:9000`            | —                                     |

> Le mot de passe n'est appliqué qu'à la **première** initialisation des volumes.
> Pour le changer ensuite : `docker compose down -v` (efface les données) puis redémarrer.

## Envoyer des logs

**Logs Docker** : collectés automatiquement pour tous les conteneurs de l'hôte.

**Syslog** depuis une machine Linux (rsyslog), dans `/etc/rsyslog.d/90-soc.conf` :

```
*.* @@IP_DU_SOC:9000    # @@ = TCP, @ = UDP
```

puis `sudo systemctl restart rsyslog`.

> Le syslog classique (RFC 3164) envoie l'heure **locale sans fuseau**. Vector l'interprète
> selon `SOC_TIMEZONE` (défaut : `Europe/Paris`, à définir dans `.env`). Le format RFC 5424
> contient son fuseau et n'est pas concerné.

## Ce que fait le pipeline

Configuration : [Vector/vector.yaml](Vector/vector.yaml).

| Index               | Contenu                                                              |
|---------------------|----------------------------------------------------------------------|
| `soc-docker-AAAA.MM.JJ` | logs des conteneurs, niveau (`log.level`) déduit, JSON parsé dans `json` |
| `soc-syslog-AAAA.MM.JJ` | syslog normalisé + champs de détection                              |

Les champs suivent l'esprit d'[Elastic Common Schema](https://www.elastic.co/guide/en/ecs/current/index.html) : `@timestamp`, `host.name`, `user.name`, `source.ip`, `event.action`, `event.outcome`…

### Détections

| Règle                           | `event.action`       | Marquée comme alerte (`event.kind: alert`) |
|---------------------------------|----------------------|--------------------------------------------|
| Échec d'authentification SSH    | `ssh_login` (failure) | oui                                       |
| Utilisateur SSH inexistant      | `ssh_invalid_user`   | oui                                        |
| Connexion SSH réussie           | `ssh_login` (success) | non                                       |
| `sudo` vers root                | `sudo`               | oui                                        |

### Alerte

`scripts/setup.sh` crée le moniteur **« SOC - Brute force SSH »** : il se déclenche quand une même IP
cumule au moins 5 échecs SSH en 5 minutes. Les alertes sont visibles dans
*Dashboards → Alerting*. Ajoutez-y une destination (Slack, e-mail, webhook) pour être notifié.

### Rétention

Les index `soc-*` sont supprimés automatiquement après 30 jours (politique ISM `soc-retention`).
Pour changer la durée : `RETENTION_DAYS=90 ./scripts/setup.sh`.

## Tester

```bash
./scripts/test-vector.sh         # valide la config Vector et lance ses tests unitaires
./scripts/simulate-attack.sh     # envoie une fausse attaque SSH par syslog
```

Après la simulation, filtrez `event.kind: alert` dans *Discover* (index `soc-syslog-*`) ;
l'alerte de brute force apparaît dans *Alerting* en moins d'une minute.

Les tests unitaires sont dans [Vector/tests.yaml](Vector/tests.yaml) : ajoutez-en un pour chaque nouvelle règle.

## Arrêter

```bash
docker compose down        # arrête en conservant les données
docker compose down -v     # arrête et supprime les données
```
