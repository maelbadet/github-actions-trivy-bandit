# github-actions-trivy-bandit

## Objectif
Ce projet a pour but de mettre en place :
- une stack de monitoring avec `Prometheus`, `Grafana` et `node-exporter`
- une stack `WordPress` avec `MariaDB`
- une ou plusieurs pipelines GitHub Actions pour le contrôle de sécurité

Le dépôt doit aussi permettre :
- un scan `Trivy`
- la génération d'un rapport de vulnérabilités
- l'envoi des résultats vers l'onglet `Security` de GitHub

## Stack utilisée

### Monitoring
- `prom/prometheus`
- `grafana/grafana`
- `prom/node-exporter`

### Application
- `wordpress`
- `mariadb`

## Lancement en local
Le projet utilise des variables d'environnement pour éviter de laisser des secrets en clair.

1. Créer un fichier `.env` à partir de `.env.example`
2. Renseigner les valeurs attendues
3. Lancer la stack

```bash
docker compose up -d
```

## Accès aux services
- `WordPress` : `http://localhost:8080`
- `Grafana` : `http://localhost:3000`
- `Prometheus` : `http://localhost:9090`
- `node-exporter` : `http://localhost:9100/metrics`

## Pipelines GitHub Actions

### `ci.yml`
Cette pipeline sert de pipeline principale.

Elle peut contenir les étapes suivantes :
1. récupération du code avec `actions/checkout`
2. chargement des variables et secrets GitHub
3. validation de la configuration `docker compose`
4. démarrage éventuel de la stack pour vérifier que les services sont cohérents
5. arrêt et nettoyage des conteneurs

Cette pipeline est utile pour vérifier que l'infrastructure du projet reste valide à chaque `push` et `pull request`.

### `trivy.yml`
Cette pipeline est dédiée au scan de sécurité avec `Trivy`.

Elle peut contenir les étapes suivantes :
1. récupération du code
2. installation ou appel de `Trivy`
3. scan du repository avec `trivy fs`
4. génération d'un rapport de vulnérabilités
5. export au format `SARIF`
6. envoi des résultats vers `GitHub Security`

Cette séparation est propre, parce que `Trivy` a un objectif différent de la simple validation de la stack.

### `bandit.yml`
Oui, tu peux créer un fichier `bandit.yml`.

Il a du sens uniquement si tu ajoutes du code Python dans le projet, par exemple :
- un script utilitaire
- un script de génération de rapport
- un script de contrôle dans la pipeline

Dans ce cas, `bandit.yml` peut contenir :
1. récupération du code
2. installation de Python et de `Bandit`
3. scan du dossier contenant les scripts Python
4. génération d'un rapport `Bandit`

Si tu n'as pas de code Python, alors `bandit.yml` n'apporte rien et il vaut mieux ne pas le créer.

## Gestion des secrets
Les secrets ne doivent pas être écrits en clair dans les workflows ni dans `docker-compose.yml`.

À mettre dans `Repository Secrets` :
- `WORDPRESS_DB_PASSWORD`
- `MARIADB_ROOT_PASSWORD`
- `GF_SECURITY_ADMIN_USER`
- `GF_SECURITY_ADMIN_PASSWORD`

À mettre éventuellement dans `Repository Variables` si tu veux aussi sortir les valeurs non sensibles :
- `MARIADB_DATABASE`
- `MARIADB_USER`

## Valeur ajoutée possible
En bonus, il est possible d'ajouter :
- un script Python utile à la pipeline
- un scan `Bandit`
- un rapport de vulnérabilités Python

## Remarque
Pour ce projet, séparer les workflows en plusieurs fichiers est une bonne approche :
- `ci.yml` pour la validation générale
- `trivy.yml` pour la sécurité des dépendances et de l'infra
- `bandit.yml` pour la sécurité du code Python, seulement si du Python existe réellement
