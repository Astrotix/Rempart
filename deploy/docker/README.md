# ZTNA Sovereign - Déploiement Docker

Docker Compose pour lancer le Control Plane complet avec PostgreSQL.

## 🚀 Démarrage rapide

```bash
cd deploy/docker
docker-compose up -d
```

**Accès :**
- **Dashboard** : http://localhost:3000
- **API** : http://localhost:8080
- **PostgreSQL** : localhost:5432 (user: `ztna`, password: `ztna-secret`)

## 📦 Services

### 1. PostgreSQL (`postgres`)
- Base de données persistante (volume `pgdata`)
- Port 5432 exposé
- Migrations automatiques au démarrage de l'API

### 2. Control Plane API (`api`)
- Go API avec connexion PostgreSQL
- Port 8080
- Toutes les données sont **persistées** dans PostgreSQL

### 3. Dashboard (`dashboard`)
- React + Vite, build en production
- Nginx reverse proxy vers l'API
- Port 3000

### 4. PoP Test (`pop-test`) - Optionnel
- Ubuntu 22.04 avec WireGuard
- Pour tester le PoP en local
- **Note** : WireGuard nécessite des privilèges, mieux vaut utiliser un VPS réel

## 🔧 Configuration

Les variables d'environnement sont dans `docker-compose.yml`. Pour changer les secrets :

```yaml
environment:
  - DB_PASS=ton-mot-de-passe
  - JWT_SECRET=ton-secret-jwt
```

## 📊 Vérifier que PostgreSQL fonctionne

```bash
# Voir les logs
docker-compose logs api

# Se connecter à PostgreSQL
docker-compose exec postgres psql -U ztna -d ztna_sovereign

# Lister les tables
\dt
```

## 🛑 Arrêter

```bash
docker-compose down
# Pour supprimer aussi les volumes (⚠️ perte de données)
docker-compose down -v
```

## 🔄 Mettre à jour

```bash
git pull
docker-compose build --no-cache
docker-compose up -d
```
