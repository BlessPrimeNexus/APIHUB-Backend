# Backend deployment (Docker, ~10 min)

Requirements: a Linux server, Docker + Compose, a domain pointing to it (ports 80/443 open).

```
cd backend
cp .env.example .env
# edit .env:
#   MASTER_KEY=$(openssl rand -hex 32)    <- keep it safe; losing it makes stored environment secrets unreadable
#   APIHUB_DOMAIN=apihub.example.com
docker compose up -d --build
curl https://apihub.example.com/health      # {"status":"ok",...}
```
Caddy obtains the TLS certificate automatically. In production the server refuses non-HTTPS requests (`REQUIRE_HTTPS=1`, via `X-Forwarded-Proto`) and refuses to start without a strong `MASTER_KEY`.

Without Docker: Node ≥ 22.13 → `cd backend && NODE_ENV=production MASTER_KEY=... npm start` behind any TLS reverse proxy.

Migrations run automatically at startup (`npm run migrate` to run them alone).

## Backup & restore
```
./backup.sh ./backups          # consistent online snapshot (VACUUM INTO)
# restore: stop the container first
./restore.sh backups/apihub-YYYYMMDD-HHMMSS.db
```
Inside Docker: `docker compose exec apihub sh -c "./backup.sh /app/data/backups"` (scripts are inside the image), or snapshot the `apihub-data` volume. Also back up `.env` (MASTER_KEY).

## Using it
App → Settings → Server URL `https://apihub.example.com` → Create account → publish an API. Published endpoints are served at `https://apihub.example.com/run/<api-slug>/<path>`.

## Hébergeurs : lesquels conviennent ?

Le backend est un processus Node **toujours actif**, qui garde sa base SQLite dans un **dossier persistant** (`DATABASE_PATH`) et planifie ses vérifications en arrière-plan. Il faut donc : un conteneur/VM permanent, un volume persistant, **une seule instance**.

| Hébergeur | Verdict |
|---|---|
| VPS (Hetzner, OVH, Contabo, DigitalOcean…) + Docker Compose | **Recommandé** : le plus simple et le moins cher, tout est déjà prêt (`docker-compose.yml`, Caddy/HTTPS). |
| Railway | **Oui**, avec un **Volume** monté sur `/app/data`. Variables : `MASTER_KEY`, `DATABASE_PATH=/app/data/apihub.db`, `TRUST_PROXY=1`, et **`RAILWAY_RUN_UID=0`** (l’image tourne en utilisateur non-root, sinon erreur de permission sur le volume). Ne pas activer « Serverless ». |
| Render | **Oui, en offre payante** avec un **Disk** monté sur `/app/data`. L’offre gratuite se met en veille après 15 min et son disque est effacé à chaque redémarrage/déploiement : inutilisable pour la base et la surveillance. |
| Fly.io, Koyeb, Northflank | Possible avec volume persistant (même principe). |
| **Vercel / Netlify / Cloudflare Workers** | **Non** : fonctions sans état, sans disque persistant ni processus permanent. Il faudrait réécrire le backend (PostgreSQL externe + fonctions). |

Réglages communs : `NODE_ENV=production`, `MASTER_KEY` (32+ caractères), `TRUST_PROXY=1` (la plateforme fournit le HTTPS), `PORT` est fourni par la plateforme. Test de santé : `GET /health`. Ne jamais lancer 2 instances en même temps (SQLite + limiteur de débit en mémoire). Sauvegardez régulièrement (`backup.sh`).

Ces plateformes n’ont **pas été testées** pour cette version ; les conditions (offres, prix) évoluent : vérifiez-les avant de choisir.
