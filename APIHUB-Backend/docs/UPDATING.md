# Updating
**App:** bump `version` in `pubspec.yaml` (increase the `+N`), build with the *same* keystore (see SIGNING_AND_UPDATES.md), install over the old version. Data and secrets are kept.
**Backend:** `git pull`/replace files → `docker compose up -d --build`. New migrations run automatically and are recorded in `schema_migrations`. Take a backup first (`scripts_backup.sh`). Never edit an already-applied migration; add `002_*.sql`.
