# Architecture

## Mobile app (`app/lib`)
```
main.dart
app/            app.dart (MaterialApp, theme mode), router/shell.dart (floating nav), theme/ (tokens, ThemeData)
core/           constants, errors, network (http_runner, api_client, request_builder), security (Vault),
                services, utils (json, variables, assertions, openapi_tools, postman, data_gen), widgets
data/           models, datasources (LocalStore), repositories (AppState)
features/       dashboard, authentication, projects, api_builder, request_tester, environments, collections,
                documentation, monitoring, history, automated_tests, settings, subscriptions, testdata
```
* State: one `AppState` (`ChangeNotifier`) exposed with an `InheritedNotifier` (`AppScope`). No third-party state package, to keep the dependency surface small.
* Local-first: everything is saved as JSON in SharedPreferences (debounced). **Secrets are never in that file**: tokens, passwords, environment secrets and the session live in `Vault` (flutter_secure_storage → Android Keystore).
* Offline mode / sync: every edit marks the project *dirty*. When signed in, `syncProject` pushes it to `POST /v1/workspaces/:wid/sync`. The server refuses to overwrite newer server data (reported as a conflict, nothing overwritten).
* Dependencies: `http`, `shared_preferences`, `flutter_secure_storage`, `yaml` (OpenAPI YAML import).

## Backend (`backend/src`)
* Node.js ≥ 22.13, **zero runtime dependencies** (built-in `node:http`, `node:sqlite`, `node:crypto`). Justification: it could be fully tested here without network access, has no supply-chain surface, and deploys as one small container. SQLite (WAL) is a deliberate choice for a single-node install; migrations are plain SQL (`migrations/`) so a move to PostgreSQL is mechanical (see below).
* `routes/` management API (`/v1/...`), `engine.js` execution engine (`/run/<slug>/...`), `monitor.js` scheduler (health checks, alert evaluation, retention purge), `ssrf.js`, `security.js`, `openapi.js`.
* Roles: owner > admin > developer > viewer, enforced per request via workspace membership; resources of other workspaces answer `404`.

### Scaling notes (honest)
SQLite + in-memory rate limiter = single instance. For multi-instance: replace `RateLimiter` with Redis and the DB layer with PostgreSQL (schema is portable; `db.js` is the only module touching the driver API).
