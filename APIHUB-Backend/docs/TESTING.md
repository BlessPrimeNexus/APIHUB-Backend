# Tests — what was actually run

| Suite | Command | Result when delivered |
|---|---|---|
| Backend end-to-end (auth, permissions, projects, endpoints, engine, auth modes, rate limit, docs, stats, alerts, sync, automated tests, env secrets, collections, SSRF, hashing) | `cd backend && npm test` | **16/16 passed** (executed) |
| Backend: server starts, `/health`, migration, backup script, prod refuses missing MASTER_KEY | manual | executed, OK |
| Flutter unit tests | `cd app && flutter test` | **written, not executed** (no Flutter SDK available) |
| Flutter compile / APK build | `flutter build apk` | **not executed** |
| Flutter static checks done instead | bracket/string-aware lexer over all Dart files, import and symbol resolution | executed, clean |

Not verified: UI behaviour on a device, Gradle/AGP version compatibility with your bot's Flutter, real-device keystore behaviour.
