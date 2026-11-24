# Signing & updates (no installation conflicts)

Android only installs an update if the **package name AND the signing key are identical** and `versionCode` is higher.

## One-time: create your permanent keystore (on your machine, never in the ZIP)
```
keytool -genkey -v -keystore apihub-release.jks -alias apihub -keyalg RSA -keysize 2048 -validity 10000
```
**Back this file and its passwords up in at least two safe places. If you lose it you can never update the app for existing users.**

## Give it to the build
Create `android/key.properties` **on the build machine only**:
```
storeFile=/absolute/path/apihub-release.jks
storePassword=...
keyAlias=apihub
keyPassword=...
```
`android/app/build.gradle.kts` reads it automatically. Without this file the build falls back to the debug key (works, but each build machine has its own debug key → updates over a build from another machine will fail with "package conflicts"). For a Telegram bot: store the keystore + key.properties in the bot's private storage and copy them into `android/` before building.

## Every release
1. Edit `pubspec.yaml`: `version: 1.0.1+2` (the number after `+` = versionCode; **must increase every time**).
2. Keep `applicationId com.nexobless.apihub` untouched.
3. Build with the same keystore.
