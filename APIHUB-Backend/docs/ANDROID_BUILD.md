# Android build (Telegram bot)

1. Use **APIHUB-App.zip** (already structured: `APIHUB/pubspec.yaml` at the project root — the bot needs `pubspec.yaml` at the root, otherwise it falls back to a native-Android build and fails with "gradlew not found"). Do not include `build/`, `.dart_tool/`, `android/local.properties`, `key.properties` or any keystore.
2. The bot must run (Flutter 3.27+ / Dart 3.3+ recommended):
   ```
   flutter pub get
   flutter build apk --release        # or: flutter build appbundle --release
   ```
   The Gradle wrapper JAR is not shipped; Flutter regenerates it automatically.
3. Output: `build/app/outputs/flutter-apk/app-release.apk`.

Details
* Application ID `com.nexobless.apihub`, `minSdk` 23, only the `INTERNET` permission.
* Network security: **HTTPS only**, except `localhost` and `10.0.2.2` (emulator). To test a plain-HTTP server on your LAN during development, edit `android/app/src/main/res/xml/network_security_config.xml` (never ship that).
* Toolchain pins (Flutter 3.29 era): AGP 8.9.1, Kotlin 2.1.0, Gradle 8.12.1 (`android/settings.gradle.kts`, `gradle-wrapper.properties`). If your bot uses a much older/newer Flutter and Gradle complains, run once `flutter create --platforms=android .` in a scratch copy and align those three versions with the generated ones.
* **Verification status:** this project was authored without a Flutter SDK, so it has **not been compiled by the author**. If the first build reports an error, send the log and it can be fixed quickly.
