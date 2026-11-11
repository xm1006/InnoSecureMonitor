# Inno TUID Monitor — LSPosed Modern API 102

This is a read-only diagnostic module targeting `com.jifen.qukan`.

## Build

The GitHub Actions workflow at `.github/workflows/api102-build.yml` builds:
`api102/app/build/outputs/apk/debug/app-debug.apk`

## Install

1. Install the generated debug APK.
2. Enable the module in LSPosed.
3. Keep the scope limited to the intended test package.
4. Force-stop and relaunch the target app.
5. Inspect LSPosed logs using the tag `InnoTuidMonitor`.

## Scope and logging

The uploaded `qtt.jar` DEX string table contains candidate class names
`com.inno.innosdk.pb.InnoMain` and `com.inno.innosdk.pb.InnoValue`.
The module checks candidate methods named `getTuid`, `getTk`, `loadTuid`,
`getInnoValue`, and `secureSo`.

This first build records method signatures, argument types, string/byte-array
lengths, primitive test values, return types, elapsed time, and thrown exceptions.
It deliberately does not write raw TK/TUID/device/account identifiers to logcat.

The JAR's DEX string table is not sufficient to prove all overload signatures;
the log will report which candidate methods were actually found. This module
does not modify method arguments, return values, or native behavior.

## API

Uses `io.github.libxposed:api:102.0.0`; no legacy XposedBridge APIs.
