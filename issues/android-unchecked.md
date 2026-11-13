# osis-android code is compiled by nothing the gate runs
> Summary: osis-android is `#![cfg(target_os = "android")]`, so host `cargo clippy -p osis-android` and the gate compile it empty; only `app/android/build.sh` (a release NDK build) compiles it. A broken Android shell merges green. Wanted: a gate stage that type-checks it for an Android target (`cargo clippy --target x86_64-linux-android -p osis-android`, needing the NDK's clang for ring) when app/android or kit changes, skipped with a visible note where no NDK is installed.
> Priority: normal
> Tags: tests, android
