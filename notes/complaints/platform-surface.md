# platform-surface
- The emulator's installed store from an older build failed to open (`storage: commit blob` in logcat) and the app showed a black screen with no on-screen error: `adb shell pm clear net.osis.app` first (now in notes/android.md). A store that fails to open could say so on screen.
- `adb shell input tap` twice cannot land inside a 300 ms double-tap window, so double and triple taps on Android are checked by kit's tests only; touch on desktop is untestable (gui-testing has no touch).
- osis-android compiles only through build.sh (a release build, about a minute warm); host clippy builds it empty, so its Rust gets no clippy at all.
