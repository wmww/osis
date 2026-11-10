# Android
> Summary: The experimental Android build of the app (app/android): the same app as desktop opened by NativeActivity; build recipe (SDK/NDK under ~/android, app/android/build.sh, no cargo-apk), the platform layer (files dir, clipboard), what works, and the blockers (no soft-keyboard text in winit 0.30, emulator GPU).

## Shape
- `app/android` (crate `osis-android`, a kit-workspace member; empty on every other target): `android_main` opens the store in `<files dir>/store` without a peer, builds the winit loop with the `AndroidApp` (`osis_kit::window::App::with_event_loop`) and runs the same `Ui` as desktop's main.rs. Lints are the workspace's with `unsafe_code = "deny"` (the one `#[unsafe(no_mangle)]` on `android_main` is allowed there).
- Platform layer: `osis_kit::platform` (cfg android) holds a clipboard reader the crate sets; the reader calls `ClipboardManager` over JNI from `ActivityThread.currentApplication()` (safe `jni` calls, `JavaVM::singleton` set by android-activity).
- App side, all `cfg(target_os = "android")`: a "Paste" chip beside the search field feeds the clipboard through the search field's text path (links, peer addresses, queries), and the composer block adds "Paste and send".
- Logging: `android_logger` to logcat (tag `osis`), a panic hook, and a tracing-subscriber `fmt` writer to logcat installed before masonry's default (whose debug log file in `temp_dir` panics on Android: /data/local/tmp is not writable).
- Manifest: app/android/AndroidManifest.xml (NativeActivity, `lib_name` osis_android, INTERNET, minSdk 28, targetSdk 36, adjustResize, config changes kept in-process, `allowBackup="false"` so the store and its keys never go to cloud or device-transfer backups, not debuggable so `run-as` cannot read them; add `android:debuggable="true"` locally to inspect the store). No icon.

## Build recipe
- One-time, no root: Android command-line tools unzipped to `~/android/sdk/cmdline-tools/latest`; `sdkmanager --sdk_root=$HOME/android/sdk "platform-tools" "build-tools;37.0.0" "platforms;android-36" "ndk;29.0.14206865"` (plus `emulator` and `system-images;android-36;google_apis;x86_64` for an emulator); `rustup target add aarch64-linux-android x86_64-linux-android`. Java 21 (system) runs sdkmanager, keytool and apksigner.
- `ANDROID_HOME=~/android/sdk ANDROID_NDK_ROOT=~/android/sdk/ndk/29.0.14206865 app/android/build.sh [arm64|x86_64]`: `cargo build --release -p osis-android --target <t>` with the NDK clang as linker and `CC`/`AR` for ring, then aapt2 link (manifest only), zip in `lib/<abi>/libosis_android.so`, `zipalign -P 16` (16 KB pages), apksigner with `~/.android/debug.keystore` (made on first run). Prints the APK path: `target/<t>/release/apk/osis-<abi>.apk`. About 15 min cold on a loaded box.
- Release, not debug: a debug build turns on wgpu's debug labels (`InstanceFlags::from_build_config`), which crash the emulator's Vulkan driver in `vkSetDebugUtilsObjectNameEXT`, and masonry's debug log file.
- cargo-apk 0.10 does not work here: its cargo-subcommand ignores `package.workspace` and the root workspace's `exclude`, and rejects kit's root package that is also the workspace root. xbuild was not tried; the manual packaging is 20 lines.

## Status
- Builds clean for aarch64 and x86_64; `aapt dump badging` shows net.osis.app, INTERNET, NativeActivity launchable, native-code arm64-v8a; apksigner verifies; zipalign -P 16 passes.
- Emulator (API 36 google_apis x86_64 image, arm64 builds run too through its translation): the app starts, the store opens, the Vulkan adapter (SwiftShader through gfxstream) is found and Vello compiles its shaders, then the first frame fails: `get_current_texture` errors `Other` (a device error: the device is lost), and the next frame panics on an invalid texture. Same with `-gpu lavapipe`; `-gpu host` does not start headless; with `-feature -Vulkan` the GLES adapter has no compute and wgpu finds no compatible device. So nothing was seen rendered; the emulator's GPU cannot run Vello as far as tried.
- Untested on a real phone: rendering, touch, the clipboard, QUIC sync, joining.

## Blockers and limits
- Soft keyboard: winit 0.30's Android backend has no IME. With NativeActivity `showSoftInput` is refused ("view is not served"); with GameActivity the keyboard shows but its text arrives as `InputEvent::TextEvent`, which winit 0.30 drops. A hardware keyboard's key events do type. Fix later: winit with Android IME (or a patched winit forwarding GameActivity text as `Ime::Commit`), then drop the paste chips.
- Rendering unverified (emulator above). If a phone shows the same device loss, the next step is wgpu/Vello on that GPU, not the app.
- No safe-area insets: the status bar and gesture bar overlap the window's edges.
- Store dir in app-private storage: uninstalling deletes the store (and its keys).
- Logs at info to logcat: no app code logs links, keys or messages; errors carry the store path. Dependencies (masonry, wgpu, quinn) log far more at debug/trace, unaudited: keep the cap at info.
