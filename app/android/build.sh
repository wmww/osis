#!/usr/bin/env bash
# Builds the debug-signed osis APK (notes/android.md): app/android/build.sh [arm64|x86_64].
# Needs ANDROID_HOME (SDK with build-tools and platforms;android-36) and ANDROID_NDK_ROOT.
# Prints the APK's path.
set -euo pipefail
abi=${1:-arm64}
case $abi in
    arm64) target=aarch64-linux-android dir=arm64-v8a ;;
    x86_64) target=x86_64-linux-android dir=x86_64 ;;
    *) echo "usage: $0 [arm64|x86_64]" >&2; exit 2 ;;
esac
here=$(cd "$(dirname "$0")" && pwd)
kit=$here/../../kit
: "${ANDROID_HOME:?set ANDROID_HOME}" "${ANDROID_NDK_ROOT:?set ANDROID_NDK_ROOT}"
bt=$(ls -d "$ANDROID_HOME"/build-tools/* | sort -V | tail -1)
jar=$ANDROID_HOME/platforms/android-36/android.jar
llvm=$ANDROID_NDK_ROOT/toolchains/llvm/prebuilt/linux-x86_64/bin
t=${target//-/_}
T=${t^^}
# NDK clang links (min SDK 28) and builds ring's C; NDK r28+ aligns to 16 KB pages.
export "CARGO_TARGET_${T}_LINKER=$llvm/${target}28-clang" "CC_${t}=$llvm/${target}28-clang" "AR_${t}=$llvm/llvm-ar"
# release: a debug build turns on wgpu's debug labels (they crash the emulator's Vulkan driver)
# and masonry's debug log file, and is slow on a phone
(cd "$kit" && cargo build --release -p osis-android --target "$target")
out=$kit/target/$target/release/apk
rm -rf "$out" && mkdir -p "$out/lib/$dir"
cp "$kit/target/$target/release/libosis_android.so" "$out/lib/$dir/"
"$llvm/llvm-strip" --strip-debug "$out/lib/$dir/libosis_android.so"
"$bt/aapt2" link -o "$out/unaligned.apk" --manifest "$here/AndroidManifest.xml" -I "$jar"
(cd "$out" && zip -q -r unaligned.apk lib)
"$bt/zipalign" -f -P 16 4 "$out/unaligned.apk" "$out/aligned.apk"
ks=$HOME/.android/debug.keystore
if [ ! -f "$ks" ]; then
    mkdir -p "$(dirname "$ks")"
    keytool -genkeypair -keystore "$ks" -storepass android -keypass android -alias androiddebugkey \
        -keyalg RSA -keysize 2048 -validity 10000 -dname "CN=Android Debug,O=Android,C=US" >/dev/null
fi
"$bt/apksigner" sign --ks "$ks" --ks-pass pass:android --out "$out/osis-$abi.apk" "$out/aligned.apk"
echo "$out/osis-$abi.apk"
