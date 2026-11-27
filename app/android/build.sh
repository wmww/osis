#!/usr/bin/env bash
# Builds the debug-signed osis APK (notes/android.md): app/android/build.sh [arm64|x86_64].
# Needs ANDROID_HOME (SDK with build-tools and platforms;android-36), ANDROID_NDK_ROOT and a JDK.
# Prints the APK's path.
set -euo pipefail
abi=${1:-arm64}
case $abi in
    arm64) target=aarch64-linux-android dir=arm64-v8a ;;
    x86_64) target=x86_64-linux-android dir=x86_64 ;;
    *) echo "usage: $0 [arm64|x86_64]" >&2; exit 2 ;;
esac
here=$(cd "$(dirname "$0")" && pwd)
root=$here/../..
: "${ANDROID_HOME:?set ANDROID_HOME}" "${ANDROID_NDK_ROOT:?set ANDROID_NDK_ROOT}"
bt=$(ls -d "$ANDROID_HOME"/build-tools/* | sort -V | tail -1)
jar=$ANDROID_HOME/platforms/android-36/android.jar
llvm=$ANDROID_NDK_ROOT/toolchains/llvm/prebuilt/linux-x86_64/bin
# release: a debug build turns on wgpu's debug labels (they crash the emulator's Vulkan driver)
# and masonry's debug log file, and is slow on a phone; NDK r28+ aligns to 16 KB pages
(cd "$root" && app/android/with-ndk "$target" cargo build --release -p osis-android --target "$target")
out=$root/target/$target/release/apk
rm -rf "$out" && mkdir -p "$out/lib/$dir"
cp "$root/target/$target/release/libosis_android.so" "$out/lib/$dir/"
"$llvm/llvm-strip" --strip-debug "$out/lib/$dir/libosis_android.so"
# java/: the activity, the view and its input connection, as classes.dex
mkdir -p "$out/classes"
javac -source 11 -target 11 -Xlint:-options -nowarn -cp "$jar" -d "$out/classes" $(find "$here/java" -name '*.java')
"$bt/d8" --release --min-api 28 --lib "$jar" --output "$out" $(find "$out/classes" -name '*.class')
"$bt/aapt2" link -o "$out/unaligned.apk" --manifest "$here/AndroidManifest.xml" -I "$jar"
(cd "$out" && zip -q -r unaligned.apk lib classes.dex)
"$bt/zipalign" -f -P 16 4 "$out/unaligned.apk" "$out/aligned.apk"
ks=$HOME/.android/debug.keystore
if [ ! -f "$ks" ]; then
    mkdir -p "$(dirname "$ks")"
    keytool -genkeypair -keystore "$ks" -storepass android -keypass android -alias androiddebugkey \
        -keyalg RSA -keysize 2048 -validity 10000 -dname "CN=Android Debug,O=Android,C=US" >/dev/null
fi
"$bt/apksigner" sign --ks "$ks" --ks-pass pass:android --out "$out/osis-$abi.apk" "$out/aligned.apk"
echo "$out/osis-$abi.apk"
