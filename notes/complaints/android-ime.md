# android-ime
- The shared emulator's adb connection dropped ("device offline") every few minutes mid-command; `adb wait-for-device` before each step and re-running the step was enough.
- Apps targeting SDK 36 get no `onBackPressed` on Android 16: the first Back closed the app and the next scripted tap landed in the launcher's Google bar (a Google sign-in screen). `OnBackInvokedCallback` is the only path.
- The emulator's Gboard never composes (commits each letter, here and in Google Messages), so composing paths can't be seen on it without a CJK layout.
- javac 27 with `-cp android.jar` needs `-source 11 -target 11 -Xlint:-options` (no `--release` with a foreign bootclasspath).
- Review: editing a vendored masonry file means regenerating its `.diff` by hand (no script): reverse-apply the committed diff to get the base, `git diff --no-index` base vs file, rewrite the paths. A first random IME test reached no surrogate-split deletes (short texts, caret mostly at the end); count the case before trusting a generator.
