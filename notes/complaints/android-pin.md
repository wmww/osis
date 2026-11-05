# android-pin
- The branch was claimed at the pinned commit, then the brief changed twice (rebase onto main, then onto a main at or after d87601bf, which local main did not have yet: rebased onto origin/main). Each rebase meant a full Android rebuild of core (15-20 min at load 40).
- cargo-apk 0.10 cannot build this repo (ignores `package.workspace` and the root `exclude`, rejects kit's root package); wrote app/android/build.sh instead.
- The emulator was the slow part: each GPU mode is a reboot, "System UI isn't responding" dialogs at load 40, and its Vulkan loses the device under Vello, so no screenshot of the app was possible.
- `adb install` defaults to incremental installs, which vanished after an emulator restart ("Activity class does not exist"); use `--no-incremental`.
- Review: the worker's commit failed `tools/policy.py libs/kit` (no forbid/workspace lints in app/android) and `cargo deny` (async-executor 1.14.0 yanked upstream, on main too; main's gate skips kit deny for core-only diffs, so it surfaces on the next kit branch). Worker briefs for kit/app should name `python3 tools/policy.py kit` and `(cd kit && cargo deny check)`.
- policy.py scanned app/android's sources as part of the app member too (members nest); now skipped.
