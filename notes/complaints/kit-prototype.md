# kit-prototype

- `cargo deny` is not installed on this box: the gate's deny step (core and GUI) cannot pass here; kit/deny.toml is unverified.
- In kit/, a bare `cargo build` first built only osis-kit (the root package), leaving a stale `osis-app` binary that exited at once; fixed with `default-members`.
- gui-testing: sessions die after the 10 min TTL (`-t` to raise it); `guibox start` that fails still leaves a session dir and its app holding the store lock; easy to mix up session dirs when restarting.
- masonry_winit panics at startup without `DISPLAY` (X11 clipboard unwrap): every Wayland-only test session; patched in kit/patches.
- `rm -rf` on scratch stores was denied by the permission system; use fresh directory names instead.
- `claudewait` is not on PATH on this box (not in ~/.local/bin either): waiting on a background gate fell back to task notifications.
- With deny missing, timing a gate run per project needed `--base REV` plus throwaway probe commits; the core run stops at deny before the GUI `cargo check` (about 1 s warm, run by hand).
- Review: `git diff --name-only` follows renames by default, so a core file moved into kit/ listed only the kit path and the gate skipped core; now `--no-renames`, with `tools/gate_select_test.sh` (fabricated histories against `gate.sh --plan`).
