# kit-prototype

- `cargo deny` is not installed on this box: the gate's deny step (core and GUI) cannot pass here; kit/deny.toml is unverified.
- In kit/, a bare `cargo build` first built only osis-kit (the root package), leaving a stale `osis-app` binary that exited at once; fixed with `default-members`.
- gui-testing: sessions die after the 10 min TTL (`-t` to raise it); `guibox start` that fails still leaves a session dir and its app holding the store lock; easy to mix up session dirs when restarting.
- masonry_winit panics at startup without `DISPLAY` (X11 clipboard unwrap): every Wayland-only test session; patched in kit/patches.
- `rm -rf` on scratch stores was denied by the permission system; use fresh directory names instead.
