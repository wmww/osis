# The app ships no screen reader support
> Summary: osis-kit's `accessibility` feature (AccessKit's platform adapter) is off by default to keep the GUI build small; turn it on (make it default, or drop the feature) before the app ships.
> Priority: normal
> Tags: app, kit, tess-call

Tess's call: off while prototyping. Off, `masonry_winit`'s `src/a11y.rs` is a no-op adapter and Masonry still builds its access tree only when asked (never). On costs ~55 crates on Linux (zbus); Windows and macOS adapters are smaller. Android has no adapter either way (`accesskit_winit`'s `accesskit_android` feature is not enabled). Test it with a screen reader (Orca) when turning it on. On, cargo deny reports the zbus stack's advisories (RUSTSEC-2026-0370, -0371, -0372: zvariant, zbus_names, zvariant_derive; no fix upstream of accesskit_unix yet): ignore them in deny.toml or upgrade.
