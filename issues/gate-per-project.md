# Gate per project
> Summary: When kit/ and app/ land (own Cargo workspace, notes/app.md), tools/gate.sh must pick checks by changed paths so GUI work skips the core gate and core work still catches app breakage.
> Tags: tools, kit, app

Repro: none yet; due with the first GUI crate.

- GUI-only diff (`kit/`, `app/`): GUI workspace build, tests, clippy only.
- Core diff: the core gate as today, plus `cargo check` of the GUI workspace (an osis API change must not silently break the app).
- Both: both.
- tools/policy.py and spec_map.py assume core code: skip kit/ and app/ or apply only the rules that fit.
- Same pattern as the sim-sweep skip already in gate.sh; generalizes to further projects in the monorepo (notes/overview.md).
