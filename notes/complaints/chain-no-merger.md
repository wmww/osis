# chain-no-merger
> Summary: Workflow notes from the chain-no-merger branch (any node of the account rotates; forks stand).

- The epochs model's honest policies hard-coded node 0 as the only merger, the remover and the roster side; letting any member rotate surfaced a dozen classification holes in the checker (re-add with the remover gone, the removal and its rotation signed at different epochs, a removed node's pre-removal head beside its removal). Each needed a hand trace of a 20-60 item world: a `print_world` that emits a minimal Rust test, and a shrinker for epochs worlds, would have saved most of the time.
- Model receipt semantics are mixed (`< t` in `rotation_candidates`, `<= t` elsewhere): a rotator's list was cut by a view one tick older than the one it rotated on.
- `epochs-exh-c` grown by half ran 2.07x the heavy limit; the gone case had to replace a case rather than add one. A family's size budget next to its definition would make the trade visible before the run.
- By mistake one `cargo test --release` of roles-model and one `timeout`-wrapped cargo ran; both cleaned up.
