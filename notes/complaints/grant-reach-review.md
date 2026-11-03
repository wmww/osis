# grant-reach-review
> Summary: mishaps while reviewing grant-reach.
- `cargo test --workspace --test it a b` fails with a bare usage error: several name filters go after `--`, and `-p osis` is what one crate wants.
- `w.run()` does not advance the clock past a reconnect back-off: after `set_online(.., true)` a test needs `w.advance`, and "never arrived" looks like a bug until then.
- Tried recomputing an inbox copy's chain on every pass (to heal a partial copy): `tied::group_admin_learns_removal_elsewhere` caught it carrying the thing's newest `keys.0`, with the seed a removal meant to keep from the group. My targeted subset had not run `tied::`; only the gate did.
