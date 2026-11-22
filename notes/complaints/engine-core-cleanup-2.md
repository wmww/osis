# engine-core-cleanup-2
> Summary: Cleanup worker notes: what a skim-level cleanup of pages/secrets/large/listing finds, and how lines of code move under it.

- pages.rs, secrets.rs, large.rs and listing.rs were already tight: the wins were repeated key arithmetic (`row_key(d) ‖ 0`, `id + 1` as a set's end), the same "copy epochs for reading only" loop twice, a hand-rolled copy of `op_type`, one forwarding wrapper. Naming each repeated piece adds a doc line and a signature, so `tools/loc.py` barely moves (pages.rs +6): judge such a commit by repeated knowledge removed, not by lines.
- Moving a block out of `Engine::run` into a free function is a mechanical dedent plus `&mut tx` -> `tx`; a Python f-string holding the `{` of a Rust signature silently mangled the first attempt (wip-commit first, check `git diff --stat`).
