# The gate runs everything for a comment-only Rust change
> Summary: A branch whose Rust diff touches only comments (a spec pointer sweep) pays the full gate, about 8 min and 3600 CPU-s, though no test reads a comment; tools/gate.sh needs a comments path beside its docs path.
> Priority: normal
> Tags: tests, performance

sync-spec repointed about 2000 `spec/sync.md §N` comments across 308 files: its gate selected 24 of 26 crates and took 485 s and about 3600 CPU-s (`build` 786 CPU-s, the hold 264 s). Most of that diff was comments; 14 lines were strings (vector headers, an error message) and tools/spec_map.py changed, so it rightly took the full gate, but a branch of comments alone pays the same, though only clippy, policy and doctests can judge it. Spec reorganizations in the sync rewrite will make such branches.

Wanted: a `core=comments` path in tools/gate.sh, taken when every changed `.rs` line, added or removed, is a whole-line `//` comment, all other paths being docs-only ones (notes/gate.md, Steps). It runs the instant checks, `cargo clippy --all-targets -- -D warnings` (a broken `/*` or a stray edit fails to compile) and `cargo test --doc` for each crate whose changed comment is a doc comment (`///`, `//!`: a doctest may sit in it); no default tests, properties or sim. A trailing comment on a code line, a string, an attribute or a test name falls through to the full gate, so the check errs toward running more. The test for it: sync-spec's `d8b89848d` fails the check (14 lines are strings: an error message, vector headers), `6050ae05f` passes.
