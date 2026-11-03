# spec-audit-rest (lodestar-spec-audit-rest)
- A two-test `cargo test -p osis-node --test it` took 7.5 minutes on the busy machine; osis-crdt under 2. Prefer settling by reading before reaching for it.
- Parallel grep of huge spec lines: one `cat spec/*` overflows the tool output; `awk` per section is the way.
