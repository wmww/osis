# keel-acct-sign2
> Summary: Mishaps on the account signing leftovers branch.

- Built roles-model with `--release` once out of habit (CLAUDE.md forbids release builds in a task); deleted `target/release` again.
- An engine test's writes and the removal landed in one millisecond, so the cutoff (strict `<` on receipt ms) named nothing and the listing came out empty: tests near the cutoff need `lp.advance(1)` between receipt and closer.
- Two issue items (session-sources, the witness cutoff) described designs main no longer has; checking took longer than the fixes would have.
