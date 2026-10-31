# No conformance artifact for validity: a second implementation cannot be checked against the spec
> Summary: spec/permissions.md §5-§6 and spec/commits.md §5 were tuned by thousands of harness-found order-dependence cases (notes/mvp-progress.md round 13), and the reference models (`core/test/crdt-model`, `core/test/membership-model`) are the real definition of several rules; the conformance vectors (`core/test/vectors`) cover bytes (CBOR, crypto, commits, blobs, steps) but no judgment: there is no "held set in, verdicts out" vector, so a compatible implementation (spec/overview.md's stated goal) has nothing to test its validity, cover, death-dating or un-merge logic against except reading osis's code.
> Tags: tests, permissions, retention, spec

## Recommended fix
A vector subject `judgment/` in `core/test/vectors` (same freeze policy as the byte vectors):
- Input: a bundle file (spec/wire.md §12) holding the commits as a server would hold them, the receiving node's seed and the actors it holds, the arrival order, and the clock.
- Expected: per delta its validity, per thing its roster and epoch start, the drop set D in found order, per body covered/uncovered and its death dates, and a digest of each aspect's canonical state and read.
- Generation: `gen-vectors` replays the order harness's shrunk seeds and the models' pinned counterexamples (notes/testing.md lists them per fix), so every fixed bug becomes a vector; plus one hand-picked scenario per spec rule family (frontier coverage, re-grant, snapshot vouching, cover drop and uncover, keep-at-most finality, un-merge).
- Freeze: provisional until the first stable release like the others; any change to a judgment vector is a spec change by definition and is logged as one.
Run as a tier-1 test against the engine; a second implementation runs the same files.
