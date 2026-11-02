# Judgment vectors: what is still missing
> Summary: `core/test/vectors/judgment/` (format: its README; generated and replayed by osis-node `tests/it/judgment.rs`) holds the roles model's reference scenarios, one scenario per rule family (epoch starts, `until`, invites included) and 6 pinned order-harness histories; still missing: referenced blobs, multi-label bundles, ledger chains across several starts, over-invite grants, re-merges.
> Tags: tests, permissions, retention, spec

## Left
- Referenced blobs (pages, chunk trees, linked header lists, linked frontiers) as bundle blob records without entries (the generator asserts none).
- Epoch starts beyond one snapshot: a second start carrying the ledger forward, an excluded start (§6 rounds), a demotion after the start auditing pre-start writes.
- Invites beyond the invite: the engine's grant flow refuses an over-invite grant locally, so a vector needs a hand-built commit.
- crdt-model's pinned cases (`tests/props.proptest-regressions`) are join properties, not judgments: no vector.
- Re-merges of nested writes (a valid snapshot or commit giving back an un-merged write): order seeds 1006, 12161 show them (11-16 KB of bundle each), left out for size.
- Size: models.vec 83 KB, rules.vec 198 KB. Per file 26 KB of `setup` hex; a bundle is about 1 KB per commit, and a grant through `Engine::grant` on G adds about 20 KB (G gets secrets of its own: the setup's edges are bare writes). Pinned seeds left out (list in `judgment.rs` `found()`) could go in another file, at 26 KB of setup plus 5-25 KB each.
