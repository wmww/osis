# Judgment vectors: what is still missing
> Summary: `core/test/vectors/judgment/` (format: its README; generated and replayed by osis-node `tests/it/judgment.rs`) holds the roles model's reference scenarios, one scenario per rule family (epoch starts, `until`, invites included) and 21 pinned order-harness histories; still missing: referenced blobs, multi-label bundles, ledger chains across several starts; rules.vec is 650 KB (each case repeats the setup's body lines, role commits' secrets dominate bundles).
> Tags: tests, permissions, retention, spec

## Left
- Referenced blobs (pages, chunk trees, linked header lists, linked frontiers) as bundle blob records without entries (the generator asserts none).
- Epoch starts beyond one snapshot: a second start carrying the ledger forward, an excluded start (§6 rounds), a demotion after the start auditing pre-start writes.
- Invites beyond the invite: the engine's grant flow refuses an over-invite grant locally, so a vector needs a hand-built commit.
- crdt-model's pinned cases (`tests/props.proptest-regressions`) are join properties, not judgments: no vector.
- Size: models.vec 124 KB, rules.vec 650 KB. Each case repeats about 3 KB of the setup commits' `body`/`aspect` lines (judging the setup once per file would save about 200 KB); a history's bundle is 3-24 KB, more with role commits' secrets and boxes (the invite case 48 KB). Order seeds left out as other shapes (12236, 1042, 583188, 845143) or not shown under seed 1038 (1085: shows 1024's case) could go in a file of their own if wanted.
