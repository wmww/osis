# A forged copy under a dropped body's dot shows where the original never arrived
> Summary: a valid writer's snapshot copying another value under the dot of a delta whose body its holders dropped (covered) before others got it shows the forged value at nodes that never received the delta, while nodes that did (the author) show the original: honest nodes disagree for good. Not a cover-check bug (the forged snapshot covers nothing). Pre-existing design residual; needs a design call.
> Tags: security, engine, retention, tests

Repro: in `walks::random_history` (core/node/tests/it/walks.rs, step 6) drop the `!forge` condition on the cover drops, then `OSIS_WALKS_FORGED_START=961728 OSIS_WALKS_FORGED_SEEDS=1 cargo test --workspace --test it walks::open_equals_rebuild_random_histories_forged -- --exact` ("peer 1 differs"); also 961118 ("a forged copy shows"). Fails with main's engine too.

Mechanism (961728, traced): peer 0 writes tag t12 (delta X, dot D), snapshots (S, honest) and drops X under S before syncing; peers 1 and 2 get X's header only (part missing, never received). Peer 2 forges F: its state with t12 replaced by `forged37` under D. At peers 1 and 2, D's delta was never received, so both valid snapshots' copies count (spec/permissions.md §5.2) and the result shows `forged37`, not t12; at peer 0, X was received (dropped), copies under D count for nothing except S's (`Meta::covered_by`): t12. F never enters any `covered_by` (`covered` compares copies, `CopyIndex::outside`). 961118: the forger forges its own dropped delta's dot; honest nodes agree on the forged value, only the forger differs.

This is the documented residual (notes/permissions.md: a valid writer can carry any write under a dot whose original a node never received) made permanent: the walks' final check assumes every node ends holding every body, which drops break; in a network the same happens to a node joining after the covered delta was deleted at servers.

Options: (a) accept (writers are trusted not to equivocate; a removed forger's snapshots stop counting) and make the forged walks compare only nodes that received the same bodies; (b) for never-received dots, prefer the copy of the snapshot that covered the delta at the dropping node — unknowable to others; (c) among valid snapshots carrying differing copies under one never-received dot, a deterministic rule (e.g. none counts) — still differs from the node that received it.


Owner decision (round 13): a snapshot is trusted for what the content is now, never for who wrote it or when.
- Content: every node follows a valid snapshot's copy of a write (also nodes holding the original), so holders converge; no worse than the snapshot's author writing the value itself; later writes win as usual; two valid snapshots disagreeing need a fixed tie-break.
- History: anything the API exposes about authors or times comes only from verified original commits; content known only through a snapshot has no history (absent, as for data compacted before one joined). No "possibly false" concept in the API.
- Detection: a node holding the original that sees a snapshot misstate it reports it through the normal diagnostics route if that is cheap (apps may show, log or drop it).
- Check whether the same rule settles issues/forged-creation-copies.md (text).
