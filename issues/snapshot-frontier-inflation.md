# A snapshot's frontier can claim writes nobody made, so a removed writer keeps writing
> Summary: a compaction snapshot's `Frontiers` (`[1, ctr]` per node) and `Absorbed` (commit ID, author) are taken as received with no bound; a writer X snapshots with `Frontiers {X: 2^60}` (or `Absorbed` listing commits it signed in advance), an admin's later demotion of X copies that into its frontier, and every write X makes afterwards at those counters (any `ts`) is covered and valid for good.
> Tags: security, engine, perm

Severity: high (revocation of a writer does nothing on the aspects it snapshotted).

Scenario: X has write on T. X writes a content snapshot S of `(T, /body)` whose `Frontiers` holds `X: 2^60` (nothing checks it: `decode_snapshot`, core/crdt/src/codec.rs:680-690, only rejects 0 or repeats). Admin A applies S (valid: X is a writer). `receipt::received` (core/engine/src/apply/receipt.rs:140-166) adds `[1, 2^60]` of X as received; `Engine::frontier` (receipt.rs:218) puts `X: 2^60` for `(T, /body)` in A's removal of X, and S's ID too (so S stays valid). After the removal X writes node-form commits on `/body` at fresh counters below 2^60, any `ts`: `Timeline::delta_valid` (core/perm/src/content.rs:69-75) finds the newest demotion and its frontier covers the dot, so they are valid everywhere, forever. Same with `Absorbed`: X signs future commit-form commits first and lists their IDs (author X) in S; A's frontier lists them (`r.commits`, receipt.rs:224). A third writer can do the same for X (collusion).

Side effect: `waits_for_deltas` (core/engine/src/apply/mod.rs:110-125) treats X's future node-form deltas as held, so commits apply without them.

Spec: spec/permissions.md §5.1 "a frontier MUST NOT cover what A had not received as of T"; §5.2 and spec/crdt.md §8 count a valid snapshot's frontiers as received, which makes the claim the receipt.

Fix direction (spec change): never let a snapshot's claim grow a demotion frontier past what exists. E.g. count a snapshot frontier for node N only up to the highest counter of N the receiver holds a header for on that aspect or that the snapshot actually carries; count `Absorbed` IDs only for commits whose header is held. Or, in the coverage rule, a node-form write is covered only if its counters are also at or below the demoter's directly received maximum. Needs a design pass (honest compaction drops bodies; the cap must not void honest dead writes).
