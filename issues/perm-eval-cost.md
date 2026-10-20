# Evaluating the membership timeline costs restarts × passes × graph searches
> Summary: Opening a node, or receiving a membership write out of order, re-evaluates the whole membership timeline of the affected group: seconds at 10^4 membership changes (4.3 s on an idle box; 34-54 s measured on a box loaded 5x). A write after every held one continues the cached walk (tens of ms); point queries start from checkpoints; `delta_valid` is memoized.
> Tags: permissions, node, security, performance

Repro: `cargo test --release -p osis-perm -- --ignored bench_10k_edges --nocapture`.

Cost shape (crates/osis-perm/src/walk.rs, timeline.rs, content.rs):
- A walk visits every edge write of the component in order. Per commit it computes the author's roles (a widest-path search, O(E)); per explicit write that may lower an edge, for each node reaching the member, two searches (with and without the restored edge) and a standing per thing reachable from the target, plus the demoter's chain writes (a scan of the current setters).
- Every drop restarts the walk, and every epoch-start change rebuilds D and restarts it. Worst case: passes ≈ drops + snapshots² (bounded, with a cap), each O(writes × nodes reached × E).
- Queries at a point (`role`, `roster`, `delta_valid`, `edges_at`) replay the change history up to it (O(history)); `delta_valid` also scans the history once for the first tenure (re-grant).
- Measured (`tests/bench.rs`, release): 1k edge writes about 30 ms, 10k about 1 s; one arrival re-evaluates its whole component (`Timelines` caches only unchanged components).

Done (wave 6 performance round): `Timeline::extend` continues the walk for commits after every held write (one more write at 10^4: 4.3 s -> 30 ms), `edges_at` from a checkpoint every 256 changes, `delta_valid`/`first_held` memoized per timeline (180 µs -> 0.6 µs warm). Remaining: the from-scratch walk itself (per explicit write O(nodes reached × E) searches; `chain_writes` scans every setter; `audit_fall` clones the edge set), open (`apply::load` evaluates every component from scratch), an out-of-order arrival or a write that grows D (full re-evaluation), the node's `rejudge_all` asking `delta_valid` for every held delta on every held-set change (memo is lost for the component that changed).

Original recommendation: the node keeps one `Timelines` per store and answers content validity from cached per-(node, thing) results; perm adds reuse of the previous walk when a commit lands after every held write and adds no drop or epoch change (the common case), and snapshots of the edge state at intervals for point queries. Not needed for correctness.
- Hardening scale check (`tests/bench.rs`, release, loaded 4-core box): 10^3 edge writes 34 ms, 10^4 4.4–5.0 s from scratch, one more write re-evaluates the component in 4.3 s, a role query 0.3 ms (slower than the 1 s above; the machine was shared). Owner chain (`bench_deep_owner_chain`, 100 edge writes at the leaf): depth 10 / 100 / 1000 evaluates in 0.3 ms / 1.7 ms / 34 ms, a role query at the leaf 1 µs / 9 µs / 189 µs: linear in depth per query, so an uncapped chain multiplies every standing check.

Second round (in progress, branch of the ledger-late-audit fix): `View::patched` overlays one edge instead of cloning the edge set in `audit_fall`, `demotion_scope` and the node's `self_removal`; `chain_writes` looks up setters of the admin edges on paths to the target instead of scanning every setter. Bench on a box at load ~20 (4 cores, numbers 5-10x an idle box): 10^4 from scratch 53.6 s -> 33.6 s, 10^3 314 ms -> 257 ms, incremental first evaluation 10^4 48.7 s -> 38.0 s, `delta_valid` cold 5.6 ms -> 0.35 ms. The org bench had 1 pass and 0 drops, so the cost is the per-write searches, not restarts. Not profiled yet (`perf record` could not open events here).

Remaining, in order:
1. Profile `bench_10k_edges` (perf needs event access, or use valgrind --tool=callgrind on the 10^3 case) and cut the per-write searches: `roles_from` per commit author and twice per reached node in `audit_fall`; `reach_backward`/`reach_forward` per explicit write.
2. Restarts and out-of-order arrivals: an undo log of the pass state (edges, prior, dead, prior_node, setter, applied, by_author_target, history, demotions, choose) with marks per item, so a restart rolls back to the earliest new drop and an arrival at p rolls back to p (D restored to the pass that first reached p; exact while the epoch configuration is unchanged; fall back to from scratch otherwise).
3. Open: persist each component's walk state as a rebuildable store cache unit keyed by its exact inputs (notes/local-store.md), or rely on 1-2 if the from-scratch walk becomes cheap enough.
4. Node `rejudge_all`: keep per-(node, thing) results and re-judge only deltas of components whose timeline changed (`Timelines::update` could return the changed components).
Measure with `bench_10k_edges` before/after on a quiet box and record in notes/permissions.md.
