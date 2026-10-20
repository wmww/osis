# Evaluating the membership timeline costs restarts × passes × graph searches
> Summary: osis-perm re-walks a whole connected component from scratch on every held-set change; each restart re-walks it, each explicit write searches the graph per affected node, and point queries (`delta_valid`, `edges_at`) replay the history; 1–5 s in release at 10^4 edge writes, and every new write pays it again. The node should cache and reuse.
> Tags: permissions, node, security, performance

Repro: `cargo test --release -p osis-perm -- --ignored bench_10k_edges --nocapture`.

Cost shape (crates/osis-perm/src/walk.rs, timeline.rs, content.rs):
- A walk visits every edge write of the component in order. Per commit it computes the author's roles (a widest-path search, O(E)); per explicit write that may lower an edge, for each node reaching the member, two searches (with and without the restored edge) and a standing per thing reachable from the target, plus the demoter's chain writes (a scan of the current setters).
- Every drop restarts the walk, and every epoch-start change rebuilds D and restarts it. Worst case: passes ≈ drops + snapshots² (bounded, with a cap), each O(writes × nodes reached × E).
- Queries at a point (`role`, `roster`, `delta_valid`, `edges_at`) replay the change history up to it (O(history)); `delta_valid` also scans the history once for the first tenure (re-grant).
- Measured (`tests/bench.rs`, release): 1k edge writes about 30 ms, 10k about 1 s; one arrival re-evaluates its whole component (`Timelines` caches only unchanged components).

Recommendation: the node keeps one `Timelines` per store and answers content validity from cached per-(node, thing) results; perm adds reuse of the previous walk when a commit lands after every held write and adds no drop or epoch change (the common case), and snapshots of the edge state at intervals for point queries. Not needed for correctness.
- With valid keys (security review): `Owners::chain` has no depth cap (the node caps epochs at 64 and departures at 8), so a writer nesting things owned by things makes every standing and chain query O(depth); with this issue's restarts that is a cost a member can drive. Cap or cache chains when caching lands.
- Hardening scale check (`tests/bench.rs`, release, loaded 4-core box): 10^3 edge writes 34 ms, 10^4 4.4–5.0 s from scratch, one more write re-evaluates the component in 4.3 s, a role query 0.3 ms (slower than the 1 s above; the machine was shared). Owner chain (`bench_deep_owner_chain`, 100 edge writes at the leaf): depth 10 / 100 / 1000 evaluates in 0.3 ms / 1.7 ms / 34 ms, a role query at the leaf 1 µs / 9 µs / 189 µs: linear in depth per query, so an uncapped chain multiplies every standing check.
