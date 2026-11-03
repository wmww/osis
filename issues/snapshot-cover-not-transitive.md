# Coverage is not transitive across a session gap: a body is uploaded and deleted each resync
> Summary: a fresh device's snapshot F covers the older snapshots but not body c they covered (F lists c's session at 0), so once they drop, the nodes holding c judge it must-hold and re-upload it, while the right holder that already dropped c's part deletes it each pass: 3 fresh bodies per resync for good. `snapshot_rights` seeds 26, 27, 36, 55, 85, 91; since 1ec11945 (session form), bisected.
> Tags: engine, node, retention, sim

Repro: `cargo run --bin sim-sweep -- --only snapshot_rights --seeds 1 --from 26`: "not quiescent", at the `quiet` after the fresh device compacts. All six are bound 0 with `fresh_compacted`.

Seed 26, c is the item's creation (`s:reg.0`, `created.0`, `group.0`), F is 5652368 by the fresh device:
- `covered(F, Z)` is true for every older snapshot Z, so each Z's part is dropped at every node. `covered(Z, c)` is now `None` (Z's part is gone), `covered(F, c)` is `Some(false)`.
- Node a (right holder, c's author) had dropped c's `s:reg.0` under Z, so any entry with that part is `MustNot(Why::Dropped)`: it deletes [(0,0),(2,0)] and keeps [(2,0)].
- b, w and the fresh device still hold that part, live by `part_live`, uncovered: must-hold [(0,0),(2,0)], and `delete_stands` does not stand because the live part is carried by nothing. Each uploads a fresh encryption; a deletes it.

Allowing a smaller entry to carry the live part does not help: the part in question is the one nobody else carries (tried). Same root as issues/snapshot-gap-never-covers.md: a writer that knows a session only through a snapshot lists it at 0. Candidates: F's frontier continues from held valid snapshots' (that issue's candidate, weighed against rule 3); or `covered` looks through a snapshot's dropped ones, whose headers stay.
