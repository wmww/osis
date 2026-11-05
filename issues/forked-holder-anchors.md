# A holder actor forked by two knowing rotators is left out where both forks are anchors
> Summary: Rule 1 (Seal) needs a keyset of M that is or descends from every anchor; rule 3 (merge) moves M only off a fork that misses a departure. Two admins of M rotating it concurrently, both knowing every departure, leave two current keysets neither lists; an actor A holding boxes to M at both has no keyset to seal M at, so M stays left out of A's new epochs until M rotates for another reason. Seed 1838 of the cycle harness (1 of 3000 at full size).
> Tags: keys, engine, tests

Repro: `OSIS_CYCLE_START=1838 OSIS_CYCLE_SEEDS=1 cargo test -p osis-engine --lib rotation::tests_members::cycle_removals_leak_nothing_random_large -- --ignored --exact` ("every holder with key access re-sealed").

Shape (4 actors, two owners, hidden grants, D removed from G2 by itself): G2 has admins P0 (owner) and P2 (through G3, keyed). After the removal both rotate G2 in the cascade before syncing: keysets 2.27 and 2.87, each listing 1.eb, each knowing the departure, so no merge is due. G1 (admin P2) was rotated twice meanwhile, its current read epochs boxing G2 at 2.27 and at 2.87. G1's next rotation of write and admin finds anchors {2.27, 2.87} for G2; no held keyset descends from both, so Seal gives none and G2 is left out of G1's write and admin for good (the re-seal trigger finds G2 missing every round; nothing makes G2 rotate again).

Liveness only: nothing leaks (a fork of knowing keysets is safe to seal to). Not in the model: Depth0.tla's forks are ignorant ones (Eager before the removal), merged by rule 3.

Candidates, unmodelled:
- Merge every fork: a node that may rotate M rotates while M has more than one current keyset of a role, departure or not. One more rotation per concurrent race; two admins merging concurrently fork again (bounded by how often admins race, like the taint churn of rule 4b).
- Seal at the newest keyset descending from the anchors that are not themselves forks of a knowing keyset: needs a way to tell a knowing fork from an ignorant one at depth 0, which is what anchoring avoids judging.
