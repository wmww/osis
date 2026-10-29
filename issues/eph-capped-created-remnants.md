# Capped server full of `/created`-only commits
> Summary: Sim `ephemeral_capped` seed 2400045 (fails on main too): at quiescence node 1's own `/e/notes` commit (8 KB) stays refused at the capped server (15 KB of 16 KB used), which holds six of node 1's `/created`-only commits (4.3 KB each) and two `/created` + `/e/typing` ones; no cover absorbs them, so node 0 never reads node 1's notes.
> Tags: engine, node, sim

- Repro: `osis_sim::replay("ephemeral_capped", 2400045)` (ignored test `repro_ephemeral_capped_seed_2400045` in core/test/sim/tests/it/net.rs); the window is node 1's `0_4F2n...`, which has `typing` (expiring) writes.
- Guess, unverified: the `/created`-only ones are typing commits whose expiring parts went, or record-only commits (`take_ephemeral_if`); node 1's forced compaction finds no aspect with two parts that it may compact (typing expires, the rest have one part), so nothing is due. Related: issues/eph-cover-partial-absorb.md (`/created` of things no picked aspect touches). A commit left with only `/created` parts, or one whose expiry passed, could perhaps be dropped and deleted by its author.
