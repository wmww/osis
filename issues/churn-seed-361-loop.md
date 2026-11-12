# Churn seed 501814946361: delete/re-place storm until a role relay
> Summary: `random_churn_converges_large` seed 501814946361 fails "no quiescence after 2000 rounds": a writer that has not learned its own demotion deletes bodies its post-demotion snapshot covers, while co-writers that know the demotion re-place them under fresh encryptions, every round trip until they relay the role commits there (up to `SETTLE_MS`). The Net's settle stands the clock still, so the storm never ends there. Fix belongs to one-peer-3h2's pass rewrite.
> Priority: normal
> Tags: ephemeral, sync, tests, one-peer-3h2

Replay: `OSIS_EPH_START=501814946361 OSIS_EPH_SEEDS=1 cargo test -p osis-node --test it -- --ignored --exact ephemeral::random_churn_converges_large` (about 35 s).

## Cause
Writers 1, 2 and 3 share two hosts. Node 3 can reach only host 0, and admin node 0 is cut from host 0. So the demotion of 3 (and the later promotion of 1) reaches only host 1 and nodes 1 and 2. Node 3 still judges itself a writer. It writes snapshot `0c14ec` of `win:cursor+.0` and forgets its earlier snapshot `be92ba` and node 0's `6df6f7` as `Covered { by: 0c14ec }`. Once `0c14ec` is present at host 0, its pass deletes their entries there (`judge_forgotten`, `Why::Dropped`).

Nodes 1 and 2 know about the demotion. For them `0c14ec` is invalid: its part is dropped while invalid, so `be92ba` and `6df6f7` are uncovered and must-hold. Each deletion at host 0 makes them place a fresh encryption and upload it, and node 3 deletes that again. They hold the role commits that would settle node 3's view, but those wait for `relay_at` (at most `SETTLE_MS` after receipt) before going to host 0. So the storm lasts until the relay: one upload and one delete per body per round trip. Checked: advancing the clock 31 s when the loop is detected ends it, and the seed passes.

This is the mirror of the eph-churn-loop rule (`At::roles_behind`). That rule makes the *deleter* that holds the role commit wait for its relay. Here the deleter lacks the role commit, and the uploaders that hold it re-place what was deleted.

## Fix direction (for one-peer-3h2, whose `bodies.rs` keeps `relay_at` and the fresh re-placement)
Rare path, so brute force is fine. When a body this node must hold is deleted at a host while a role commit it must hold there still waits for its relay, the deletion shows that a holder there judges by an older role view. Relay those role commits at once (end the wait for that host). Another option is to hold the re-placement until the relay, as deletes already wait. The first ends the storm in one round trip. The second waits up to `SETTLE_MS` with the label's body missing at that host.

Regression test (default, counts messages): three writers on two hosts. The writer cut from the admin's host writes a snapshot after a demotion it never sees. Count the uploads and deletes of the covered commits' entries at the shared host within one settle: at most one re-placement per entry.
