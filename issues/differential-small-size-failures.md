# Sync differential fails at the gate's size on some seeds
> Summary: `differential::histories_hold_their_closure_plain` at small size fails on fresh offsets: a re-granted writer lacks role commits' `secrets.0` parts (seed 6170, not shrunk), and a storm past the delivery cap (seed 594660024526, not shrunk); must-hold bodies with no entry at quiet (seed 61254442551, not shrunk).
> Priority: normal
> Tags: sync, engine, tests

**Seen**: seeds 6170 (offset 6168) and 594660024526 fail on main. Replay: `OSIS_SYNC_START=<seed> OSIS_SYNC_SEEDS=1 cargo test -p osis-sync --test it -- --ignored --exact differential::histories_hold_their_closure_plain`; scripts replay in a scratch test (notes/sync-test-harness.md, Replaying a script).

## A storm past the delivery cap
- Seed 594660024526 (fails on main 038a90b45 as on a cleanup branch): `storm: past the cap of 30000 deliveries`, with no partition and nothing still flowing. Not shrunk: shrink first, then find which messages keep answering each other (the settle round counters: notes/test-harnesses.md, Measuring).

## A re-granted writer lacks role commits' `secrets.0` parts (seed 6170)
- `must-hold bodies a caught-up reader lacks at quiet`: Bob (node 1) grants Alice write on T (his), lowers her to sync, revokes her and gives her write again; at quiet Alice's nodes 0 and 2 hold seven of T's role commits (keyset rotations: `keys.0`, `sync.0`, `secrets.0`) with the `secrets.0` part missing, verdict May at the reader, Must at Bob's node. Not the outside-the-closure case (role-class parts, no `Outside` wait). Not shrunk; the 30-step history passes through `Lower`, `Revoke` and `Give` again.

## Must-hold bodies with no entry at quiet (seed 61254442551)
- `must-hold bodies with no entry at quiet (node, S, commit)`: node 0 holds two commits must-hold under one S with no entry of them in its store at quiet. Fails on main c67cbeeb8; not shrunk. First shrink it with `OSIS_SHRINK_MATCH` set to this message (unset, shrinking drifts to another class).
