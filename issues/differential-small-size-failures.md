# Sync differential fails at the gate's size on some seeds
> Summary: `differential::histories_hold_their_closure_plain` at small size fails 3 of 60 seeds on main (c8822df81), with three panics: a node keeps store entries under a sync ID it does not hold (shrunk script, 50 of 50 worlds), a node reads a thing the model holds unread (the seed whose shrink reached the first), a caught-up reader lacks a must-hold body at quiet under duplicated messages (shrunk script, 0 of 50 other worlds). None is one of issues/differential-full-size-classes.md's classes as written.
> Priority: normal
> Tags: sync, engine, tests

**Seen**: the first run at a random offset (the gate's random `OSIS_SYNC_START`): seed 959507911307 of 6 failed, then seed 318840271993 of 48 at another offset, then seed 914688535823 of 6 at a merge gate (mizzen-watch-1). All three fail on main's binary (`tools/bin-at`). Replay: `OSIS_SYNC_START=<seed> OSIS_SYNC_SEEDS=1 cargo test -p osis-sync --test it -- --ignored --exact differential::histories_hold_their_closure_plain`; scripts replay in a scratch test (notes/sync-test-harness.md, Replaying a script).

## Entries kept under a sync ID not held
- Shrunk script (10 steps), fails on 50 of 50 worlds: `New(2), New(0), Run, Strong(1, None, 1), Give(2, 1, Holder::Node(1), Reads), Run, NewIn(0, 0), Unstrong(1, None, 1), Give(0, 2, Holder::Thing(1), Syncs), Strong(1, None, 2)`. Panic: `node 1 keeps 20 store entries under thing 2's sync ID, which it does not hold`.
- Node 1 was granted read on thing 1 and held it, then dropped it; thing 1 is then granted sync on thing 2, which node 1 holds from its root. The model says node 1 does not hold thing 2 (its only role on it runs through thing 1, which it no longer holds); the node syncs and stores thing 2's entries. Possibly the same root as the unaccepted-grant class (a role counted through a thing the node does not take up), unconfirmed.

## A read the model holds unread
- Seed 959507911307 (30 steps) failed first with `node 1 reads thing 2: Some(Str("v4")), the model does not`: node 1's `why_role` gives Read by a chain path account -Write-> X -Read-> thing 2, the model says held unread. Its shrink took the failure above instead, so this one has no script of its own yet.

## A must-hold body missing under duplicates
- Shrunk script (6 steps; shrink budget spent): `New(1), Give(1, 0, Holder::Node(0), Reads), Run, Strong(0, None, 0), Lossy(Loss { drop: 0, dup: 25, delay: 0, delay_ms: 312 }), Run`. Panic: `must-hold bodies a caught-up reader lacks at quiet (holder, reader, S, commit)`. Fails on seed 318840271993's world only: 0 of 50 other worlds, so the duplicate timing matters; widen the replay or shrink with a larger budget before reading it.

