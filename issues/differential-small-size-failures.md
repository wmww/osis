# Sync differential fails at the gate's size on some seeds
> Summary: `differential::histories_hold_their_closure_plain` at small size fails on fresh offsets: a caught-up reader lacks part of a must-hold minting body after a connection reset (one world in 50, studied, parked), and a node lacks a read the model has (seed 3994064562, not shrunk).
> Priority: normal
> Tags: sync, engine, tests

**Seen**: seed 318840271993 (gate offset) fails on main. Replay: `OSIS_SYNC_START=<seed> OSIS_SYNC_SEEDS=1 cargo test -p osis-sync --test it -- --ignored --exact differential::histories_hold_their_closure_plain`; scripts replay in a scratch test (notes/sync-test-harness.md, Replaying a script).

## A must-hold body a caught-up reader lacks (one world in 50)
- Shrunk script (6 steps): `New(1), Give(1, 0, Holder::Node(0), Reads), Run, Strong(0, None, 0), Lossy(Loss { drop: 0, dup: 25, delay: 0, delay_ms: 312 }), Run`; fails on seed 318840271993's world only (0 of 50 others). Panic: `must-hold bodies a caught-up reader lacks at quiet`: Bob mints T (dependent on his D), grants Alice read (T keyed, its own sync ID S); Alice's node accepts, her sibling node 2 lacks part of T's minting commit.
- What the trace shows (node 2): at the grant Bob's node logs the minting's blob verbatim under S (the blob it holds under D's sync ID). Node 2's fetch of S's head entries from Bob's node is lost with a duplicate's connection reset; it fetches the minting blob from Alice's node 0 first and applies the commit, its u:v.0 part (written while T's secrets derived from D's) unopened. The role commits arrive on Bob's next connection, after which every verdict moves to Must, and node 2 holds the blob and opens its wrap, but the commit's u:v.0 part stays missing at quiet: nothing hands node 2 a section of it under an epoch of T. On the other worlds node 2 reads T's first value, so some other path covers the part there (not yet traced).
- Open: whether a holder may pass the D-era minting blob on under S verbatim (spec/crypto.md §5 Passing on: the wrap gates the header and the floors clause binds parts "on a thing whose read secrets are those of the wrap's sync ID's thing") or must log a fresh encryption of S's body, and which path gives the part on the passing worlds. Trace a passing world of the script next (`OSIS_SYNC_TRACE=all:<commit>,<blob>`).

## A node lacks a read the model has
- Seed 3994064562 (gate offset 3994064557; fails on main's binary ec950c4ef): `node 1 reads thing 1: None, the model reads it`. The reverse of the earlier "reads what the model holds unread" facet; not shrunk.
