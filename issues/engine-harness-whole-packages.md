# Engine test harness: whole-commit deliveries and broadcast certificates
> Summary: `LocalPeer::packages` (whole commits) still has 13 direct call sites and `common::packages` (engine tests/it) about 103 more; `Engine::package` hand deliveries are whole too; certificates go to every node. Each can hide a carried-set bug: content outside the closure waits forever under a `LocalPeer` carrier, and a certificate no real route brings can make a test pass.
> Priority: low
> Tags: engine, tests

## Sites
`grep -rn '\.packages(\|[^_a-z]packages(&mut lp' core/engine`: rotation/tests.rs `arrival_order_holds_alike` (N and O handed every commit by index-permuted orders: give each receiver its own list, mapped by commit ID), tests/it/shred.rs 6 (record and setup lists handed to fresh nodes), order.rs 2 and apply_order.rs 1 (lists for fresh nodes in order tests), memory.rs 1, and `common::packages` in validity.rs 46, waits.rs 19, sessions.rs 13, parts.rs 12, receive.rs 11, review.rs 2. Each moves to `packages_for(from, to)` (receiver in the net, sync set as it stands), `packages_to(from, to)` (as it stands after a sync: a grant in the list moves it), `packages_to_peer(from, &mut peer)` (a node apart), `packages_of(from, t)`, or `commit_ids(from)` where only IDs are read; or, where whole delivery is what it tests (a hostile sender), it says so at the site; then `LocalPeer::packages` and `common::packages` go.

## Oracles
- Certificates (`Engine::certificate_parts`) go to every node in `packages_under`: deliver instead what `Engine::certificates(t)` gives for the things whose sync IDs the receiver syncs, plus the named routes (contact card, ticket fire, holder's sync ID), so a missing certificate route fails a test.
