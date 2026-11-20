# Engine test harness: whole hand deliveries and broadcast certificates
> Summary: Engine tests still hand commits over whole through `Engine::package` (about 270 sites) and give certificates to every node; each can hide a carried-set bug: content outside the closure waits forever under a `LocalPeer` carrier, and a certificate no real route brings can make a test pass.
> Priority: low
> Tags: engine, tests

## Sites
`grep -rn 'engine\.package(' core/engine --include=*.rs | grep -v src/local_peer.rs`: a commit packaged whole by its holder and handed to another node, whatever that node's sync IDs carry. Most are a commit just made, handed to a peer syncing its thing (whole is what its sync IDs carry); the rest need reading one by one. Each moves to `common::package_for(lp, from, to, id)` (its sync set as it stands), `packages_to` (after a sync), `common::packages_for_peer` (an observer apart, its sync set as it stands), `common::packages_reading` (a fresh reader given its grant alone), `LocalPeer::packages_to_peer` (a node apart whose sync set the packages move), or stays where whole delivery is the point: a forged or hostile commit (`commit_hostile`, `commit_forged`, hand-built bytes), pairing (a node's own account), a node's own commits. The heaviest files: tests/it shred.rs 27, waits.rs 23, order.rs 15, validity.rs 14; lib apply/tests_addenda.rs 19, rotation/tests_signing.rs 16, apply/tests_validity.rs 16, rotation/tests_custody.rs 13, retention/mod.rs 13.

## Oracles
- Certificates (`Engine::certificate_parts`) go to every node in `packages_under`: deliver instead what `Engine::certificates(t)` gives for the things whose sync IDs the receiver syncs, plus the named routes (contact card, ticket fire, holder's sync ID), so a missing certificate route fails a test.
