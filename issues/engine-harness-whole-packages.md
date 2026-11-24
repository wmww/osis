# Engine test harness: whole hand deliveries and broadcast certificates
> Summary: Engine tests hand commits over whole through `Engine::package` (about 270 sites) and give certificates to every node; each can hide a carried-set bug: content outside the closure waits forever under a `LocalPeer` carrier, and a certificate no real route brings can make a test pass.
> Priority: normal
> Tags: engine, tests

## Sites
`grep -rn 'engine\.package(' core/engine --include=*.rs | grep -v src/local_peer.rs`. Each moves to `common::package_for(lp, from, to, id)` (its sync set as it stands), `packages_to` (after a sync), `common::packages_for_peer` (an observer apart), `common::packages_reading` (a fresh reader given its grant alone), `LocalPeer::packages_to_peer` (a node apart whose sync set the packages move), or stays where whole delivery is the point (a forged or hostile commit, hand-built bytes, a node's own commits). Heaviest files: tests/it shred.rs, waits.rs, order.rs, validity.rs; lib apply/tests_addenda.rs, apply/tests_validity.rs, retention/mod.rs.

## Certificates
`Engine::certificate_parts` go to every node in `packages_under` (and `Engine::sent_parts` under `LocalPeer` sends every certificate part to every node). This hid a real bug once (a write link's redeemer never got the delete base's later step; only osis-sync and `osis` tests saw it). Deliver instead what `Engine::certificates(t)` gives for the things whose sync IDs the receiver syncs, plus the named routes (link, grant fire, the holder's sync ID), so a missing route fails a test.
