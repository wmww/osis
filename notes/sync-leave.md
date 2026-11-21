# Sync: leave
> Summary: osis-sync's `leave` module (core/sync/src/leave.rs) and the engine's `released`: the one owner of "the sync IDs this node syncs" (the sync set plus each leaving sync ID while it waits), the one wait rule for a sync ID leaving and a thing released (the pass in flight with connected sources), its costs and state.

Spec: spec/sync-set.md §3. Overview: notes/sync.md. What leaves is the node closure's (notes/node-closure.md).

**Principle:** a thing goes when its last reference goes, after the pass in flight with the connected sources; nothing waits for an absent peer, the node's own writes not held elsewhere included.

## What this node syncs
One value: the sync set, and each sync ID that left it while it waits to stop. `leave` alone follows the engine's sync set (`Engine::sync_held_added`, then `sync_held` per key) and writes the value into the store (`Store::set_holdings`, stamped per S, fed by `Store::syncs_feed`). Every other module follows the store's value, never the engine's sync set: store, opens and dials by their own `set::SyncsFollow`, unread by its own, status by `Store::syncs` whole, read, streams and inbox by `Store::synced`/`holding`. So a waiting S stays open, served, logged into and judged as before, with no per-module case. `leave` settles first in each round, so no module sees S drop and come back.

The engine answers for a leaving S by its things' held read secrets, not the sync set (`Engine::opening_things`): `read_credentials`, `claim_key`, `open_entry` and `dial_peers` go by it, `sync_bodies` by `thing_sync`.

## The wait
One wait, for a sync ID leaving the sync set and a thing leaving the node closure alike (spec/sync-set.md §3): a complete pass begun after it left (status runs one, `Leave::passes_wanted`, by pass place; leave reads `Status::passed_since`), or none while S has no source (`Status::sourced`).
- A role commit uncounted for want of its lists (a revocation taken before them) is no reason to wait longer: waiting for a source to bring the lists would stall on an absent peer for good. S given back later is fetched again.

## A sync ID
- Each sync ID out of the sync set that this node syncs or holds rows of is one `Effects` key (`leave::judge`). The first settle wants every stored one (a start, or a restart of the modules), later ones each S the sync set loses.
- S has left when it has an entry (as synced, else as this node's keys hold it, `Engine::sync_holder`) and this node has joined an account (`Engine::sync_rooted`). Its entry and pass place are noted (`leaving`); it stays synced while it waits.
- After the pass, this node's keys must still hold S as when it left (`sync_holder` equal); else it stops at once (secrets lost, a removal: shredded, nothing released).
- Then it stops: a read S's thing is released (below), then `Store::shred`, then not synced. Before each shred the engine drops what only S's entries own of the blobs no other sync ID's entry or tombstone names (`Store::alone_under`, `Engine::shredding`): its notes (`bp/`) of S's per-sync-ID copies sealed for S's thing alone, whether the commit stays held or not (a certificate copy of the account's chain under a released thing's sync ID), the held commit's openings under things whose record is gone (`ou/`), and blobs of commits not held. A shared blob of a held commit stays: a peer still listing it under another sync ID is how a commit dropped as invalid is found again. Engine first, so a crash between does both again.

## A thing
`Engine::left_closure` lists each thing that left with the sync units that held it then. Leave notes the pass place and those units' sync IDs (`releasing`, stamped: status runs their passes), and releases it once each has passed or has no source; one that left the local part (no sync unit) at once. A thing back in the node closure before then leaves `left_closure` and is kept as it was.

## Release (engine: core/engine/src/retention/release.rs, retention/forget.rs `Scope::Local`)
- One `Ground::release` per settle for everything that goes: `Engine::released`. It forgets the things given that the node closure does not hold, and each thing whose independent is one of them, by the lost-access machinery (`retention::forget::forget`), fate `Local`: commits left with no part are deleted and fetched again, others keep their other parts. Event cause `Released`. Each released thing leaves `left_closure` in the same transaction.
- This node's own entries of every commit forgotten then or after (`retention::needed` forgets the role-class rest once nothing held needs it) go under every sync ID by the engine's ciphertext door (notes/sync-store.md, Own entries), so no judgement reaches a commit no longer held.
- Cost: incremental, as for lost access (notes/engine-lost-access.md, Forgetting): the commits on what left, no reload.

## State
Per sync ID out of the sync set with rows or an entry, one key; per leaving S its entry and place; per thing released its place and sync IDs. Nothing durable: a restart begins each wait afresh.
- A restart of the modules must not see things leave that did not: the engine keeps its followed links across a reload (`load_fresh`), else the sync IDs of links being redeemed would leave and wait a pass at every reload. A start follows the sync set whole before anything is judged left (`Inbox::start`, then `Engine::forget_unread`, then leave).

## Reasons
- One value every module follows, written by the module that owns leaving: a per-module "also synced while waiting" would be a carve-out in each.
- No wait for a peer to take own unsynced writes: it kept rows for a peer that may never return.

Tests: rules on a fake ground, core/sync/tests/it/leave.rs.
