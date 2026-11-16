# Sync: leave
> Summary: osis-sync's `leave` module (core/sync/src/leave.rs) and the engine's `released`: the one owner of "the sync IDs this node syncs" (the sync set plus each leaving sync ID while it waits), the one wait rule for a sync ID leaving and a thing released (the pass in flight with connected sources), its costs and state.

Spec: spec/sync-set.md §3. Overview: notes/sync.md. What leaves is the node closure's (notes/node-closure.md).

## What this node syncs
One value: the sync set, and each sync ID that left it while it waits to stop. `leave` alone follows the engine's sync set (per sync ID: `Engine::sync_held_added`, then `sync_held` per key) and writes the value into the store (`Store::set_holdings`, stamped per S, fed by `Store::syncs_feed`). Every other module follows the store's value, never the engine's sync set: store, opens and dials by their own `set::SyncsFollow`, unread by its own, status by `Store::syncs` whole, read, streams and inbox by `Store::synced`/`holding`. So a waiting S stays open, served, logged into and judged exactly as before, with no per-module case. `leave` settles first in each round, so no module ever sees S drop and come back.

The engine side answers for a leaving S by its things' held read secrets, not the sync set (`Engine::opening_things`): `read_credentials`, `claim_key`, `open_entry` and `dial_peers` go by it, `sync_bodies` by `thing_sync`.

## The rule
- One wait, for a sync ID leaving the sync set and for a thing leaving the node closure alike: the pass in flight with the connected sources (spec/sync-set.md §3). A complete pass begun after it left (status runs one, `Leave::passes_wanted`, by pass place; leave reads `Status::passed_since`), or none at all while S has no source (`Status::sourced`). No absent peer is waited for, and the node's own writes not held elsewhere go with what is released.
- A sync ID: the sync IDs out of the sync set that this node syncs or holds rows of, each an `Effects` key judged (`leave::judge`). The first settle wants every stored one (a start, or a restart of the modules), later ones each S the sync set loses. S has left when it has an entry (as synced, else as this node's keys hold it, `Engine::sync_holder`) and this node has joined an account (`Engine::sync_rooted`). Its entry and the pass place it left at are noted (`leaving`), and it stays synced while it waits.
  - After the pass, this node's keys must still hold S as when it left (`sync_holder` equal); else it stops (secrets lost, a removal: shredded, nothing released).
  - Lacking a list is waiting: when the keys no longer hold S after that pass and a role commit on S's thing is held uncounted (`Engine::uncounted_role_on`), leave waits once more (`Left::sourced`) for a pass that ends only once a source caught up (`Status` `pass_sourced`), then judges again; only while S's thing is in the node closure (`in_sync_things`). Why: an outsider cannot tell a list not yet arrived from one never written; with the account's records proved at a revoked epoch no peer is to be waited for, so a plain pass would end in the step the rotation arrives.
  - Then it stops: a read S's thing is released (`Engine::released`, which keeps what is still in the node closure), then each S `Store::shred`, then not synced.
- A thing: `Engine::left_closure` (each thing that left with the sync units that held it then). Leave notes the pass place and those units' sync IDs (`releasing`, stamped: status runs their passes), and releases it once each has passed or has no source; one that left the local part (no sync unit) at once. A thing back in the node closure before then leaves `left_closure` and is kept as it was.
- Release is one `Ground::release` per settle for everything that goes: `Engine::released`, then this node's own entries of the commits that went whole are unlogged under every sync ID naming their blobs (`Store::naming`), so no judgement reaches a commit no longer held. A crash between release and shred leaves the rows, so the start redoes both.
- State: per sync ID out of the sync set with rows or an entry, one key; per leaving S its entry and place; per thing released its place and sync IDs. Nothing durable: a restart begins each wait afresh.
- A restart of the modules must not see things leave that did not: the engine keeps its followed links across a reload (`load_fresh`), else the sync IDs of links being redeemed would leave and wait a pass at every reload. A start follows the sync set whole before anything is judged left (`Inbox::start`, then `Engine::forget_unread`, then leave).

## released (engine, core/engine/src/retention/release.rs, retention/forget.rs `Scope::Local`)
- Forgets the things given that the node closure does not hold, and each thing whose secret actor is one of them, but those the node closure holds; same machinery as lost access (`retention::forget::forget`), fate `Local`: commits left with no part are deleted and fetched again, others keep their other parts. Event cause `Released`. Each released thing leaves `left_closure` in the same transaction.
- Cost: incremental, as for lost access (notes/engine-lost-access.md, Forgetting): the commits on what left, no reload; once per settle.

## Reasons
- One value every module follows, written by the module that owns leaving: a per-module "also synced while waiting" would be a carve-out in each.
- A thing goes when its last reference goes (spec/sync-set.md §3): nothing waits for an absent peer, own unsynced writes included. Waiting for a peer to take them kept rows for a peer that may never return.

## Tests
Rules on a fake ground: core/sync/tests/it/leave.rs.
