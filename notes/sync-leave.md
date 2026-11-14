# Sync: leave
> Summary: osis-sync's `leave` module (core/sync/src/leave.rs) and the engine's `forget_local`: the one owner of "the sync IDs this node syncs" (the sync set plus each leaving sync ID while it waits), the wait rule for read and kept-unread leaving, unsyncing's forget, its costs and state.

Spec: spec/sync-set.md §3. Overview: notes/sync.md.

## What this node syncs
One value: the sync set, and each sync ID that left it while it waits to stop. `leave` alone follows the engine's sync set (`set::SetFollow`, per key) and writes the value into the store (`Store::set_holdings`, stamped per S, fed by `Store::syncs_feed`). Every other module follows the store's value, never the engine's sync set: store, opens and dials by their own `set::SyncsFollow`, unread by its own, status by `Store::syncs` whole, read, streams and inbox by `Store::synced`/`holding`. So a waiting S stays open, served, logged into and judged exactly as before (spec: "stays a member of its shared sets as before"), with no per-module case. `leave` settles first in each round, so no module ever sees S drop and come back.

The engine side reads the thing, not the sync set, where a waiting S needs it: `sync_bodies` goes by `thing_sync` (whatever lists the thing), `read_credentials`/`claim_key` by the owner's keys, `dial_peers` by `sync_holder` (S's thing and how the node's keys hold S, closure ignored). Certificate bodies and the pass wants (`passes_wanted`, `forget_unread` at open) still go by the engine's sync set: a waiting S gets no new certificate copies and no complete-pass want; its own writes are what it waits on, and those are content bodies.

## The rule
- S leaves the sync set (`SetFollow` says gone) while it was synced: it waits, keeping its entry (thing, holding).
- Each waiting S is one `Effects` key, judged on: this node's keys still hold S as when it left (`Engine::sync_holder(s)` equal); else it stops at once (secrets lost, a removal, read lost with sync kept: shredded, nothing forgotten; lost access forgets the content). Read: each own commit with an entry under S (`Engine::own_commits`) held elsewhere by status's durable mark on one of its entries (`Store::elsewhere`). Kept unread: each own entry present at a source (streams' `Sources::present`). Done: read, `Engine::forget_local(thing)` first; then `Store::shred`, then not synced. A crash between forget and shred leaves the rows, so the start redoes both.
- Synced again before it stops: the wait ends, nothing goes.
- At a start (first settle): every sync ID with rows (`Store::held_ids`) not synced whose holder (`sync_holder`) is some: it left while the node was down, it is synced again and waits. One with no holder (another account's inbox this node deposits to) is left alone.
- State: the waiting sync IDs and their `Effects` keys, bounded by the sync IDs the store holds rows of; nothing durable (the store's rows are the truth after a restart, the start's sweep rebuilds it).
- Cost: a sync set change costs what moved (`SetFollow`); a waiting S is judged when its own commits, marks, presence or keys move, O(own writes under S).

## forget_local (engine, core/engine/src/sync/mod.rs, retention/forget.rs `Scope::Local`)
- Forgets `t` and each thing whose secret actor is `t`, but those the synced group's closure holds (a plain thing listed elsewhere still syncs under that group). Same machinery as lost access (`retention::forget::forget`), fate `Local`: everything an erased thing loses but `secrets.0`, so the thing stays read and syncs again when listed; commits left with no part are deleted and fetched again, others keep their other parts (late parts join). Event cause `Unsynced` (`DerivedFrom::Unsynced`). A commit that also wrote a synced thing (a creation commit adding the thing to a synced group) stays, and the forgotten thing's part of it joins again when a peer serves that commit again, so the forgotten thing can show that commit's values (core/osis/tests/it/sync.rs `an_unsynced_write_goes_out_before_the_copy_goes_spec_sync_set_3`).
- A thing under `t`'s secrets still in the closure syncs under `t`'s S, so S stays in the sync set and `t` is never unsynced; the closure exclusion matters only to a direct call. Things known only from pending commits are not named (their parts stay pending).
- Cost: decodes every commit header and reloads the engine, like lost access. Unsyncing is rare; per thing.

## Reasons
- One value every module follows, written by the module that owns leaving: a per-module "also synced while waiting" would be a carve-out in each, and two writers would let modules disagree within a round.
- Any thing, admin or not, goes when unsynced: unsyncing means "not on this node" (Tess). Unsyncing everywhere the last copy loses it; stated in the spec as the behaviour, like deleting a local file.
- The wait guards only this node's own writes: a peer that never got them would lose them. Everyone else's are someone else's to keep.
- Status's durable mark, not stream presence, for a read S: a reader source shows what it holds by reported positions, which status already folds into the mark.
- A wait with no other node syncing S never ends (the copy stays until synced again): that is the rule (its own writes held nowhere else), not a stuck state; the API shows it as `GroupSync::leaving`.

## Tests
Rules on a fake ground: core/sync/tests/it/leave.rs. End to end over a restart: flows.rs `an_unsynced_write_reaches_a_peer_before_the_copy_goes_spec_sync_set_3`. The API: core/osis/tests/it/sync.rs (leaving).
