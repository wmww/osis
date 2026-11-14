# Sync: store
> Summary: osis-sync's `store` module (core/sync/src/store/): the one ciphertext store per node for every sync ID, read or kept unread; its rows, the engine's ciphertext door, what it follows of the engine, caps and the policy, the bounds on what peers make it keep, and the carriers of pending commits.

Spec: spec/sync-ids.md §5-§6, spec/sync-streams.md §3, spec/sync-inbox.md §3 Deposits, spec/sync-judgement.md §4 (stand state). Overview: notes/sync.md. The underlying store: notes/local-store.md.

## What it owns
Entries (wrap or filler, stamp, deposited flag, own, role, class, expiry; held elsewhere in a row of its own, status's), tombstones with what the entry was, blob bytes once per node, the path per sync ID (steps and claim sets), the node log with a per-sync-ID index (osis-store `nodelog`; a join costs that sync ID's events), usage per sync ID against the caps and the deposit budget, charges against each peer's budget, and the rows a source's record keeps for `read` (stands, deletes seen). Ephemeral entries, their tombstones and bytes and the log's memory part live in memory (`store/memory.rs`, lost at a restart). The row layout is in `store/rows.rs`' module doc. It decrypts nothing and judges no open.

Every operation is one transaction of the underlying store, so a crash keeps all of its rows or none (an entry and its log event, a removal and its tombstone). Every row change stamps, so memos and `Effects` may read it.

## The engine's ciphertext door
`Store` is a cheap `Clone` handle over one locked store and implements `osis_store::CipherHost` (`store/cipher.rs`): the engine holds and releases blob bytes through it, inside the engine's own transactions; sync locks it only between engine calls, so one step never holds both. A blob's bytes stay while the engine or any entry of any sync ID holds them.

## Rows other modules keep
A peer's record holds other modules' rows (osis-store `record_put_row(id, tag, sync_id, key, value)`, or `record_put_wide_row` for a row about the record as a whole), one tag per owning module (`store::rows::tag`): store `b` charges, `s` stands, `d` deletes seen; opens and streams theirs (notes/sync-opens.md, notes/sync-streams.md). They go with the record, a sync ID's also with the sync ID. `with_tx` gives other modules a transaction for their own rows.

## What it follows (`store/follow.rs`, settled first in every round)
- The sync IDs this node syncs (`set::SyncsFollow` over `Store::syncs_feed`; `leave` writes them, `Store::set_holdings`), the caps (`Engine::caps`, `caps^.0`), and for each S read here its served path (`Store::serve_path` from `sync.0`), each an `Effects` value.
- **Parked entries**: a peer's entry whose commit is neither held nor pending here (it did not open, or opened to a commit thrown out; record blob carriers included: the engine's loose records are in memory) is parked under S's read secrets (`Follow::parked`, in memory), found by the store's entry feed (which also reports removals, so a gone entry unparks) and by one pass over S's entries when S becomes read (a start, a grant). Each time S's read-secret epochs gain one, only S's parked entries are opened again (notes/sync.md Arriving early); one that gives something held goes off its peer budget. The engine re-examines its pending commits itself (`reexamine`: notes/sync-facade.md Pending), so sync opens nothing again for them.
- Per read S, its served head: a stamp vouches only under the head; otherwise the entry is charged. At a start and each move, `charge_unvouched` charges each peer's stamped carrier (its commit pending, or a loose record) whose stamp no longer verifies to the peer that brought it (`EntryRow::brought`, kept for every uncharged peer entry, cleared by `gone`); past that peer's budget, or with it gone, the entry is not kept (no tombstone; its pending copy goes as its blob goes unnamed). An honest rotation drops nothing within budget. O(entries of S) per head move.
- **Carriers** (pending commits and loose records, spec/commits.md §4 Pending storage): the engine keeps a pending copy, or a loose record, only while a store entry names a blob of it. `Carriers` follows the store's `unnamed_feed` (a blob no entry names any more: removed, expired, shredded, gone with its peer) and calls `Engine::forget_pending` once no blob of the commit is named (`store::release`; a commit that came by no entry, an inbox payload or pairing, names no blob and is left); a body not kept (past its peer's budget) is released at once (`streams::Ground::unkept`); a start sweeps every pending commit once. A blob unnamed also drops the loose records only it carried (`forget_carrier`). A commit held here, or a record blob whose loose records were all learned (`loose_feed`), takes its carriers off their peers' budgets.

`settle_at` expires entries (no tombstone, no event), ends tombstones and aged stand rows after `TOMBSTONE_LIFETIME`, drops claim sets superseded for `ROLE_KEEP`, sweeps the log's deletion events, and lets the unread sync ID using most give way past the total cap.

## Caps and policy
`Policy` (`Policy::from_caps`) reads each value from `caps^.0`'s `policy` by field name, defaults where it names nothing; per-thing caps replace `entries` and `bytes`. Caps apply to sync IDs kept unread only, but `memory_bytes`, which also bounds what a reader holds of S's ephemeral commits (`memory_room`; an entry of a held one counts at `Engine::memory_charge`, at least its bytes: `set_memory_charge`); role entries count toward none. The deposit budget is the policy's raised to `osis_proto::limits::deposit_budget` for the head's claim-set size. A child step past the caps is taken at most once per `register_every_ms` per sync ID (spec/sync-ids.md §6 Storage caps).

## What peers can make it keep
- A Delete of an entry not held writes nothing, so tombstones never outnumber what was held.
- Unstamped entries a peer brought count against its peer budget (`log` and deposits alike) and go with its connection or its dropped record (`gone`). `log` checks a peer's stamp against S's head write key: one that does not verify is charged as unstamped (and replaces no stamp held), so a forged stamp floods nothing. So what one peer makes pend in the engine, commits and records alike, is bounded by its own peer budget and never evicts another's; what a writer stamped is charged to its bringer once its key is not the head's.
- A record-less connection's stand and delete-seen rows live in memory and age out after `TOMBSTONE_LIFETIME` like a record's.
- Deposits per sync ID by the shared deposit budget, which any holder of the deposit key can fill until a delete-key holder clears (spec/sync-inbox.md §4).

## A reader's store of S
Its own entries plus those it pulled that did not open, or that opened to a commit pending in the engine (`Engine::pends`: unjudgeable, an epoch or pages away, drift; streams' `take_body` logs them as the commit's carrier, charged to the peer when unstamped).

## Reasons
- One store for every sync ID, read or kept unread, and a shredding one: a node keeping S unread may read other sync IDs on the same machine, so wraps and blobs surviving a delete in freed pages would break spec/requirements.md Deletion (notes/local-store.md).
- A store failure closes every connection and restarts the modules from the store (notes/sync-driver.md); nothing here assumes a module's memory survived.
