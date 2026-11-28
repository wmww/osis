# Sync: unread
> Summary: osis-sync's `unread` module (core/sync/src/unread.rs): judgement for sync IDs this node keeps unread (keep while a held sync secret derives the head's sync key, else drop the copy and take nothing); why it needs nothing of what S carries, and the reasons behind its rules.

Spec: spec/sync-judgement.md §6, spec/sync-set.md §3, spec/sync-opens.md §4 (what it shows), spec/sync.md §3. Model: core/test/tla/net/NetKeep.tla. Overview: notes/sync.md.

**Principle:** a node keeping S unread holds S's sync secrets (from the box that gave its role, and from when it last read S) and S's path in its store, nothing of what S carries; it keeps S while a held secret derives the head's sync key.

## The rule
`unread::judge`, over plain values (`Judged`):
- **Keep** while a held sync secret derives the head's sync key. Credentials: that key, its proof, the head's deposit key and head claim keys.
- **Stranded**: at a head no held secret derives, the store holds and takes nothing (`Store::set_unheld`: every entry dropped, durable and in memory, with no deletion event; path and tombstones kept; stamped entries, deposits and Deletes refused as with no head). It shows only the held secrets whose sync key no step of its path bears.
- **No head**: it shows every held secret.
- Credentials show every eligible secret, not the newest alone: a box at a self-made epoch would otherwise hide the grant's key.
- Leaving the sync set is `leave`'s one rule (notes/sync-leave.md): S stays synced, so judged here, until it stops.

## State
Per S kept unread a `Kept` (stranded, credentials), stamped; opens (`Unread::credentials`) and status (`stranded`) read it. Nothing durable of its own: the secrets are the engine's (`Engine::kept_sync_secrets`), the path is the store's. The store's mark of a drop is durable (`N/`, loaded at open as unheld), and a start judges every S before anything opens.

## Needs nothing of what S carries
It reads exactly the sync IDs this node syncs kept unread (`set::SyncsFollow`), the sync secrets of S's thing, and the store's path. No call reads S's roster, chain, `keys.0` or commits; `open_entry` is never called for a kept-unread S. Read and unread move by one predicate in the engine's sync set: a read secret held.

## Work follows change
The sync IDs by the store's feed (O(moved)); each S through one `Effects` key over its secrets and path, so a head move or a box judges only its own S. `set_unheld` runs when the verdict changes, and `set_unheld(false)` for every S that moves to read (also one not followed since a start: a copy dropped before a restart is fetched anew, notes/sync-streams.md Fetched anew).

Tests: core/sync/tests/it/keep.rs (end to end over connections: removal steps registered and a copy dropped, a step issued while a store is away, Registers lost and sent again).

## Reasons
- **No removal message.** The head moving past every key the node holds is what a removal does to it (a removal rotates sync), and a Register is verified on its path. A late box costs a re-fetch, not data a reader holds (Tess: predictable over keeping "in case").
- **The path stays at a stop**: it makes the stop stable. Without it the node has no head, shows its old secrets, and every reader's test registers the path and stops it again.
- **Shows unborne secrets at a stopped head**: a node removed and granted again after a further rotation would otherwise never move past its old head (no one registers at a node that shows nothing).
- **Takes nothing at a head it holds no key of** (also while a path registered from genesis passes steps before its grant): otherwise a node opened by such a secret would take what is stamped for a head past its removal.
- **No epoch rule**: it decides its own grant by the boxes sealed to it and the steps registered with it, so a granter's account rotation (whose lists it never sees) cannot un-count its grant.
