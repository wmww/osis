# Sync: unread
> Summary: osis-sync's `unread` module (core/sync/src/unread.rs): judgement for sync IDs this node keeps unread (keep, stop at a head past its keys); why it needs nothing of what S carries, and the reasons behind its rules.

Spec: spec/sync-judgement.md §6, spec/sync-set.md §3, spec/sync-opens.md §4 (what it shows), spec/sync.md §3. Model: core/test/tla/net/NetKeep.tla. Principle: the module doc. Overview: notes/sync.md.

## What it owns
Per S kept unread a `Kept` (stranded, credentials), stamped, which opens (`Unread::credentials`) and status (`stranded`) read. Nothing durable of its own: the sync secrets are the tickets' and those held from its own reading (`Engine::kept_sync_secrets`), the path the store's; a start settles every key once. The rule is `unread::judge` over plain values (`Judged`).

The rule: keep while a held sync secret derives the head's sync key (credentials: that key, its proof, the head's deposit key and claim set). At a head no held secret derives (`stranded`) the store holds and takes nothing (`Store::set_unheld`: drops every entry, durable and in memory, with no deletion event, keeping path and tombstones; refuses stamped entries, deposits and Deletes as with no head), and it shows only the held secrets whose sync key no step of its path bears. With no head it shows every held secret. Unlisted, it is `leave`'s (notes/sync-leave.md): it stays synced, so judged here, until each own entry is present at a source, then is shredded.

Credentials show every eligible secret, not the newest alone: a box at a self-made epoch would otherwise hide the grant's key.

## Kept unread needs nothing of what S carries
It reads exactly the sync IDs this node syncs kept unread (`set::SyncsFollow`: the sync set, and each leaving one while it waits), the sync secrets of S's thing its tickets give, and the store's path and `set_unheld`. No call reads S's roster, chain, `keys.0` or commits; `open_entry` is never called for a kept-unread S. Read and unread move by the one predicate in the engine's sync set: a read secret held.

## Work follows change
The sync IDs this node syncs by the store's feed (O(moved)); each S's judgement through one key reading its secrets and path, so a head move or a box judges only its own S. `set_unheld` runs when the verdict changed, and `set_unheld(false)` for every S that moves to read (also one never followed since a start: a copy dropped before a restart is fetched anew, notes/sync-streams.md Fetched anew). The store's mark of a drop is durable (`N/`, loaded at open as unheld), and a start re-judges every S before anything opens.

End to end over connections: core/sync/tests/it/keep.rs (a sync grant kept unread, opened by the grantee's own test with its grant's sync key, the path registered from genesis, a write held; the removal's step issued by node 0 and registered, the copy dropped, a later write not taken; granted again, the head reached under the new sync key).

## Reasons
- One rule, no removal message: the head moving past every key the node holds is what a removal does to it (the removal rotates sync), and a Register is verified on its path, so no other proof is needed. A late box costs a re-fetch, not data a reader holds (Tess: predictable over keeping "in case").
- The path stays at a stop: it is what makes the stop stable. Dropping it would leave the node with no head, showing its old secrets, and every reader's test would register the path and stop it again. Kept, an old box adds nothing, and only a secret no step bears (a grant past its head) shows.
- It shows the secrets no step of its path bears even at a stopped head: a node removed and granted again after a further rotation is otherwise never moved past its old head (no one registers at a node that shows nothing).
- Takes nothing at a head it holds no key of (also while a path registered from genesis passes steps before its grant): otherwise a node opened by such a secret (an epoch no step bears) would take what is stamped for a head past its removal.
- No epoch rule at a node keeping S unread: it decides its own grant by the boxes sealed to it and the steps registered with it, so a granter's account rotation (whose lists it never sees) cannot un-count its grant.
- At a stop it does not wait for its own entries to be present at a source: it can open S nowhere to learn it. Unlisted (still able to open), it waits: leaving earlier could lose the only copy of its own writes.
