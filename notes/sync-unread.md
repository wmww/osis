# Sync: unread
> Summary: osis-sync's `unread` module (core/sync/src/unread.rs): judgement for sync IDs this node keeps unread (keep, stranded, stop, leave); why it needs nothing of what S carries, how a removal notice counts, and the reasons behind its rules.

Spec: spec/sync-judgement.md §6, spec/sync-set.md §3. Model: core/test/tla/net/NetKeep.tla. Principle: the module doc. Overview: notes/sync.md.

## What it owns
Per S kept unread a `Kept` (stranded, credentials), stamped, which opens (`Unread::credentials`) and status (`stranded`) read. Nothing durable of its own: the sync record is the engine's, the head the store's; a start settles every key once. The rule is `unread::judge` over plain values (`Judged`), which the rule tests drive (core/sync/tests/it/unread.rs). `Sources` (an own entry present at some source) is streams'.

Credentials: its step's sync key and proof (the head's, derived from the record's secret of the head's epoch; with no head, the newest sync secret of the record, at no step), the head's deposit key (public) and claim set; none while stranded or holding no sync secret.

## Kept unread needs nothing of what S carries
It reads exactly the facade's `sync_things`/`thing_sync(t)` (whether the synced group's closure, walked only through groups the node reads, lists the thing: a fact of the node's own groups, not of S), `sync_record(t)` (the thing's sync IDs and sync secrets by epoch, from boxes sealed to its own key), `removal_notices(s)` (from the node's own inbox, which it reads) and `stop_sync_record`; and the store's path, head, own entries and `shred`. That is every input spec/sync-judgement.md §6 names. No call reads S's roster, chain, `keys.0` or commits; `open_entry` is never called for a kept-unread S. Read and unread move by the one predicate in the engine's sync set: a read secret held.

## Work follows change
The closure through one `Effects` key, diffed on change (O(closure) per closure change); each thing's `thing_sync` through its own; each S's judgement through one key reading its record, notices, path and own entries, so a head move, a box or a notice judges only its own S.

## Removal notices
A notice counts when its epoch is at or past every held sync epoch and it verifies under a step from the newest held step to the head. The Stop marks it counted (`Engine::stop_sync_record`); while it is held no box at or below its epoch makes a record again, so the old grant's inbox blob, judged again by inbox's `held` (a sync-only take applies no commit, so `taken` does not cover it), cannot bring the record back. A box at a self-made epoch makes notices stale there (spec/sync-hostile.md, a stated limit: that node keeps ciphertext it held). `RemovalNotice::recipient` is the blob's AD recipient, never a payload value: the removal signature binds it, so a notice to another recipient re-sealed here verifies nowhere.

End to end over connections: core/sync/tests/it/keep.rs (a sync grant kept unread, opened by the grantee's own test with its grant's sync key, the path registered from genesis, a write held, the removal noticed and S shredded).

## Reasons
- A node keeping S unread never drops its store on a head move alone (spec/sync-judgement.md §6 Stranded): a holder whose box is late would lose a copy that may be the only one. A head moving to a sync key with no box strands it (opens nothing) and drops nothing; only a removal notice drops the store.
- A removal notice counts only at an epoch at or past every sync epoch held (§6 Stops): a re-grant boxes a newer epoch than the removal's rotation, so the old notice no longer applies.
- No epoch rule at a node keeping S unread: it decides its own grant by the boxes sealed to it and the notices to it, nothing else, so a granter's account rotation (whose lists it never sees) cannot un-count its grant.
- Unlisted, it leaves only once each entry it logged itself is present at a source, keeping its record: leaving earlier could lose the only copy of its own writes.
