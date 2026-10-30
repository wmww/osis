# Map removals and tombstones keep the entry's key
> Summary: Since entries are keyed by (dot, key) (spec/crdt.md §5.6), every removal record and every snapshot tombstone carries the removed entry's key. For app maps the key can be user content: it outlives the entry's purge, expiry and keep-at-most bound in the removal's body and in snapshots, against spec/requirements.md Deletion ("Purge is prompt", "No fingerprint", history kept at most). Needs owner sign-off or a narrower design.
> Tags: security, crdt, owner

## Problem
- A removal `[dot, [D], key, []]` is a separate edit (often another author's) with its own retention. Purging or expiring the entry's creation folds the key away in states (§4.7), but the removal's body keeps it at every node and untrusted server holding that body, and readers decrypt it. Before (dot-only identity) a removal plus a purge of the creation left no key, unless someone else had written into the entry (nested writes already repeated the key: pre-existing, narrower).
- Snapshot tombstones keep the key until the map fragment is reset, past any keep-at-most bound on the removed value.
- For `/secrets` (box and history keys) and `/members` (tids) keys are public ids: no concern there.

## Direction
- Keyed removals only where validity needs them (`/secrets`, maybe `/members`); elsewhere writers emit the keyless form (the dot's key-erased record), whose reset already reaches every record of the dot (§5.6), so honest single-key entries remove as before and tombstones carry no key. Spec §3.2/§5.6 would allow a keyless removal in a writer's delta outside membership aspects.
- Or accept and amend spec/requirements.md (a deleted map key is metadata like the edit's fact and time).
