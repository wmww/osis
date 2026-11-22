# A store on a sibling step under a new admin secret is never moved
> Summary: Two admins each removing an admin at once make sibling steps under two new admin secrets (two delete keys); a store registered at the sibling the recorded path does not take shares no delete key with the recorded branch below its head, so Register (a branch only off a step bearing the head's delete key) never moves it on, and it keeps its sibling's keys for good.
> Priority: normal
> Tags: sync, security

**Seen**: by reading the branch rule (spec/sync-ids.md §6 Register; notes/sync-access.md, Why the gate and the claim). Not reproduced yet: a hand test as `inbox::a_store_on_a_losing_sibling_step_is_moved_on_spec_sync_ids_6`, with each admin's removal rotating the admin role.

## What happens
- Steps A and B are children of P, each under a new admin secret (delete keys dA, dB, both unlike P's dP). A store took A; readers record B, then C. A Register of [B, C] branches off P, whose delete key is not the head's (dA): refused (9), and the registrar sends nothing (`inbox::register::plan` mirrors the rule).
- So the store stays at A: it keeps taking entries stamped under A's write key while that key is current somewhere, and serves S to holders of A's sync key, a holder removed at C included, until its node closure lets the thing go.

## Why the rule refuses it
- An admin removed at A or B still holds dP. Off P it could register its own branch, as deep as it likes, on keys of its own; a store cannot tell that from B's branch (both chain from dP). The delete-key bound keeps a removed admin to what a child of the head gave it.

## Directions (not decided)
- A step that names both tips (a merge step signed under each tip's delete key by an admin holding both): every later step stays a single child.
- The keys layer's own answer to the admin fork (which epoch wins) as the store's evidence: the store holds no secrets, so it would need the winning rotation's signature chain.
