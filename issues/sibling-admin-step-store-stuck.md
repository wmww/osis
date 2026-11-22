# A store on a sibling step under a new admin secret is never moved
> Summary: When two admins step siblings for one rotation and the sibling a store took rotated the admin secret (its issuer removed an admin), the store's head bears a delete key no step the recorded branch leaves from does, so Register (a branch only off a step bearing the head's delete key) never moves it on, and it keeps its sibling's keys for good.
> Priority: normal
> Tags: sync, security

**Seen**: by reading the branch rule (spec/sync-ids.md §6 Register; notes/sync-access.md, Why the gate and the claim), and at store level: `store::a_branch_moves_a_store_whose_sibling_kept_the_admin_secret_spec_sync_ids_6` (a loser that rotated the admin secret stays, whatever the winner did). Not reproduced end to end: a hand test as `inbox::a_store_on_a_losing_sibling_step_is_moved_on_spec_sync_ids_6`, with the losing issuer's removal rotating the admin role.

## What happens
- Steps A and B are children of P. A is under a new admin secret (delete key dA, unlike P's dP); B may or may not be. A store took A; readers record B, then C. A Register of [B, C] branches off P, whose delete key is not the head's (dA): refused (9), and the registrar sends nothing (`inbox::register::plan` mirrors the rule).
- So the store stays at A: it keeps taking entries stamped under A's write key while that key is current somewhere, and serves S to holders of A's sync key, a holder removed at C included, until its node closure lets the thing go.
- Only the loser's admin rotation matters: a loser keeping P's admin secret moves onto B's branch even when B rotated it.

## Why the rule refuses it
- An admin removed at A or B still holds dP. Off P it could register its own branch, as deep as it likes, on keys of its own; a store cannot tell that from B's branch (both chain from dP). The delete-key bound keeps a removed admin to what a child of the head gave it.

## Directions (not decided)
- **An endorsement by the head's delete key** (looks simplest): a Register may carry a signature by the head's delete key over the branch's last step ID; a branch off any step on the path, deeper than the head, is taken when its fork bears the head's delete key or such an endorsement verifies. It grants nothing a child of the head did not (whoever signs could make that child), so a removed admin without dA gains nothing. Who signs: any admin holding A's admin secret (every admin of A's epoch but the one A removed); it would be written once to `sync.0` so any reader relays it. Open: an admin of A's epoch must exist on the winning side and notice the fork; endorsements needed per losing tip.
- A step that names both tips (a merge step signed under each tip's delete key by an admin holding both): every later step stays a single child.
- Following the recorded `sync.0` directly does not work: the store keeps S unread and cannot read it; its evidence must verify under public keys it holds.
- The keys layer's own answer to the admin fork (which epoch wins) as the store's evidence: the store holds no secrets, so it would need the winning rotation's signature chain.
