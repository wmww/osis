# Recovery by an owner key
> Summary: Decided (Tess): recovery is no mechanism of its own. An owner key (a key a thing lists as allowed to sign as it) outranks the thing's admins: they see it and cannot remove it, and its role writes on the thing always apply. So anyone may attach an owner key to a thing, write it down, share adminship and take it back. It recovers authority, not data. Designed and modelled with the owner-key work.
> Priority: normal
> Tags: perm, keys, spec, api

Owner keys: notes/handoff.md, Decided by Tess. None by default: a thing with no owner key is a fully valid way to use osis, and a thief with an unlocked node taking control is accepted.

## The rule
- An owner key acts as the thing itself, and no grant gives or takes a thing's authority over itself, so no admin's write lowers it: its removal of an admin is an ordinary removal nothing contests, and it settles a fight among admins. The owner-key list is written only as the thing itself (by an owner key); admins read it. A thing with none takes its first from an admin, as an ordinary admin write.
- **Authority, not data** (Tess): nothing is sealed to an owner key. A node that lost every other way in regains control of the thing, and reads again what another reader shares with it.
- **A stolen owner key has no remedy** (Tess): two parties holding one key cannot be told apart.
- An adminless thing with an owner key (a node root) is unaffected.

## Must hold (Tess)
Attach an owner key, share adminship, the new admin turns hostile and backdates: no takeover and no dispute. It follows from a grant counting only from its own start: the admin's write adding an owner key is dated either before its grant (no right) or after the owner key exists (only an owner key writes the list). Not protected, by design: a party made admin of a thing that then attaches an owner key, against an admin who held the thing earlier and backdates one ahead of it.

## Designed
The rules, clause by clause: notes/write-path-design.md, Owner keys (the list, the key hop, who writes the list, a thing acting as itself, removing a key). The flow above holds for a key from the thing's record or added by an owner key, and against a backdated add; it does not hold where the first key was attached by an admin that a later admin removes without listing the attach: issues/owner-key-first-attach.md (for Tess).

## To do
- Model the rules and the flow before building (notes/write-path-design.md §6, roles-model 5). A thing given a role on itself changes nothing: acting as itself it is already its own admin (the unclassed difference of `windlass-wiring-1`: notes/priorities.md, Unlanded branches).
- API: making an owner key, showing it once, acting with one on a fresh node.
