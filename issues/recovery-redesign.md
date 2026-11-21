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

## To do
- Model the override and the flow above before building: the self edge is a soft spot (a thing given a role on itself is one of the unclassed differences of `windlass-wiring-1`: notes/priorities.md, Unlanded branches).
- API: making an owner key, showing it once, acting with one on a fresh node.
