# A thing's creation as an ordinary write
> Summary: Built (notes/expiry-creation-design.md): `created.0` follows the ordinary purge and expiry rules, purging or expiring a thing's creation ends the thing, and authority that passed through it stands as its frozen history says. Open: Tess's sign-off on the requirements wording.
> Priority: normal
> Tags: spec, permissions, api, tess-call

Built: notes/expiry-creation-design.md steps 1-8 (dependents: B, records as identity, raw records in chain certificates). Needs Tess: the requirements wording (§5 of the note).

Today `created.0` has fixed `nobody` retention, kept forever, with an exemption so it can share a commit (spec/commits.md §5), and can't go in an expiring commit, so creating a thing with expiring content takes two (§6). `delete` keeps it, and a later write recreates the thing (notes/api.md).

## Proposed
- Purging a creation permanently ends the thing, for everyone honest. `delete` stays the undoable way.
- A creation in an expiring commit ends the thing at that time, so a disappearing message is one commit.
- The exemption goes. Today a thing whose only content expires needs a durable stub write first, or a `sync` or grant, which keep it (notes/api.md Writes).

## Latitude (Tess)
No sign-off needed. If this fails for dull internal reasons, that's fine. Other outcomes are acceptable: purge and expiry of a creation allowed conceptually but handled specially, keeping the data they need; or what exists today. Any of them beats quietly splitting a write.

## To settle
1. **What remains.** Late writes must be told from writes to an unknown thing, and a purge must be judged by its author's role at the time, which is rooted in the record. So a purge leaves a tombstone at least holding the request and what proves it: possibly the record and a chain. Is that smaller than today's record, or the same with a new name? An expiry may need less: it's in the creation's own signed header.
2. **Order.** The purge arriving before the creation, before grants it relies on, or at a node that never held the thing. Must converge (spec/requirements.md).
3. **Recreation.** "Tids never die, and a later write recreates" stops holding for an ended thing. What do writes made concurrently with the purge do?
4. **Who may.** Under which retention, and does a single admin's permanent purge fit the threat model (hostile admins aren't defended against)? **Disputes** (notes/disputes-plan.md): one side purging the root of a disputed thing must not end it for the other.
5. **Multi-thing commits.** Purge is per part (notes/whole-commits.md), so purging one thing's creation part leaves the other things in that commit alone.
6. **Dependents.** Things it holds as a group, things whose record chain it is on (their derivation and labels read through it), grants it holds as an actor. An ended account or actor is a much bigger event than an ended note: is ending an actor allowed at all?
7. `required^.0` has the same exemption; check whether it can go too.

## Direction (Tess, coordinator)
No tombstone or kept record: a node keeps no writes for a thing whose creation it does not hold; it fetches that thing's writes again from the group once the creation arrives. A purged or expired creation then leaves nothing anywhere (closes the per-thing leak, growth row 6). Only if edits commonly arrive before their thing's creation, hold them briefly (a picked number, notes/arbitrary-values.md); expected rare. Study with issues/expiry-knocks-out-commit.md: refetch by thing without per-unknown-thing state; writes to a deleted thing leave group storage by ordinary retention; things whose first admin is the deleted thing follow the standing-edge rule; nothing else depends on records being permanent.
