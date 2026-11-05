# A thing's creation as an ordinary write
> Summary: Proposal (Tess): `created.0` follows the ordinary purge and expiry rules, and purging or expiring a thing's creation ends the thing. That removes its special cases, including the exemption from the `nobody` rule and the two commits for creating a thing with expiring content. Open: what must remain to judge late writes and prove the purge was allowed. Design after owner removal, which changes the record.
> Tags: spec, permissions, api

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
4. **Who may.** Under which retention, and does a single admin's permanent purge fit the threat model (hostile admins aren't defended against)? **Disputes** (notes/owner-removal-plan.md): one side purging the root of a disputed thing must not end it for the other.
5. **Multi-thing commits.** Purge is per part (notes/whole-commits.md), so purging one thing's creation part leaves the other things in that commit alone.
6. **Dependents.** Things it holds as a group, things under it by ownership until owners go, grants it holds as an actor. An ended account or actor is a much bigger event than an ended note: is ending an actor allowed at all?
7. `required.0^` has the same exemption; check whether it can go too.
