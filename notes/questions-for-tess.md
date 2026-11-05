# Questions for Tess
> Summary: Open requirement and edge-case decisions, written for Tess to answer when she has time; each with a recommendation. Coordinators append; remove an entry once answered (record the answer in spec or notes).

Background for all of these: notes/core-triage.md §2. The two below: notes/keys-requirements-study.md.

## 5. Realms (design: notes/realms.md) — ON HOLD
Tess (in discussion): realms and tags may be one concept unless clearly distinct; her current lean: a realm is how ownerless things are exposed to users (making a realm = making an organization you admin and can hand off; it owns things; a tag is a collection that shares, owns nothing; a realm may own tags). Ownerless things are being replaced by first admins (notes/owner-removal-plan.md, step 2); no realm/tag design work until that settles. Answered: 5.2 yes (members see the member list). Open with it: 5.1 (tied vs plain grants: shared tags let any writer unplace and so revoke; she finds that too much power), 5.3 (roles: edit details = admin, interact = write, view = read; details need admin-only aspects).
A realm is an actor marked `realm.0` (plus `name.0`), as `tag.0` marks a group; members are its holders, "in the realm" is what it owns or holds a role on; nesting, overlap and per-person roles are plain grants. Eight small choices, each with a recommendation (details in notes/realms.md):
1. A thing's realm grant: plain (only admins remove a thing from a realm; recommended) or tied to placement like shared tags (any writer could remove it).
2. Members see the member list: yes, stated (recommended).
3. Who renames a realm: writers (recommended).
4. Role on joining: write (recommended); read for "viewer" invites.
5. Removed members keep their copies by default: keep (recommended, as chat); admins may choose erase.
6. Things created in a realm are owned by the realm, so they stay when their maker leaves (recommended); existing things shared in keep their owner.
7. Realms ownerless by default, person-owned allowed (recommended).
8. Host admission for realms: left to the host admission work (recommended).
Say "realms as recommended" to build, or change any.

## 6. Re-granting someone brings back writes a removal left out on purpose
Today when a removed person gets their role back, every write they made since they first had the role becomes valid again, including writes the removing admin left out on purpose (spec/permissions.md §5.2; notes/permissions.md "Re-grant validates the gap"). Leaving writes out on purpose is how an admin undoes a writer's lockout (bad key rotations) or takes back their purges. So re-adding that writer later quietly undoes the recovery.
- A: keep it (simple, one rule; the app warns an admin re-adding someone whose removal left writes out on purpose). Recommended.
- B: a re-grant only restores writes from the start of the current grant plus the gap, never ones a removal left out on purpose (needs the timeline to remember deliberate omissions).

## 7. A removal can make writes valid that were never allowed
A removal's frontier lists the removed person's writes it had seen, and each listed write is valid, whether or not the person had the role when writing (spec/permissions.md §5.2). Writes made after an `until` expiry rely on this, as intended. Side effect: a write made before the person was ever granted (an outsider's write the admin happened to receive) becomes valid when that person is later granted and removed. Rare, needs a hostile writer.
- A: keep it, and have clients leave out of a frontier the writes made before the person first held the role. Recommended (receivers unchanged).
- B: receivers also require the role "as restored" at the write (more rules in validity).

## 8. Q2 follow-up: the model check changed the picture (please re-confirm)
Now also the first step of notes/owner-removal-plan.md: removing owners and roster snapshots wants the depth-0 keys built first.
The short model check you asked for before building Q2 A (a group never looks inside its member actors) found two things. Details: notes/keys-requirements-study.md §4.
- **The downside is bigger than I told you.** In the rare cases (an out-of-date device of Alice makes her new key including the removed tablet, or the stolen tablet forges one while the removal news is held back), the tablet can read the group's messages written *since the removal*, not only messages written after that moment. Today the same cases lock Alice out instead. Two small extra rules (Team only accepts an Alice key that builds on the ones it already used; Alice's devices fix any of her keys that misses a removal they know of) close the simple version of this, and the model found no leak with them.
- **Cycles have no simple rule.** When two groups each hold a role on the other (X in Y and Y in X), every simple rule the model tried either leaks to a removed device, keeps re-keying back and forth forever, or locks one group out of the other for good. Today's design handles cycles only through the machinery Q2 A deletes.
Options for cycles:
- **A (recommended): no key cycles.** A role that would let X read Y while Y can already read X (directly or through others) gives no key access; the earlier grant in the agreed order wins. Plain data check over grants, no key machinery; realms nest and overlap without cycles. Changes the requirement "groupings may be cyclic" for reading through each other.
- **B:** keep today's machinery for cycle members only (most of the 2k lines stay).
- **C:** accept that in a cycle a removed device may keep reading until the next knowing re-key (a further stated limit).
- **D:** go back to Q2 B (keep today's design everywhere).
With A, I'd build Q2 A with the two extra rules. If the bigger downside above changes your mind on Q2 itself, say D.

## Decided (Tess)
- Q1: option A (any writer finalizes an ended timed share), built as item 280.
- Q2: option A, a group never looks inside its member actors. Model check done: reopened as question 8 (bigger downside, cycles).
- Q3: Tess's wording in spec/requirements.md (no values of another thing; only metadata, and only when one commit touches both); the exact metadata (thing ID, `ai` list, owner chain, size) is stated in spec/wire.md §4 and changes there deliberately, without her sign-off. Built as is (whole-2b).
- Q4: option A, written into spec/requirements.md Deletion (an undo made before the device saw the purge is its own change). Nothing to build.
