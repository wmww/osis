# Questions for Tess
> Summary: Open requirement and edge-case decisions, written for Tess to answer when she has time; each with a recommendation. Coordinators append; remove an entry once answered (record the answer in spec or notes).

Background for all of these: notes/core-triage.md §2.

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

## 9. Owner removal step 6: what hosts do during a dispute
A model (core/test/tla/sides; notes/owner-removal-plan.md step 6) settled most of step 6. Hosts need one gate: while two admins are in a dispute, nobody deletes data at a host when the reason rests on a write only one side accepts. Without it the two sides delete and re-upload forever, or a body is lost before the other side ever fetched it. The plan's other candidates failed. What the gate costs, and a choice:
- **Cost, either way:** while a dispute lasts, deletes only one side agrees with (a purge, an old version being replaced, compaction) don't reach hosts: the encrypted data stays and hosts grow until the dispute is settled.
- **Choice: how precise the gate is.**
  - **A (recommended): per field.** No deletes at hosts on any field a disputed write touched. One check, plus three small cases. Extra cost: a purge *both* sides agree with, on such a field, also waits until the dispute ends. Fits "a fight may do wide damage, its handling must not spread through the code".
  - **B: per reason.** Every delete reason names the write it rests on; only those resting on disputed writes wait. Precise, but touches every place that decides a delete (about seven kinds).
- **Stated limits, for your OK:** after the fork, the losing side's new devices get only what its own devices held when the race was lost, plus what shared members carry across. And one shape is safe only because role changes reach devices before content does; a host delivering content first could lose a body (the model shows it). Not yet modelled: several hosts picking different winners, several disputes at once.

## Decided (Tess)
- Q1: option A (any writer finalizes an ended timed share), built as item 280.
- Q2: option A, a group never looks inside its member actors, with the two extra rules of notes/keys-requirements-study.md §4. Role cycles (Q8): Tess left it to us: no key cycles (the earlier grant in the agreed order gets keys, the later one none), model-check first, fall back to accepting a leak in cycles until the next knowing re-key if a hidden cycle leaks. Nested shared tags can be one-way. Plan: issues/keys-depth0.md.
- Q3: Tess's wording in spec/requirements.md (no values of another thing; only metadata, and only when one commit touches both); the exact metadata (thing ID, `ai` list, owner chain, size) is stated in spec/wire.md §4 and changes there deliberately, without her sign-off. Built as is (whole-2b).
- Q4: option A, written into spec/requirements.md Deletion (an undo made before the device saw the purge is its own change). Nothing to build.
