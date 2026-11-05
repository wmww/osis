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

## 10. Deleting while removed, then re-granted (linked to 6 and 7)
The requirement says the right to delete is judged at the time of the request. Now a delete request someone made while removed counts once they get the role back, like their edits from that gap do (spec/permissions.md §7; needed so a re-grant cannot bring back an edit's value its own request deleted, order seed 3001). They could delete the same things right after the re-grant anyway, so this gives no new power, but the requirement's wording no longer says what happens.
- Proposed sentence for spec/requirements.md Deletion: "A re-grant counts for deletes as for edits: a request made while removed takes effect once the role is back."
Side effect, from 7: a delete request made before the person ever held the role (a reader's, the admin happened to receive it) takes effect when that person is later granted and then removed, because the removal lists it. The removal itself then deletes data. Mostly no new power (while granted they could have asked again), but in a rare case (acting for another person's device) it may delete what they never could. Choices:
- A: answer 7 with A and extend it: clients also leave out of a removal the delete requests made before the person first held the role (receivers unchanged). Recommended.
- B: receivers also require that the person had held the role at some point at or before the request (one condition in the purge right).

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
- Q6: A (Tess): a re-grant revives all the person's writes; no special case. Her point: leaving writes out of a removal on purpose as a recovery tool is depending on a side effect; an admin who wants something gone should revert it explicitly, not as a side effect of a kick. Don't extend that side effect to new uses (bears on Q7, Q10 and on notes that describe deliberate omission as lockout or purge recovery).
- Q7: simplest (Tess: "this would be a strange thing for an admin to do"): no change; a removal's listed writes are valid as today; stated limit only. Lockout recovery by deliberate omission (`--repudiate`) to be re-studied as a key fork from the last epoch held (Q6 principle).
