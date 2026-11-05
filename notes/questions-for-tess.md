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

## 9. Owner removal step 6: hosts when an actor forks
A fork can last forever, so everything below is a permanent rule, not a waiting period. A model (core/test/tla/sides; notes/owner-removal-plan.md step 6) checked it with devices switching sides; no loops and no data lost.
- **The forked actor's own data: each side gets its own branch at the host.** Today the second side is refused and moves to a new label, and its new devices then get only what its own devices still hold. With branching, both sides keep everything that was at the host before the fork, for good. Shared members also copy across data no fork-dependent write touches, so late uploads reach both sides.
- **Other data, where someone's access runs through the forked actor** (an actor holding a role whose admins fork, a person whose devices fork): a host deletes a body only when no side needs it.
- **What users notice:** nothing, except that hosts keep more. Deletes only one side accepts (a purge, an old version being replaced, compaction) never reach hosts on that shared data while the fork lasts.
- **Choice: the rule's form.**
  - **A (recommended): "no side needs it".** One side's own old versions still get cleaned up, since the other side never needed them.
  - **B: plain "never delete because of a fork-dependent write, nor such a write itself".** Simpler to state, but every edit one side makes after the fork leaves its old version at hosts forever.
  - (Per field was rejected: a purge both sides accept would never reach hosts.)
- **Stated limits, for your OK:**
  1. A removed admin (no fork needed) can open a branch of its old label at a host. Other devices ignore it; it costs host storage, and it can download again the encrypted copies it could already read before its removal.
  2. A host that won't branch falls back to today's new label, with today's reach loss at that host.
  3. After one side concedes, its branch is abandoned; its admins should delete it, like a replaced label.
  4. As before, one shape is safe only because role changes reach devices before content does.
- Not yet modelled: several hosts, several forks at once, two honest admins rotating at the same moment.

## Decided (Tess)
- Q1: option A (any writer finalizes an ended timed share), built as item 280.
- Q2: option A, a group never looks inside its member actors, with the two extra rules of notes/keys-requirements-study.md §4. Role cycles (Q8): Tess left it to us: no key cycles (the earlier grant in the agreed order gets keys, the later one none), model-check first, fall back to accepting a leak in cycles until the next knowing re-key if a hidden cycle leaks. Nested shared tags can be one-way. Plan: issues/keys-depth0.md.
- Q3: Tess's wording in spec/requirements.md (no values of another thing; only metadata, and only when one commit touches both); the exact metadata (thing ID, `ai` list, owner chain, size) is stated in spec/wire.md §4 and changes there deliberately, without her sign-off. Built as is (whole-2b).
- Q4: option A, written into spec/requirements.md Deletion (an undo made before the device saw the purge is its own change). Nothing to build.
- Q6: A (Tess): a re-grant revives all the person's writes; no special case. Her point: leaving writes out of a removal on purpose as a recovery tool is depending on a side effect; an admin who wants something gone should revert it explicitly, not as a side effect of a kick. Don't extend that side effect to new uses (bears on Q7, Q10 and on notes that describe deliberate omission as lockout or purge recovery).
- Q7: simplest (Tess: "this would be a strange thing for an admin to do"): no change; a removal's listed writes are valid as today; stated limit only. Lockout recovery by deliberate omission (`--repudiate`) to be re-studied as a key fork from the last epoch held (Q6 principle).
- Q10: a gap delete counts after re-grant, like gap edits. Requirements kept to the property (Tess: "define the properties we care about, not shrink-wrap the behavior"): Deletion now says a purge counts only if its author had the right, judged as an edit's validity; the demotion-omission exception sentence is gone (it follows). Side effect (grant-then-remove of a stranger) is a stated limit, as Q7.
