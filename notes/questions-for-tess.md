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

## 11. Limits kept after the requirements pass
The pass (spec/requirements.md) dropped limits that follow from a stated property and moved mechanism to the subsystem specs. Three real limits stay; say if any should instead become a guarantee:
1. A write mixing expiries, or mixing data nobody may purge with other data, becomes several changes, so it is not atomic. Keep as a stated limit (recommended: apps rarely mix them), or make one change carry per-part expiries (wire and host work).
2. Removing an account whose kept writes number more than about 1.9 million fails. Keep (recommended: rare; it only bites on data whose history is kept forever), or require removals of any size.
3. "Byte-identical everywhere" now reads "equal values compare equal on every node", since a large value's bytes carry random keys. Confirm that is the property you want (recommended).

## 12. Depth 0 bends a little (re your Q2)
You decided a group never looks inside its member groups. Fixing a leak bent that a little: if a device already holds a member group's keys and knows someone left it, it won't hand out that group's old key, and it won't keep writing under a parent key that passes the old key on. It never fetches or walks anything it doesn't already hold. Why: a removal that has to go out on its own (its key change waiting) would otherwise let the removed person keep reading everything the group can read. Cost: until a device that may change the member group's key next syncs, that group's members don't see new content in shared things above it (devices do this every sync pass, not lazily). Recommended: accept. The alternative is accepting the leak while a removal's key change waits.

## 13. Who may make something whose first admin is a group?
With owners gone (owner-removal step 2), every new thing names a first admin. When Alice, a writer in group G, creates a document "in G", the document's first admin is G, so all of G's admins control it, not Alice personally. Today owned things already work this way. Recommended: yes, anyone with write on G may create a thing whose first admin is G (it's how "make a doc in this team" works). The alternative, only G's admins may, means ordinary members can only create things they personally control and then share.

## Decided (Tess)
- Q1: option A (any writer finalizes an ended timed share), built as item 280.
- Q2: option A, a group never looks inside its member actors, with the two extra rules of notes/keys-requirements-study.md §4. Role cycles (Q8): Tess left it to us: no key cycles (the earlier grant in the agreed order gets keys, the later one none), model-check first, fall back to accepting a leak in cycles until the next knowing re-key if a hidden cycle leaks. Nested shared tags can be one-way. Plan: issues/keys-depth0.md.
- Q3: Tess's wording in spec/requirements.md (no values of another thing; only metadata, and only when one commit touches both); the exact metadata (thing ID, `ai` list, owner chain, size) is stated in spec/wire.md §4 and changes there deliberately, without her sign-off. Built as is (whole-2b).
- Q4: option A, written into spec/requirements.md Deletion (an undo made before the device saw the purge is its own change). Nothing to build.
- Q6: A (Tess): a re-grant revives all the person's writes; no special case. Her point: leaving writes out of a removal on purpose as a recovery tool is depending on a side effect; an admin who wants something gone should revert it explicitly, not as a side effect of a kick. Don't extend that side effect to new uses (bears on Q7, Q10 and on notes that describe deliberate omission as lockout or purge recovery).
- Q7: simplest (Tess: "this would be a strange thing for an admin to do"): no change; a removal's listed writes are valid as today; stated limit only. Lockout recovery by deliberate omission (`--repudiate`) to be re-studied as a key fork from the last epoch held (Q6 principle). Studied: notes/lockout-recovery.md (not a fork: the removal's rotation lists the epochs it cannot open, superseding them).
- Q10: a gap delete counts after re-grant, like gap edits. Requirements kept to the property (Tess: "define the properties we care about, not shrink-wrap the behavior"): Deletion now says a purge counts only if its author had the right, judged as an edit's validity; the demotion-omission exception sentence is gone (it follows). Side effect (grant-then-remove of a stranger) is a stated limit, as Q7.
- Q9: closed by model (Tess: "if that actually works great"). Forks are permanent. The forked actor's own label: hosts branch on a step a registrar's view rejects; each side keeps its branch; members holding both sides' keys carry bodies no fork-dependent write touches. Other labels where a right flows through the forked actor: a body is deleted at a host only when on every side it is invalid or a delete reason holds ("no side needs it"). Permanent cost: deletes only one side accepts never reach hosts on shared data. Limits: a once-removed admin may open a branch from an old step (host storage; it re-reads what it could read); a host that won't branch falls back to label replacement; a conceded branch is deleted like a replaced label; one shape relies on role commits arriving before content. Not modelled: several hosts, several forks at once (each fork-dependent write tagged with the picks it rests on). core/test/tla/sides, notes/owner-removal-plan.md step 6.
