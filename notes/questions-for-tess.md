# Questions for Tess
> Summary: Open requirement and edge-case decisions, written for Tess to answer when she has time; each with a recommendation. Coordinators append; remove an entry once answered (record the answer in spec or notes).

Background for all of these: notes/core-triage.md §2. The two below: notes/keys-requirements-study.md.

## 5. Realms (design: notes/realms.md)
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

## Decided (Tess), to build
- Q1: option A, any writer finalizes an ended timed share (role no higher than its own) with an explicit removal that rotates; self-removal stays a departure; admin-only finalize is an accepted fallback if any-writer hits trouble. notes/keys-requirements-study.md §2.5.
- Q2: option A, a group never looks inside its member actors (seals to a member's current keyset, rotates when it is superseded). notes/keys-requirements-study.md. Needs a short model check before building.
- Q3: Tess's wording in spec/requirements.md (no values of another thing; only metadata, and only when one commit touches both); the exact metadata (thing ID, `ai` list, owner chain, size) is stated in spec/wire.md §4 and changes there deliberately, without her sign-off. Built as is (whole-2b).
- Q4: option A, written into spec/requirements.md Deletion (an undo made before the device saw the purge is its own change). Nothing to build.
