# Questions for Tess
> Summary: Open requirement and edge-case questions for Tess, each with a recommendation: realms (on hold), three limits kept in spec/requirements.md, depth 0 bending for stale member keys. Coordinators append; an answered question leaves this file and its answer goes to the spec or the relevant note.

Background: notes/core-triage.md §2. Ask one at a time, saying the trade-off and why users care.

## 5. Realms (notes/realms.md): on hold
First admins are built (notes/disputes-plan.md step 2), so realm and tag design may resume. Answered already: members see the member list. Open, with recommendations in notes/realms.md (Open questions):
1. A thing's place in a realm: a plain grant (only admins remove it; recommended) or tied to group membership as shared tags are (any writer could remove it, so revoke). Tess finds tied too much power for a writer.
2. Roles: edit details = admin, take part = write, view = read. Details then need admin-only aspects of a realm's own thing.
3. Who renames a realm: writers (recommended).
4. Role on joining: write (recommended); read for "viewer" invites.
5. Removed members keep their copies by default (recommended, as chat); admins may choose erase.
6. Things made in a realm have the realm as first admin, so they stay when their maker leaves (recommended); things shared in keep their own admins.
7. No single controlling account by default: a realm's admins are equals; a realm one account controls is allowed too (recommended).
8. Host admission for realms: left to the admission work (recommended).

## 11. Limits kept in spec/requirements.md
One limit stays; say if it should become a guarantee:
1. "Byte-identical everywhere" reads "equal values compare equal on every node", since a large value's bytes carry random keys. Confirm that is the property wanted (recommended).

## 12. Depth 0 bends a little
Tess decided a group never looks inside its member groups. One rule bends that: if a node already holds a member group's keys and knows someone left it, it won't hand out that group's old key, and it won't write under a parent key that passes the old key on (notes/crypto.md, Blocked through holder actors). It never fetches or walks anything it doesn't already hold. Why: a removal whose key change has to wait would otherwise let the removed person keep reading everything the group can read. Cost: until a node that may change the member group's key next syncs, that group's members don't see new content in shared things above it (nodes do this every sync pass). Built. Recommended: accept; the alternative is the leak while a removal's key change waits.

Part of the same question: the rule still leaks when a second admin of the parent group cannot read the member group, and stops at actors the node may not rotate (issues/blocked-walk-stops-at-readers.md, models `D0_readers_g2`, `D0_above_g2`). A candidate ("mark": a rotation records the keyset it left a member out at, and a re-seal takes only a keyset listing it) passes one of the two models but needs a wire field. Choice: build the mark, or state the leak as a limit.
