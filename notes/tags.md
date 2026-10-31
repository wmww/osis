# Tags and the standard core aspects
> Summary: The user-facing organization layer decided with the owner: toplevel core aspects (`/name`, `/body`, `/tag` in the core schema), tags as marked groups in a graph (not a tree), sharing a tag per item through one nested roster, recursive sharing semantics, the "only share what you may share" property, the confirmation guideline for first-party apps, the logical-document convention, costs, what examples/tags and notes-app show, and what is still open.

## Direction (owner)
- No standard schema existed; the example apps minted four aspects for "name". The foundation should be settled before stabilizing.
- Generic aspects go toplevel in the core schema (single-segment AKs are the core schema, spec/data-model.md §2), not in a `/common` namespace.
- No `kind` aspect: what a thing is, is defined by its aspects, and a thing may be several kinds (ECS).
- No directory or folder concept (the tree was always too inflexible) except for interfacing with real filesystems. User-facing organization is **tags**: nestable as a graph, any thing can be in any tag, a bit of optional metadata over the existing group infrastructure. Not every group is a tag; internal application groups carry no tag metadata and are never shown.
- No user-visible "space". Moving a thing to another owner is a copy with a new tid, so users must never be expected to move things between containers; a share is per item, through one roster (below).
- Chat is thrown out until a good schema is designed (notes/std.md); notes/chat.md keeps the old pattern and its costs.

## Core aspects (spec/data-model.md §9, core.osis)
```
aspect /name: string;                 // what humans call the thing
aspect /body: markdown;                // freeform content: a note's text, notes on anything
aspect /tag: struct { 0 color: option<string> };   // marks a group as a user-facing tag
```
- No `/icon` for now (owner): added when an app needs it. Typed keys `osis::core::{NAME, DESCRIPTION, TAG, Tag}`.
- `/tag` on a group thing makes it a tag; its items and subgroups are the tag's contents and sub-tags. Default retention `author`, no bounds, like `/group`.
- No order or position inside a tag in core (owner): apps keep their own, since one wants a list, another a 2D canvas position.

## Tags
- A tag is a group thing with `/tag` and usually `/name`. Membership of a thing in a tag is placement (`/group.items`), nesting is `/group.subgroups`. Graph, cycles allowed, a thing or tag may be in many tags.
- Why placement and not a `/tags: set<tid>` on the thing: placement is written on the tag, so a reader can tag a thing it cannot write, and one person's tags of a shared thing never reach the thing's other readers. Each reader's tags are private by construction.
- Placement is also what syncs a thing (spec/requirements.md, Offline and network): a thing in no tag and no internal group stays local. Apps keep an internal synced group for "all my notes" or similar; tags are extra.
- Internal groups (buckets, app indexes) have no `/tag`; generic tools list only tags.

## Sharing a tag
Built from the mirrored-edges pattern of notes/permissions.md Patterns with **tied grants** (spec/permissions.md §2); core/osis/tests/it/tags.rs and tied.rs build it (`share_into`, `new_sub_tag`, `unplace`):
- **The operation** (owner, round 13: tied grants over "placement grants access"; explicit; the "no helper" rule withdrawn for it; eventual removal accepted): `db.share_into(T, G, role, ShareOpts { subgroup, place_anyway })` places T and writes G's edge on T tied to that placement (the `/group` element's creation stamp and set; an existing tied edge whose element is dead here is tied again to the new one); plain `place` never shares. `unplace`/`remove_subgroup` remove the tied edge right after when that is a self-removal (admin on G only); else node-sync's obligation (`SyncEngine::untie_unplaced`) removes it at a node that holds the named element dead (a tombstone, or absent under a later reset of the set, struct or aspect) and may (explicit by T's admin, after the pre-sync passes; self-removal by G's admin), like link finalization. An element not held yet is on its way: the edge may arrive first (two commits, separate uploads), so no pass count proves the placement gone; the named element does. One way: a placement without an edge re-grants nothing; an untied (hand) edge survives an unplace. `db.remove_edge_of(G, T)` is G's admin's self-removal; `db.reach(T)` lists per group `Tied`/`Untied`/`Excluded` and tied edges whose placement is gone.
- Why not "placement grants access" (rejected): the rights record would leave the thing, so T's admins could no longer see or revoke shares (Alice places her note in Bob's tag, Bob removes Alice: she can no longer unplace, nothing on the note stops it); placements would become rights writes in the timeline; readers may tag what they cannot write.
- Why not one commit for placement plus edge (the issue's first plan): a mixed-kind commit touches commit validation, retention, compaction, projection and undo, and a membership commit applies partially at a receiver anyway (spec/commits.md §4), so it buys no receiver-side atomicity. Two commits in one local operation (placement first: a crash leaves "placed, excluded", safe; the edge names the placement's element, so its arrival order does not matter). The first version waited for a complete pass of G's labels instead; the edge could still arrive first and be removed (review repro, now `tied::edge_before_placement_is_not_removed`).
- A self-removal of G's edge goes whole under the labels holding G (`Delivery::Deposit` from `demote_in`): the target is out of G's closure after the unplace, and its bodies leave G's label once G reads it no more, so without it the removal never left the remover.
- The tag becomes an actor (secrets of its own, a label, a roster). Each direct item gets one edge for the tag's actor at the share's role or lower; a sub-tag gets the same edge and is made a shared actor itself if it is not one yet. Rights chain through membership edges (spec/permissions.md §1): a member of T reaches an item of sub-tag U by the path T → U → item, role = the minimum along it.
- Items keep tid and owner; an item in several shared tags has one edge per tag; moving between tags is an edge change, never a copy. Everything under the tag travels under the tag's one label (entitlement holds through the chain).
- Rosters nest: U's roster lists T as one member actor. Removing Bob from T rotates T, then lazily each sub-tag and item below it once (the cascade of spec/permissions.md §3), whatever the graph shape.
- Members with write on the tag may add their own things (edge for the tag) or create tag-owned things in it.
- **Recursive by default**: sharing a tag shares everything reachable below it, a sub-tag that also hangs under a private tag included. "Items only" is the same operation without the edges on sub-tags: their contents stay unentitled and are not uploaded under T's label.
- **Only what you may share**: granting T an edge on a sub-tag or item needs admin on it (or an invite right). A tag or thing someone shared with me read-only, placed under my tag T, is not shared on when I share T; the client shows the tag's reach and what is excluded. This is the honest property the edge model gives over inherited folder ACLs; keep it.
- Unsharing: removing the last members of T; the edges on items may stay (harmless; T then reads nothing new). Removing an item: unplace (its tied edge follows).
- Cost: a few KB of secrets per item and sub-tag once, one lazy rotation per thing below the tag per roster change (owner accepted for tags in the thousands of items). A removal of one of my devices also rotates every shared item I own (notes/permissions.md Nesting cost). Rejected: an edge for T copied onto every item below (one edge per shared ancestor per item; add and remove must walk ancestors); per-item labels (N labels, N chain-certificate copies, N steps per removal: the case the usage rule warns about).

## Guideline for first-party apps (owner)
Adding a thing or a tag to a shared tag has significant privacy implications and gets a **confirmation** showing who will see it (as Drive does for moving into a shared folder). Same when sharing a tag that already has contents: show the reach. Not an API-level rule: the `osis` crate is used by apps and agents that know what they are doing.

## Logical documents
A thing made of parts (a presentation of slides) owns its parts and is a group of them; sharing it is one edge on the whole. Users never see this as a container; the only copy is an explicit ownership transfer. Apps must not depend on sharing parts individually.

## Other conventions settled
- Shared roots (a shared tag, a chat) are created unplaced and synced under their own label, not placed in the home group (notes/api.md `create`).
- "Shared with me": a foreign thing placed in a home-private group mirrors to all my devices through entitlement (I hold an edge). The home group should hold small person-private index things, not shared roots.
- Timestamps come from commits (`Osis::created`, commit `ts`), never from aspects.
- Files: `blob` plus a mime string on a file thing.

## Open
- Admin-only aspects on shared actors: a chat moderation question, not a tag one (writers may rename a shared tag, owner); issues/admin-only-aspects.md, decided with the chat redesign.
- Chat redesign (notes/chat.md, notes/std.md).
