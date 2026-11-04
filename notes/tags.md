# Tags and the standard core aspects
> Summary: The user-facing organization layer decided with Tess: toplevel core aspects (`name.0`, `body.0`, `tag.0` in the core schema), tags as marked groups in a graph (not a tree), sharing a tag per item through one nested roster, recursive sharing semantics, the "only share what you may share" property, the confirmation guideline for first-party apps, the logical-document convention, costs, what examples/tags and notes-app show, and what is still open.

## Direction (Tess)
- No standard schema existed; the example apps minted four aspects for "name". The foundation should be settled before stabilizing.
- Generic aspects go toplevel in the core schema (single-segment AKs are the core schema, spec/data-model.md §2), not under a `common:` first segment.
- No `kind` aspect: what a thing is, is defined by its aspects, and a thing may be several kinds (ECS).
- No directory or folder concept (the tree was always too inflexible) except for interfacing with real filesystems. User-facing organization is **tags**: nestable as a graph, any thing can be in any tag, a bit of optional metadata over the existing group infrastructure. Not every group is a tag; internal application groups carry no tag metadata and are never shown.
- No user-visible "space". A thing never changes owner, so users must never be expected to move things between containers; a share is per item, through one roster (below).
- Chat is notes/chat.md: an ownerless actor, not a tag.

## Core aspects (spec/data-model.md §9, core.osis)
```
aspect name.0: string;                 // what humans call the thing
aspect body.0: markdown;                // freeform content: a note's text, notes on anything
aspect tag.0: struct { 0 color: option<string> };   // marks a group as a user-facing tag
```
- No `icon.0` for now (Tess): added when an app needs it. Typed keys `osis::core::{NAME, DESCRIPTION, TAG, Tag}`.
- `tag.0` on a group thing makes it a tag; its items and subgroups are the tag's contents and sub-tags. Default retention `author_or_admin`, no bounds, like `group.0`.
- No order or position inside a tag in core (Tess): apps keep their own, since one wants a list, another a 2D canvas position.

## Tags
- A tag is a group thing with `tag.0` and usually `name.0`. Membership of a thing in a tag is placement (`group.0` items), nesting is `group.0` subgroups. Graph, cycles allowed, a thing or tag may be in many tags.
- Why placement and not a `tags.0: set<tid>` on the thing: placement is written on the tag, so a reader can tag a thing it cannot write, and one person's tags of a shared thing never reach the thing's other readers. Each reader's tags are private by construction.
- Placement is also what syncs a thing (spec/requirements.md, Offline and network): a thing in no tag and no internal group stays local. Apps keep an internal synced group for "all my notes" or similar; tags are extra.
- Internal groups (buckets, app indexes) have no `tag.0`; generic tools list only tags.

## Sharing a tag
Built from the mirrored-edges pattern of notes/permissions.md Patterns with **tied grants** (spec/permissions.md §2); core/osis/tests/it/tags.rs and tied.rs build it (`share_into`, `new_sub_tag`, `unplace`):
- **The operation** (Tess, round 13: tied grants over "placement grants access"; explicit; the "no helper" rule withdrawn for it; eventual removal accepted): `db.share_into(T, G, role, ShareOpts { subgroup, place_anyway })` places T and writes G's edge on T tied to that placement (the `group.0` element's creation stamp and set; an existing tied edge whose element is dead here is tied again to the new one); plain `place` never shares. `unplace`/`remove_subgroup` remove the tied edge right after when that is a self-removal (admin on G only); else node-sync's obligation (`SyncEngine::untie_unplaced`) removes it at a node that holds the named element dead (a tombstone, or absent under a later reset of the set, struct or aspect, or absent with its own commit held invalid) and may (explicit by T's admin, after the pre-sync passes; self-removal by G's admin), like link finalization. Known limits: a dead element revives only by un-merge (the edge stays removed); a value-less copy from a snapshot of an expiring placement reads dead before its T; an edge whose placement never leaves its writer (device lost between the two uploads) stays until removed by hand (`reach` shows `placed: false`); a re-tie racing another node's removal of the old tie can lose (the placement stays, excluded). An element not held yet is on its way: the edge may arrive first (two commits, separate uploads), so no pass count proves the placement gone; the named element does. One way: a placement without an edge re-grants nothing; an untied (hand) edge survives an unplace. `db.remove_edge_of(G, T)` is G's admin's self-removal; `db.reach(T)` lists per group `Tied`/`Untied`/`Excluded` and tied edges whose placement is gone.
- Why not "placement grants access" (rejected): the rights record would leave the thing, so T's admins could no longer see or revoke shares (Alice places her note in Bob's tag, Bob removes Alice: she can no longer unplace, nothing on the note stops it); placements would become rights writes in the timeline; readers may tag what they cannot write.
- Why not one commit for placement plus edge (the issue's first plan): a mixed-kind commit touches commit validation, retention, compaction, projection and undo, and a role commit applies partially at a receiver anyway (spec/commits.md §4), so it buys no receiver-side atomicity. Two commits in one local operation (placement first: a crash leaves "placed, excluded", safe; the edge names the placement's element, so its arrival order does not matter). The first version waited for a complete pass of G's labels instead; the edge could still arrive first and be removed (review repro, now `tied::edge_before_placement_is_not_removed`).
- A removal of G's edge (explicit or self-removal) goes under the labels holding G that its author syncs (`Delivery::Removal` from `demote_in`), without the commit's `secrets.0` and `keys.0` (an explicit removal's rotation boxes, and the target's refreshed deposit seed, which G's holders must not read): the target may be out of G's closure after an unplace, and its bodies leave G's label once G reads it no more, so without it G's holders never learnt the removal (and holders still holding the edge re-upload the target's bodies that the others delete: a storm). G's inbox is its owner's home label, which only G's admins read; they copy what it brings for G under G's own label (`inbox_certificates`), so G's other holders learn grants and removals sent only to the inbox. An author that syncs no label holding G and holds no `keys.0` of G (an admin of the target through another tag H) sends neither; then any node that applied the removal and syncs G's label places it there after `SETTLE_MS` (`Engine::removal_certificates`, from `certificates`; T in G's closure only, `roles.0` and `tenures.0` only: T's newest `keys.0` is usually the removal's own, with the fresh deposit seed). Without it a G admin who learnt it through H deleted T's bodies under G as `Outside` and G's holders that had not re-uploaded them on every pass (about 2.6 KB per pass for a one-line card, the whole thing for a large one; `tied::group_admin_learns_removal_elsewhere`). Nobody in G learning it at all is stale but consistent.
- The tag becomes an actor (secrets of its own, a label, a roster). Each direct item gets one edge for the tag's actor at the share's role or lower; a sub-tag gets the same edge and is made a shared actor itself if it is not one yet. Rights chain through role grants (spec/permissions.md §1): a holder on T reaches an item of sub-tag U by the path T → U → item, role = the minimum along it.
- Items keep tid and owner; an item in several shared tags has one edge per tag; moving between tags is an edge change. Everything under the tag travels under the tag's one label (entitlement holds through the chain).
- Rosters nest: U's roster lists T as one holder actor. Removing Bob from T rotates T, then lazily each sub-tag and item below it once (the cascade of spec/permissions.md §3), whatever the graph shape.
- Holders of write on the tag may add their own things (edge for the tag) or create tag-owned things in it.
- **Recursive by default**: sharing a tag shares everything reachable below it, a sub-tag that also hangs under a private tag included. "Items only" is the same operation without the edges on sub-tags: their contents stay unentitled and are not uploaded under T's label.
- **Only what you may share**: granting T an edge on a sub-tag or item needs admin on it (or an invite right). A tag or thing someone shared with me read-only, placed under my tag T, is not shared on when I share T; the client shows the tag's reach and what is excluded. This is the honest property the edge model gives over inherited folder ACLs; keep it.
- Unsharing: removing the last holders of T; the edges on items may stay (harmless; T then reads nothing new). Removing an item: unplace (its tied edge follows).
- Cost: a few KB of secrets per item and sub-tag once, one lazy rotation per thing below the tag per roster change (Tess accepted for tags in the thousands of items). A removal of one of my devices also rotates every shared item I own (notes/permissions.md Nesting cost). Rejected: an edge for T copied onto every item below (one edge per shared ancestor per item; add and remove must walk ancestors); per-item labels (N labels, N chain-certificate copies, N steps per removal: the case the usage rule warns about).

## Guideline for first-party apps (Tess)
Adding a thing or a tag to a shared tag has significant privacy implications and gets a **confirmation** showing who will see it (as Drive does for moving into a shared folder). Same when sharing a tag that already has contents: show the reach. Not an API-level rule: the `osis` crate is used by apps and agents that know what they are doing.

## Logical documents
A thing made of parts (a presentation of slides) owns its parts and is a group of them; sharing it is one edge on the whole. Users never see this as a container. Apps must not depend on sharing parts individually.

## Other conventions settled
- Shared roots (a shared tag, a chat) are created unplaced and synced under their own label, not placed in the home group (notes/api.md `create`).
- "Shared with me": a foreign thing placed in a home-private group mirrors to all my devices through entitlement (I hold an edge). The home group should hold small person-private index things, not shared roots.
- Timestamps come from commits (`Osis::created`, commit `ts`), never from aspects.
- Files: `blob` plus a mime string on a file thing.

## Open
- Admin-only aspects on shared actors: a chat moderation question, not a tag one (writers may rename a shared tag, Tess); issues/admin-only-aspects.md, decided with the chat redesign.
