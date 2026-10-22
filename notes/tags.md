# Tags and the standard core aspects
> Summary: The user-facing organization layer decided with the owner: toplevel core aspects (`/name`, `/description`, `/icon`, `/tag`), tags as marked groups in a graph (not a tree), sharing a tag per item through one nested roster, recursive sharing semantics, the "only share what you may share" property, the confirmation guideline for first-party apps, the logical-document convention, costs, and what is still open. Proposal stage: not yet in spec/data-model.md §9 or core.osis.

## Direction (owner)
- No standard schema existed; the example apps minted four aspects for "name". The foundation should be settled before stabilizing.
- Generic aspects go toplevel in the core schema (single-segment AKs are the core schema, spec/data-model.md §2), not in a `/common` namespace.
- No `kind` aspect: what a thing is, is defined by its aspects, and a thing may be several kinds (ECS).
- No directory or folder concept (the tree was always too inflexible) except for interfacing with real filesystems. User-facing organization is **tags**: nestable as a graph, any thing can be in any tag, a bit of optional metadata over the existing group infrastructure. Not every group is a tag; internal application groups carry no tag metadata and are never shown.
- No user-visible "space". Moving a thing to another owner is a copy with a new tid, so users must never be expected to move things between containers; a share is per item, through one roster (below).
- Chat is deferred (fiddly, important to get right); notes/chat.md stands as built.

## Core revision 2 (proposed shapes, to confirm)
```
aspect /name: string;                 // what humans call the thing
aspect /description: markdown;
aspect /icon: struct { 0 emoji: option<string>, 1 image: option<tid> };   // image: a thing with a blob
aspect /tag: struct { 0 color: option<string> };   // marks a group as a user-facing tag
```
- `/tag` on a group thing makes it a tag; its items and subgroups are the tag's contents and sub-tags. Default retention `author`, no bounds, like `/group`.
- Ordering inside a tag is not core (apps keep their own order aspects where they need one); open.

## Tags
- A tag is a group thing with `/tag` and usually `/name`. Membership of a thing in a tag is placement (`/group.items`), nesting is `/group.subgroups`. Graph, cycles allowed, a thing or tag may be in many tags.
- Why placement and not a `/tags: set<tid>` on the thing: placement is written on the tag, so a reader can tag a thing it cannot write, and one person's tags of a shared thing never reach the thing's other readers. Each reader's tags are private by construction.
- Placement is also what syncs a thing (spec/requirements.md, Offline and network): a thing in no tag and no internal group stays local. Apps keep an internal synced group for "all my notes" or similar; tags are extra.
- Internal groups (buckets, app indexes) have no `/tag`; generic tools list only tags.

## Sharing a tag
Built from the mirrored-edges pattern of notes/permissions.md Patterns (examples/folder `add_mirrored`):
- The tag becomes an actor (secrets of its own, a label, a roster). Each direct item gets one edge for the tag's actor at the share's role or lower; a sub-tag gets the same edge and is made a shared actor itself if it is not one yet. Rights chain through membership edges (spec/permissions.md §1): a member of T reaches an item of sub-tag U by the path T → U → item, role = the minimum along it.
- Items keep tid and owner; an item in several shared tags has one edge per tag; moving between tags is an edge change, never a copy. Everything under the tag travels under the tag's one label (entitlement holds through the chain).
- Rosters nest: U's roster lists T as one member actor. Removing Bob from T rotates T, then lazily each sub-tag and item below it once (the cascade of spec/permissions.md §3), whatever the graph shape.
- Members with write on the tag may add their own things (edge for the tag) or create tag-owned things in it.
- **Recursive by default**: sharing a tag shares everything reachable below it, a sub-tag that also hangs under a private tag included. "Items only" is the same operation without the edges on sub-tags: their contents stay unentitled and are not uploaded under T's label.
- **Only what you may share**: granting T an edge on a sub-tag or item needs admin on it (or an invite right). A tag or thing someone shared with me read-only, placed under my tag T, is not shared on when I share T; the client shows the tag's reach and what is excluded. This is the honest property the edge model gives over inherited folder ACLs; keep it.
- Unsharing: removing the last members of T; the edges on items may stay (harmless; T then reads nothing new).
- Cost: a few KB of secrets per item and sub-tag once, one lazy rotation per thing below the tag per roster change (owner accepted for tags in the thousands of items). A removal of one of my devices also rotates every shared item I own (notes/permissions.md Nesting cost). Rejected: an edge for T copied onto every item below (one edge per shared ancestor per item; add and remove must walk ancestors); per-item labels (N labels, N chain-certificate copies, N steps per removal: the case the usage rule warns about).

## Guideline for first-party apps (owner)
Adding a thing or a tag to a shared tag has significant privacy implications and gets a **confirmation** showing who will see it (as Drive does for moving into a shared folder). Same when sharing a tag that already has contents: show the reach. Not an API-level rule: the `osis` crate is used by apps and agents that know what they are doing.

## Logical documents
A thing made of parts (a presentation of slides) owns its parts and is a group of them; sharing it is one edge on the whole. Users never see this as a container; the only copy is an explicit ownership transfer. Apps must not depend on sharing parts individually.

## Other conventions settled
- Shared roots (a shared tag, a chat) are created `Unsynced` and synced under their own label, not placed in the home group (notes/api.md `create`); the notes-app's notebook currently is placed in home and should follow.
- "Shared with me": a foreign thing placed in a home-private group mirrors to all my devices through entitlement (I hold an edge). The home group should hold small person-private index things, not shared roots.
- Timestamps come from commits (`Osis::created`, commit `ts`), never from aspects.
- Files: `blob` plus a mime string on a file thing (examples/folder's `/folder/content: string` is wrong for binary).

## Open
- Confirm the shapes above, then: spec/data-model.md §9 and core.osis revision 2, `osis::core` constants, an API helper for "share tag" / "add to shared tag" (writes placement and edge together; the helper notes/sync.md Why already asks for), examples/notes-app and folder moved onto `/name` and tags.
- Admin-only aspects on shared actors (tag settings today, chat moderation later): issues/admin-only-aspects.md (owner-call).
- Order inside a tag; whether `/icon.image` should be a tid or an inline small blob.
- Chat redesign (notes/chat.md) after tags land.
