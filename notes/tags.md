# Tags and the standard core aspects
> Summary: The user-facing organization layer decided with Tess: toplevel core aspects (`name.0`, `body.0`, `tag.0` in the core schema), tags as things whose `holds.0` references what they tag, in a graph (not a tree), sharing a tag per item through one nested roster, recursive sharing semantics, the "only share what you may share" property, the confirmation guideline for first-party apps, the logical-document convention, costs, other conventions.

> In discussion: tags and realms may become one concept, or realms the user face of actors that are first admins while tags collect; see notes/realms.md "Current state of the discussion".

## Direction (Tess)
- Generic aspects go toplevel in the core schema (single-segment AKs are the core schema, spec/data-model.md §2), not under a `common:` first segment.
- No `kind` aspect: what a thing is, is defined by its aspects, and a thing may be several kinds (ECS).
- No directory or folder concept (the tree was always too inflexible) except for interfacing with real filesystems. User-facing organization is **tags**: nestable as a graph, any thing can be in any tag, a thing with `holds.0` and `tag.0` (spec/data-model.md §8). Not every `holds.0` is a tag; internal application containers carry no `tag.0` and are never shown.
- No user-visible "space". A thing never changes tid, so users must never be expected to move things between containers; a share is per item, through one roster (below).
- Chat is notes/chat.md: an actor made by its record, not a tag. Shared permission collections are realms (notes/realms.md): `realm.0` marks an actor as `tag.0` marks a container.

## Core aspects
`name.0`, `body.0`, `tag.0`: schema/core.osis.
- No `icon.0` for now (Tess): added when an app needs it. Typed keys `osis::core::{NAME, BODY, TAG, Tag}`. Writers may rename a shared tag (Tess).
- No order or position inside a tag in core (Tess): apps keep their own, since one wants a list, another a 2D canvas position.

## Tags
- A tag is a thing with `holds.0` and `tag.0`, and usually `name.0`: what it tags is what its `holds.0` references (spec/data-model.md §8), nesting is a tag referencing a tag. Graph, cycles allowed, a thing or tag may be in many tags.
- Why references on the tag and not a `tags.0: set<tid>` on the thing: they are written on the tag, so a reader can tag a thing it cannot write, and one account's tags of a shared thing never reach the thing's other readers. Each reader's tags are private by construction.
- A strong in a tag grants nothing (spec/permissions.md §1): whether a tagged thing syncs with the tag is its sync unit's rule (spec/sync-set.md §2).
- Internal containers (buckets, app indexes) have no `tag.0`; generic tools list only tags.

## Sharing a tag
- Sharing a tag shares its sync unit, never what it only references: to share a tag of notes made under home, the app grants the tag a role on each note (when the tag is shared, and for each note added later); `NotCarried` names each one missed (issues/reference-graph.md, Sync units). A call doing that sweep is the API's to consider (notes/api-design.md).
- The tag becomes an actor (secrets of its own, a sync ID, a roster). Rights chain through role grants (spec/permissions.md §1): a holder on T reaches an item of sub-tag U by the path T → U → item, role = the minimum along it.
- Rosters nest: U's roster lists T as one holder actor. Removing Bob from T rotates T, then lazily each sub-tag and item below it once (the cascade of spec/permissions.md §3), whatever the graph shape.
- **Only what you may share**: granting T a grant on a sub-tag or item needs admin on it (or `may_grant`). A tag or thing someone shared with me read-only, added to my tag T, is not shared on when I share T; the client shows the tag's reach and what is excluded. This is the honest property the grant model gives over inherited folder ACLs; keep it.
- Cost: a few KB of secrets per item and sub-tag once, one lazy rotation per thing below the tag per roster change (Tess accepted for tags in the thousands of items). A removal of one of my nodes also rotates every shared item I own (notes/keys-rotation.md Nesting cost).

## Guideline for first-party apps (Tess)
Adding a thing or a tag to a shared tag has significant privacy implications and gets a **confirmation** showing who will see it (as Drive does for moving into a shared folder). Same when sharing a tag that already has contents: show the reach. Not an API-level rule: the `osis` crate is used by apps and agents that know what they are doing.

## Logical documents
A thing made of parts (a presentation of slides) is first admin of its parts and references them strongly; sharing it is one grant on the whole. Users never see this as a container. Apps must not depend on sharing parts individually.

## Other conventions settled
- Shared roots (a shared tag, a chat) get their own keys at creation and are held by ticket (issues/reference-graph.md, Sync units).
- Timestamps come from commits (`Osis::created`, commit `ts`), never from aspects.
- Files: `blob` plus a mime string on a file thing.
