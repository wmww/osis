# Realms
> Summary: Design (awaiting Tess's go, nothing built or in spec): a realm is an actor marked user-facing by a core aspect `realm.0`, as `tag.0` marks a group. Members are its holders with their roles; what is in it is what it owns or holds an edge on. Access, any kind of content, nesting, overlap and per-person roles all come from existing grants. Replaces the chat-only "faction" (notes/chat-designs/e-realms.md). Open questions at the end.

## Tess's brief
Not chat-specific; "to actors what tags are to groups". User-visible, user-managed collections of permissions; actors stay an app tool nontechnical users never see. Joining gives access to what is in the realm: chats, documents, calendars, anything. Nesting, overlap, things in several realms and per-person roles must not be special features: they fall out of what osis has.

## The shape
- **A realm** is an actor thing with `realm.0` (and usually `name.0`). Nothing else marks it. Without `realm.0` an actor is app machinery (person, node, link key, client, a plain chat, a shared tag) and generic tools never list it.
- **Members** are R's holders (`roles.0` on R), each with a role: read (sees), write (takes part, edits), admin (manages members and contents). A holder may be a person or another realm. Shown are persons (read through their devices, as `osis-chat` `members` already does) and realms; other actors (a link's K) show as what they are ("invite link").
- **In the realm** is every thing R owns or holds an edge on. A member's role on it is the minimum along the path (spec/permissions.md §1): member's role on R, then R's role on the thing. Rights are the maximum over paths.
- **Seeing the contents**: grants naming R reach R's inbox, and R's admins copy them under R's label (`inbox_certificates`), so every member's node holds the list. Needed: an `osis` query "what does actor X hold an edge on, at which role" over held state (API only, no format change).
- **Its own label**: a realm is created like a chat root: an ownerless actor (by default), `make_group`, synced under its own label, unplaced (notes/tags.md Other conventions). The label carries the roster, `name.0`, the copied grants and whatever is placed in R's group.
- **Sync of contents**: a thing with its own label (a chat, a calendar, a large document) syncs under that label, which every member can open. A small thing without one is also placed in R's group, so it travels under R's label (one label for many small things, not one each). Placement is only the sync route; the grant is what puts it in the realm.

## How each property falls out
| property | existing feature |
|---|---|
| joining gives access | grant on R (`share`, or a link: `make_link` on R, `redeem`); removal is `demote` with its rotation |
| any kind of thing | an edge for R on any thing; nothing in the realm is typed |
| nesting | a grant of R on K (both realms): R's members reach K's contents at the path minimum; K's own members stay K's. Cycles are allowed (role cycles) |
| a realm as a role inside another | K holds a role on R ("mods" holding admin): K's members act in R at that role, admin passing only through admin |
| overlap: a person in two realms | two paths; leaving one keeps what the other gives |
| a thing in two realms | two edges on the thing; removing one leaves the other |
| per-person permissions | the member's role on R caps everything reached through R; finer splits are a sub-realm with its own grants, or a direct grant to the person |
| nontechnical management | the screen below maps to plain grants |
| no admin left | members keep reading and writing as granted (ownerless) |

The management screen, and what each control writes:
- Name, color: `name.0`, `realm.0` on R (writers, as for shared tags).
- Members, with role: `roles.0` on R. Add: `share` or an invite link. Change role: `change_edge`. Remove: `demote` (keep or erase, from R's default). Leave: self-removal.
- Contents, with what members may do with each: R's edges. Add: grant R a role on the thing, needing admin or invite on it (only what you may share, notes/tags.md); place it in R's group too if it has no label of its own. Remove: remove R's edge (the thing's admin, or R's admin as a self-removal) and unplace.
- Sub-realms and roles: realms R holds an edge on, and realms holding an edge on R.
- Who can see a thing and through which realm: `holder_path` and `reach`.
- First-party apps confirm before adding to a realm, showing who will see it (the tags guideline).

## Removal and the depth-0 rule
Removing a member rotates R in the removal commit. Under Tess's Q2 (a group never looks inside its member actors) each thing R holds an edge on sealed its boxes to R's old keyset; that keyset is now superseded, so those boxes are stale and the next writer of each thing rotates it before encrypting. Nested realms cascade the same way one level at a time. So one commit protects new content everywhere, the rotations are lazy and per thing, and nothing needs depth beyond 0. Q2's residual (an ignorant concurrent rotation of R lets the removed member read until R's next knowing rotation) applies unchanged. Costs as measured for chats and shared tags: 2.7 KB per remaining holder for R, a few KB per thing below.

## Realms and tags
| | tag | realm |
|---|---|---|
| marks | a group (`tag.0`) | an actor (`realm.0`) |
| is about | organization | permission |
| contents | placement (`group.0`) | edges for the realm, and what it owns |
| who sees it | its reader; my tags of a shared thing never reach others | every member: roster and contents are shared |
| nesting | subgroups, a graph | grants between realms, a graph |

A shared tag is already an actor (notes/tags.md Sharing a tag); it may also carry `realm.0`. The two markings are independent, and one thing may be both.

## What the faction design no longer needs
- **"A chat is a faction"**: gone. A chat is a thing a realm holds write on (or owns). A plain 1:1 or group chat is no realm. A server or team is a realm; a channel is a chat in it; a mod role is a realm holding admin on it or on some chats.
- **The directory aspect** (`faction:children.0^`): not part of the concept, since the contents list is R's edges. A chat app that wants categories, order or names of channels it has not synced keeps its own layout aspect on R, as tags leave order to apps.
- **Tied content**: a document in the realm is just an edge for R. Placement in R's group is only the sync route, and unplacing does not revoke.
- **Chat-specific core asks** become realm asks: default-off sync (a member chooses which of a realm's labels to sync; today a node syncs every label whose secret it holds) and pure readers placing nothing under big labels. Both matter more now, since realms gather any number of things.

## Core changes
- `realm.0: struct { 0 color: option<string> }` in spec/data-model.md §9, default retention `author_or_admin`, typed key `osis::core::REALM`.
- `osis` query: edges held by an actor. Possibly a `create_realm` helper (ownerless actor, group, sync, unplaced); otherwise apps compose it.
- Later, for big realms: default-off sync of a realm's things, pure readers (notes/chat-cases.md core s, r).

## Must not preclude
A realm being a tag too; person-owned realms ("family", I stay admin) beside ownerless ones; realm-owned things (stay with the realm when their maker leaves) beside shared-in things (keep their owner, can be in several realms); realms holding roles on realms both ways; role cycles; links into a realm; keep or erase per removal.

## Open questions for Tess
1. **Tied or plain edges for contents.** Recommend plain: removing a thing from a realm is a permission change, so only the thing's admins or R's admins do it. With tied edges (as shared tags), any writer of R could remove a thing by unplacing it.
2. **Member list visible to members.** It is by construction (the roster is under R's label). Recommend accepting it as stated; hiding it would need another shape.
3. **Who may rename the realm.** Recommend writers, like shared tags; admin-only names wait for issues on admin-only aspects.
4. **Default role on joining.** Recommend write (taking part needs write, spec/requirements.md); read for "viewer" invites.
5. **Keep on removal.** Recommend keep by default, matching chat: an honest client cannot force erasure, and silent erasure of someone's own messages reads as data loss. Admins can choose erase per removal.
6. **Things created in a realm**: owned by the realm (stay when the maker leaves, like a team drive) or by the maker and shared in (the maker stays its admin). Either can be granted to further realms. Recommend realm-owned by default, shared-in for things that already exist.
7. **Ownerless by default.** Recommend yes (no single owner; admins equal), with person-owned allowed.
8. **Hosts.** An ownerless realm's label is not taken by `admit own`; each realm needs a host taking it by label or `admit open`, as chats do today. Recommend leaving this to host admission work, not the realm design.
