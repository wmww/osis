# Realms
> Summary: Design under discussion with Tess, nothing built or in spec, on hold until owners become first admins. A realm is an actor marked `realm.0`, as `tag.0` marks a group: members are its holders, what is in it is what it holds a grant on or is first admin of; access, nesting, overlap and per-account roles come from existing grants. Realms and tags may turn out to be one concept. Open questions at the end (notes/questions-for-tess.md Q5).

## Status of the discussion
Decided: members see the member list. Everything else is a proposal.
- **Realms and tags may be one concept** (Tess): unless a clear distinction exists they should be the same, called "tag" (different names only if users must ever see several kinds). "Group these notes on my home screen" and "a 100-person org with shared channels, calendars and documents" may be one concept with the same aspects and management screen, used differently. Both need both mechanisms: membership in the tag's group (what syncs) and grants to the tag's actor (what members may do). No counterexample found where users must understand two concepts. What a user does need are two settings: who is first admin of things made in it (me, or the tag, so they stay when I leave), and what syncs (a personal tag syncs everything; a big org syncs channels on demand, the default-off sync ask). "Add to tag" organizes on a private tag and also grants on a shared one: the confirm-before-sharing guideline covers it (notes/tags.md).
- **Tess's lean, not decided**: a realm is how things with no single owner reach users. Making a realm = making an organization you administer and can hand off (add an admin, step away). The distinction would be **owning vs collecting**: an account or a realm is first admin of things (access follows it; things made in a realm stay when a member leaves); a tag is a collection that organizes and, when shared, grants, and administers nothing. A realm may hold tags; its top tag can be its home. This removes the "who administers new things" setting (made in a realm = the realm is first admin).
- **Tied vs plain grants** (Q5.1): shared tags tie T's grant on an item to the item's membership in T's group (notes/tags.md, Sharing a tag), and membership is an ordinary edit, so any writer of T can unplace an item and so revoke everyone's access to it. Tess finds that too much power for a writer. Direction: plain grants; unplacing changes only what the tag shows; removing access needs an admin of the tag or of the thing.
- **Roles** (Q5.2): Tess wants at least edit details (admin), take part in chats and edit documents but not details (write), view (read). The path minimum gives it: the realm holds write on its contents, a member's role on the realm caps theirs. Gap: write on the realm's own thing lets a member edit its name and color; admin-only details need admin-only aspects (the `^` marker, spec/data-model.md §2). Finer cases (a read-only announcement channel, a private doc, a sub-team) are per-thing grants and nested realms.

## Tess's brief
Not chat-specific: "to actors what tags are to groups". User-visible, user-managed collections of permissions; actors stay an app tool nontechnical users never see. Joining gives access to what is in the realm: chats, documents, calendars, anything. Nesting, overlap, things in several realms and per-account roles must not be special features: they fall out of what osis has.

## The shape
- **A realm** is an actor thing with `realm.0` (usually `name.0` too). Nothing else marks it. Without `realm.0` an actor is app machinery (account, node, link key, client, a plain chat, a shared tag) and generic tools never list it.
- **Members** are R's holders, each with a role: read (sees), write (takes part, edits), admin (manages members and contents). A holder may be an account or another realm. Shown are accounts (read through their nodes, as `osis-chat` `members` does) and realms; other actors show as what they are ("invite link").
- **In the realm** is every thing R is first admin of or holds a grant on. A member's role on it is the minimum along the path (member's role on R, then R's role on the thing); rights are the maximum over paths (spec/permissions.md §1).
- **Seeing the contents**: grants naming R reach R's inbox, and R's admins copy them under R's label (`inbox_certificates`), so every member's node holds the list. Needed: an `osis` query "what does actor X hold a grant on, at which role" over held state (API only).
- **Its own label**: created like a chat root, synced under its own label, in no group (notes/tags.md, Other conventions). The label carries the roster, `name.0`, the copied grants and what is in R's group.
- **Sync of contents**: a thing with its own label (chat, calendar, large document) syncs under it. A small thing without one is also added to R's group so it travels under R's label (one label for many small things). Membership is only how it syncs; the grant is what puts it in the realm.

| property | existing feature |
|---|---|
| joining gives access | grant on R (`grant`, or a link on R and `redeem`); removal is `set_role` to `None`, with its rotation |
| any kind of thing | a grant to R on any thing; nothing in the realm is typed |
| nesting | R granted a role on K (both realms): R's members reach K's contents at the path minimum; K's own members stay K's. Role cycles are allowed |
| a realm as a role inside another | K holds a role on R ("mods" holding admin): K's members act in R at that role |
| an account in two realms | two paths; leaving one keeps what the other gives |
| a thing in two realms | two grants on the thing; removing one leaves the other |
| per-account permissions | the member's role on R caps everything reached through R; finer splits are a sub-realm or a direct grant |
| no admin left | members keep reading and writing as granted |

The management screen, and what each control writes:
- Name, color: `name.0`, `realm.0` on R.
- Members, with role: `roles.0` on R. Add: `grant` or a link. Change: `set_role`. Remove: `set_role` to `None` (retain or erase, from R's default). Leave: self-removal.
- Contents: R's grants. Add: grant R a role on the thing, needing admin or `may_grant` on it (only what you may share); add it to R's group too if it has no label. Remove: remove R's grant and unplace.
- Sub-realms and roles: realms R holds a grant on, and realms holding a grant on R.
- Who can see a thing, through which realm: `holder_path` and `reach`.
- First-party apps confirm before adding to a realm, showing who will see it (the tags guideline).

## Removal at depth 0
Removing a member rotates R in the removal commit. A group never looks inside its member actors (notes/crypto.md, Holder actors at depth 0): each thing R holds a grant on sealed its boxes to R's old keyset, which R's rotation lists as superseded, so those boxes go stale and each thing's next writer rotates it before encrypting. Nested realms cascade one level at a time. One commit protects new content everywhere; the rotations are lazy and per thing. Depth 0's limit applies: an ignorant concurrent rotation of R lets the removed member read until R's next rotation that knows. Costs as measured for chats and shared tags: 2.7 KB per remaining holder for R, a few KB per thing below.

## Realms and tags compared
| | tag | realm |
|---|---|---|
| marks | a group (`tag.0`) | an actor (`realm.0`) |
| is about | organization | permission |
| contents | membership (`group.0`) | grants to the realm, and what it is first admin of |
| who sees it | its reader; my tags of a shared thing never reach others | every member: roster and contents are shared |
| nesting | subgroups, a graph | grants between realms, a graph |

A shared tag is already an actor (notes/tags.md, Sharing a tag) and may also carry `realm.0`; one thing may be both.

## What chat no longer needs (an earlier chat realms design's "faction")
- **"A chat is a faction"**: a chat is a thing a realm holds write on or administers. A plain 1:1 or group chat is no realm; a server or team is a realm, a channel a chat in it, a mod role a realm holding admin on it or on some chats.
- **The directory aspect** (`faction:children.0^`): the contents list is R's grants. A chat app wanting categories, order or names of channels it has not synced keeps its own layout aspect on R.
- **Tied content**: a document in the realm is a grant to R; removing it from R's group does not revoke.
- **Chat core asks become realm asks**: default-off sync (a member chooses which of a realm's labels to sync; today a node syncs every label whose secret it holds) and pure readers placing nothing under big labels. Both matter more, since realms gather any number of things.

## Core changes
- `realm.0: struct { 0 color: option<string> }` in spec/data-model.md §9, default retention `author_or_admin`, typed key `osis::core::REALM`.
- `osis` query: grants held by an actor. Possibly a `create_realm` helper (actor, group, sync, in no group); otherwise apps compose it.
- For big realms: default-off sync and pure readers (notes/chat-cases.md core s, r).

## Must not preclude
A realm being a tag too; realms administered by one account ("family", I stay admin) beside ones with several equal admins; things the realm is first admin of (stay when their maker leaves) beside shared-in things (keep their admins, can be in several realms); realms holding roles on realms both ways; role cycles; links into a realm; retain or erase per removal.

## Open questions (recommendations)
1. **Tied or plain grants for contents**: plain. Removing a thing from a realm is a permission change, so only the thing's or R's admins do it.
2. **Roles**: as above; needs admin-only aspects on the realm thing.
3. **Who renames the realm**: writers, like shared tags, until admin-only details exist.
4. **Default role on joining**: write (taking part needs write, spec/requirements.md); read for "viewer" invites.
5. **Keep on removal**: keep by default, matching chat: an honest client cannot force erasure, and silent erasure of someone's own messages reads as data loss. Admins may choose erase per removal.
6. **Things created in a realm**: the realm is first admin (they stay when the maker leaves, like a team drive) rather than the maker sharing them in; things that already exist are shared in.
7. **No single owner by default**: a realm's admins are equals (today an ownerless actor); a realm one account controls is allowed too.
8. **Serving**: a realm's label is not taken by `admit own`; each realm needs a serving peer taking it by label or `admit open`, as chats do today. Leave this to the admission work.
