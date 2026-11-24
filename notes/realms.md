# Realms
> Summary: The design of realms, first pass done with Tess, nothing built or in spec; agents take it on (issues/realms-design.md). A realm is a thing marked `realm.0`, as `tag.0` marks a tag: members are its holders, what is in it is what it holds a grant on or is mint admin of; every account's home is one; access, nesting, overlap and per-account roles come from existing grants. Realms and tags may be one aspect used two ways.

## Status of the discussion
Decided: members see the member list. The rest is Tess's lean and proposals, enough to build from: what remains are tweaks.
- **Realms and tags may be one concept** (Tess): unless a clear distinction exists they should be the same, called "tag" (different names only if users must ever see several kinds). "Group these notes on my home screen" and "a 100-person org with shared channels, calendars and documents" may be one concept with the same aspects and management screen, used differently. Both need both mechanisms: strongs in the tag's `holds.0` (what syncs, within its sync unit) and grants to the tag (what members may do). No counterexample found where users must understand two concepts. What a user does need are two settings: who is mint admin of things made in it (me, or the tag, so they stay when I leave), and what syncs (a personal tag holds everything by strongs; a big org lists channels by weaks and each member's app holds the ones it syncs). "Add to tag" organizes on a private tag and also grants on a shared one: the confirm-before-sharing guideline covers it (notes/tags.md).
- **Tess's lean, not decided**: a realm is the inside view of an account: a place holding a body of things in ways users reach, with views over them. Every account is a realm (what the app calls home), an app may make one at setup, and users make more and add people to them: an organization you administer and can hand off is a realm whose members are accounts, a personal account a realm whose members are its signers (issues/actors-one-mechanism.md). The line against a tag stays unclear and may be only use: the core of both may be one aspect, realms carrying some extras whose shape comes later, apps showing them differently, and a thing converting from one to the other. Candidates for the extras: a profile (optional), and being externally grantable (issues/external-signals-taken-by-default.md). Open: whether a person's profile hangs on their home realm exactly as an org's does on its realm (Tess sees an elegance in it).
  - What separates them so far is **administering vs collecting**: a realm is mint admin of the things made in it (they are its dependents, cheap in any number, read by its readers, and stay when a member leaves); a tag collects things by strongs and, when shared, by a grant per thing, and administers nothing. A realm may hold tags; its top tag can be its home. This removes the "who administers new things" setting (made in a realm = minted with the realm as admin). Both mechanisms are open to any thing, so converting changes the marker and what an app does next, never the things already there (a thing's mint admin is fixed in its tid).
  - Tess: the mint-admin line is a convention apps are meant to follow, not a rule: nothing stops a tag being a mint admin, a realm holding both signers and accounts, or any other arrangement. Core judges none of it and decides no rule such as "may a realm have signers and accounts as members"; a home realm is one configuration among many that the schema describes and apps make and handle well. Everything minted with a realm being read by its readers is expected: a thing made there and then restricted, or a second realm for fewer people, are ordinary uses. Adding accounts to a home realm is not a normal thing to do, which is app UX. Adding to a tag needs write on the tag (whether making the tag a holder of the added thing needs its admin is open and unimportant: a member holds the tag's secrets, so it needs none of the tag's public keys either way).
  - **An account is a kind of realm** (Tess): an account aspect that generally sits on the same things as the realm aspect(s), holding whatever only accounts have (possibly an empty struct). What apps support well: an account's members are nodes, an account has no accounts as members, and some settings appear on accounts and on no other realm. Other arrangements stay possible.
  - **Home is the user's**: neither core's nor an app's. One per account, described by the schema, never one per app implementation; core cares only as far as it must.
  - **Can the account root go** (to establish in issues/actors-one-mechanism.md): it exists because an account is a key, which can hold no data, roster or sync ID, and that reason goes when an account is an ordinary independent thing. What stays true and must be stated: whoever holds a role on the thing that holds the account's roles reads everything the account reads anywhere (a role on M reaches what M holds). With account and home one thing, letting someone into home gives them all of that, so a space to share is another realm. Check for other reasons the two were apart (what today's profile and inbox being outside the root's sync unit relies on).
- **Plain grants** (Tess): a strong grants nothing and removing one revokes nothing (notes/node-closure.md Design rules), so a writer removing a thing's strong from a tag or realm changes what it holds, never who may read; removing access needs an admin of the tag or of the thing.
- **Roles** (Q5.2): Tess wants at least edit details (admin), take part in chats and edit documents but not details (write), view (read). The path minimum gives it: the realm holds write on its contents, a member's role on the realm caps theirs. Gap: write on the realm's own thing lets a member edit its name and color; admin-only details need admin-only aspects (the `^` marker, spec/data-model.md §2). Finer cases (a read-only announcement channel, a private doc, a sub-realm) are per-thing grants and nested realms.

## Tess's brief
Not chat-specific: "to actors what tags are to groups". User-visible, user-managed collections of permissions; actors stay an app tool nontechnical users never see. Joining gives access to what is in the realm: chats, documents, calendars, anything. Nesting, overlap, things in several realms and per-account roles must not be special features: they fall out of what osis has.

## The shape
- **A realm** is a thing with `realm.0` (usually `name.0` too) that holds roles. Nothing else marks it. A holder without `realm.0` is app machinery (account, node, link key, client, a chat, a shared tag) and generic tools never list it.
- **Members** are R's holders, each with a role: read (sees), write (takes part, edits), admin (manages members and contents). A holder may be an account or another realm. Shown are `holders`' `HolderKind::Actor` entries that hold R directly or through a link, with each `Link` shown as an invite link; nodes and link keys (`Key`) are machinery.
- **In the realm** is every thing R is mint admin of or holds a grant on. A member's role on it is the minimum along the path (member's role on R, then R's role on the thing); rights are the maximum over paths (spec/permissions.md §1).
- **Seeing the contents**: a grant naming R reaches R's nodes in R's key part where its writer writes R, else as an offer (`grant@~0`) on R (a thing that is no account is its own inbox, spec/sync-inbox.md §1, §5), kept as long as R's setting keeps that signal. A lasting list needs an aspect on R or an `osis` query "what does thing X hold a grant on, at which role" over held state (API only).
- **Its own sync ID**: made like a chat root, independent at creation and held by a strong (notes/tags.md, Other conventions). Its sync ID carries the roster, `name.0` and R's sync unit: what its `holds.0` strongly references that R reads.
- **Sync of contents**: a thing with its own sync ID (chat, calendar, large document) syncs under it. A small thing without one is also strongly referenced from R's `holds.0`, so it travels in R's sync unit (one sync ID for many small things). The strong is only how it syncs; the grant is what puts it in the realm.

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
- Contents: R's grants. Add: grant R a role on the thing, needing admin or `may_grant` on it (only what you may share), and a strong from R's `holds.0` if it is dependent. Remove: remove R's grant and the strong.
- Sub-realms and roles: realms R holds a grant on, and realms holding a grant on R.
- Who can see a thing, through which realm: `holders` (each entry's `through` path).
- First-party apps confirm before adding to a realm, showing who will see it (the tags guideline).

## Removal at depth 0
Removing a member rotates R in the removal commit. A thing never looks inside its holders (notes/holder-actors.md): each thing R holds a grant on sealed its boxes to R's old keyset, which R's rotation lists as superseded, so those boxes go stale and each thing's next writer rotates it before encrypting. Nested realms cascade one level at a time. One commit protects new content everywhere; the rotations are lazy and per thing. Depth 0's limit applies: an ignorant concurrent rotation of R lets the removed member read until R's next rotation that knows. Costs as measured for chats and shared tags: 2.7 KB per remaining holder for R, a few KB per thing below.

## Realms and tags compared
| | tag | realm |
|---|---|---|
| marks | a container (`tag.0`) | a holder (`realm.0`) |
| is about | organization | permission |
| contents | strong references (`holds.0`) | grants to the realm, and what it is mint admin of |
| who sees it | its reader; my tags of a shared thing never reach others | every member: roster and contents are shared |
| nesting | tags referencing tags, a graph | grants between realms, a graph |

A shared tag already holds roles (notes/tags.md, Sharing a tag) and may also carry `realm.0`; one thing may be both.

## What realms make unnecessary for chat
- **"A chat is a faction"**: a chat is a thing a realm holds write on or administers. A plain 1:1 or group chat is no realm; a server or an organization is a realm, a channel a chat in it, a mod role a realm holding admin on it or on some chats.
- **The directory aspect** (`faction:children^.0`): the contents list is R's grants. A chat app wanting categories, order or names of channels it has not synced keeps its own layout aspect on R.
- **Content by grant**: a document in the realm is a grant to R; removing its strong from R does not revoke.
- **Chat core asks become realm asks**: pure readers placing nothing under big sync IDs matters more, since realms gather any number of things.

## Core changes
- `realm.0: struct { color 0: option<string> }` in spec/data-model.md §9, default purge-by (`admin`), typed key `osis::core::REALM`.
- `osis` query: grants a thing holds. Possibly a `create_realm` helper (an independent thing, held by a strong); otherwise apps compose it.
- For big realms: pure readers (notes/chat-cases.md core r).

## Must not preclude
A realm being a tag too; realms administered by one account ("family", I stay admin) beside ones with several equal admins; things the realm is mint admin of (stay when their maker leaves) beside shared-in things (keep their admins, can be in several realms); realms holding roles on realms both ways; role cycles; links into a realm; retain or erase per removal.

## Open questions (recommendations)
1. **Roles**: as above; needs admin-only aspects on the realm thing.
2. **Who renames the realm**: writers, like shared tags, until admin-only details exist.
3. **Default role on joining**: write (taking part needs write, spec/requirements.md); read for "viewer" invites.
4. **Keep on removal**: keep by default, matching chat: an honest client cannot force erasure, and silent erasure of someone's own messages reads as data loss. Admins may choose erase per removal.
5. **Things created in a realm**: the realm is mint admin (they stay when the maker leaves, like a shared drive) rather than the maker sharing them in; things that already exist are shared in.
6. **No single controlling account by default**: a realm's admins are equals (a thing whose admins are its grants, the mint admin removable); a realm one account controls is allowed too.
7. **Serving**: a node that cannot read a realm keeps its sync ID as any other (spec/sync.md): nothing realm-specific.
