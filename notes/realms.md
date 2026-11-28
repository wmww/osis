# Realms
> Summary: What a realm is and what is built. A realm is a thing marked `realm:realm^.0` (schema/realm.osis, no core rule): members are its holders; its grants and references behave by the general rules (nothing is "in" a realm for core); what an app shows as its contents is what it references. Every account is a realm, the person's home. osis-account's `Realm` makes and reads them; the decisions taken on the details.

## Tess's brief
Not chat-specific: "to actors what tags are to groups". User-visible, user-managed collections of permissions; actors stay an app tool nontechnical users never see. Joining gives access to what is in the realm: chats, documents, calendars, anything. Nesting, overlap, things in several realms and per-account roles must not be special features: they fall out of what osis has. Core judges none of it (Tess): a realm is an arrangement of ordinary things the schema describes and apps make; nothing stops a tag being a mint admin, a realm holding both nodes and accounts, or any other arrangement.

## The shape (built: schema/realm.osis, osis-account `Realm`)
- **A realm** is a thing with `realm:realm^.0` (its colour; admin-only) and usually `name.0`, minted with its keys (`create_with_keys`: it holds roles from the start) by `Realm::make(db, within, name)`: mint admin `within` (the person's account, or another realm), held from `within`'s `holds.0`, its setting retaining removed members' copies. A holder without the marker is app machinery (node, link key, client, a chat, a shared tag) and generic tools never list it as a realm.
- **Members** are R's holders, each with a role: read (sees), write (takes part, edits, adds to it), admin (manages members and details). A holder may be an account or another realm. Add by `grant` or a link on R, change by `set_role`, remove by `set_role` to `None` (retain or erase; R's default retains). The mint admin's edge is an ordinary admin grant: admins are equals.
- **Grants and references**: every combination of R's grants (on other things, and to its members) and its references behaves by the general rules (spec/sync-set.md §2, spec/permissions.md §1): a member's role on a thing R holds a role on is the minimum along the path, rights the maximum over paths. A grant to R holds nothing for anyone until something references the thing (or a signal names it); a strong grants nothing and removing one revokes nothing. Nothing is realm-specific.
- **An account is a realm**: A carries `realm:realm^.0`; its members are the person's nodes. It is **home**: what the person makes is minted with A as admin and held from A's `holds.0`, and the apps' per-person state (schema/ui.osis: favorites, the look, windows, collections) is on A. One per person, whatever the app. Letting someone into home is letting them into the account (everything A reads anywhere), so a space to share is another realm.
- **Profile and contacts are a realm's**: `realm:profile.0` names a public thing R holds, naming R back in `realm:of.0` and carrying R's card (its inbox), so whoever holds it may grant R roles; `Realm::contact_card` is a locator of it, `Realm::import_contact` redeems one for R and records it in `realm:contacts.0` (by realm), `Realm::profile_of` reads it back. Every account has a profile (`Account::make`); no other realm gets one yet (same steps as the account's: inbox, profile, card, public grant, when an app asks).
- **Contents** an app shows are what R references: the app's choice (a strong syncs a thing whole, a weak its stub). `Realm::make` (minted with `within`, referenced from `within`) is one convenient arrangement.

| property | existing feature |
|---|---|
| joining gives access | grant on R (`grant`, or a link on R and `redeem`); removal is `set_role` to `None`, with its rotation |
| any kind of thing | a grant to R on any thing, referenced from R; nothing is typed |
| nesting | R granted a role on K (both realms): R's members reach what K reaches at the path minimum; role cycles are allowed |
| a realm as a role inside another | K holds a role on R ("mods" holding admin): K's members act in R at that role |
| an account in two realms | two paths; leaving one keeps what the other gives |
| a thing shared with two realms | two grants on the thing; removing one leaves the other |
| per-account permissions | the member's role on R caps everything reached through R; finer splits are a sub-realm or a direct grant |
| no admin left | members keep reading and writing as granted |

## Decisions
- **Realm and tag are two markers**, not one aspect used two ways (Tess leaned to one concept unless a clear distinction exists). The distinction: a realm administers (a thing in it is minted with it as admin; it holds grants for its members), a tag collects (strongs in its `holds.0`, administers nothing, a grant per thing when shared). That is exactly what an app does differently when a thing is minted "in" it, so one aspect would need a field saying which. One thing may carry both; converting changes the marker and what an app does next, never the things already there (a mint admin is fixed in the tid). Whether users see one word for both is UX.
- **No account aspect.** Tess allowed "possibly an empty struct": nothing only accounts have needs one yet. A node's account is what its node root's `settings^.0` names while its node thing holds write or admin on it (`settings_thing`, `Account::of`; a removed node acts for none and may make another); its members are node things. Add one when an account-only setting appears.
- **Details admin-only, name by writers** (open questions 1, 2): the marker (and colour) is `^`, so a writer cannot un-realm or recolour it; the name is `name.0`, which every tool reads and writes, so writers rename as on a shared tag. An admin-only name would be a second name aspect: only if Tess asks.
- **Default role on joining: write** (taking part needs write); read for "viewer" invites. App UX: links and grants take the role.
- **Keep on removal** by default (R's setting `retain_copies`): an honest client cannot force erasure, and silent erasure of someone's own messages reads as data loss. Admins choose erase per removal. An account's node removal erases (`Account::remove_node`).
- **Serving**: a node that cannot read a realm keeps its sync ID as any other (spec/sync.md): nothing realm-specific.
- **Removal at depth 0**: removing a member rotates R in the removal commit; each thing R holds a grant on sealed its boxes to R's old keyset, which R's rotation lists as superseded, so its next writer rotates it before encrypting (notes/holder-actors.md). Nested realms cascade one level at a time. Depth 0's limit applies: an ignorant concurrent rotation of R lets the removed member read until R's next rotation that knows. Costs as for chats and shared tags: 2.7 KB per remaining holder for R, a few KB per thing below.

## Left for realm UX
- The management screen: name and colour; members with role (`holders`' `HolderKind::Thing` entries, each `Link` shown as an invite link; nodes and link keys are machinery); contents; sub-realms and the realms holding a role on R; who can see a thing through which realm (`holders`' `through`). First-party apps confirm before adding to a realm, showing who will see it (the tags guideline, notes/tags.md).
- A granter tells R's nodes of a grant by a grant signal on R's inbox (optional, spec/sync-inbox.md §5): a realm others grant into from outside needs a card and an inbox (a profile), as an account has.
- For big realms: pure readers placing nothing under big sync IDs (notes/chat-cases.md core r).

## Must not preclude
A realm being a tag too; realms administered by one account ("family", I stay admin) beside ones with several equal admins; things the realm is mint admin of beside shared-in things; realms holding roles on realms both ways; role cycles; links into a realm; retain or erase per removal.

## Chat under realms
A chat is a thing a realm holds write on or administers. A plain 1:1 or group chat is no realm; a server or an organization is a realm, a channel a chat in it, a mod role a realm holding admin on it or on some chats. What the app lists as R's channels is what R references; a chat app wanting categories, order or names of channels it has not synced keeps them in its own layout aspect on R.
