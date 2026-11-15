# The reference graph: one plan for sync, holding, lifetime, invitations and storage
> Summary: Tess's design, decided with her except where marked open. Every reference is a strong, a weak or a ticket; a strong says "this belongs here" and grants nothing; a node holds exactly what its node root reaches by strongs, entering a thing with its own keys only by a ticket it can open; a thing is deleted when its last reference goes. Invitations become tickets posted to an account's inbox thing (a new lowest role, post). Removes retainers, release requests, synced groups, default filing, the group concept, inbox blobs, grant copies, the acted-on set and tied grants. Built after the account forks work, by demolition and rebuild on main, with less code and fewer, faster tests at the end.
> Priority: normal
> Tags: engine, sync, data-model, permissions, tess-call

## Status
- Comes after the account forks work (notes/account-forks-design.md) is done.
- Before demolition (Sextant): this plan, the spec rewrite, a model, research. On a branch, rebased once at the end. Then the active coordinator executes, starting with demolition (Execution).
- Open decisions and checks: last section. Everything else is decided (Tess).

## Principles (Tess)
- **A strong grants nothing.** It says the target belongs to this closure; anyone knowing a tid may write one. Permission is a separate act by someone who may grant, and removing a reference revokes nothing.
- **A thing is deleted when its last reference goes.** That is the intended result, never a risk to design around: no rule waits on an absent peer, and nothing is kept because a deletion might be a mistake.
- **Core holds only what cannot be built correctly on top of it.** Home, which invitations to accept, contact lists and "what is on my other nodes" are the app's.
- **Lean on osis for storing data.** Node and account state are ordinary things and aspects. No aspect is exempt from sync; what is local is local by where it sits.
- **One mechanism, reused.** A ticket is the one way to say "here is how to sync this", wherever it is stored.
- **Nothing grows only.** No set of everything ever seen, accepted or granted.

## Terms
- **tid**: a thing's ID. Never a value.
- **ref** (reference): a strong, a weak or a ticket inside a value.
- **strong**: a ref that makes its target part of the closure. **weak**: a ref that only points.
- **ticket**: a weak that also carries what is needed to sync its target (Tickets).
- **Own keys**: a thing with role secrets of its own, and so a sync ID. **Plain**: a thing without; its keys derive from where it was made.
- **Piece** of a thing T with own keys: T and the plain things reached from it (Pieces).
- **Closure** of a thing: it and everything reached from it by strongs, transitively. A closure is a set; the thing it is taken from is its **root**.
- **Node root**: the one local thing per node whose closure the node holds. **Node closure**: that closure. **Node thing**: the node's face to its account (keys, addresses); a different thing.
- **Account**: the identity (a key actor: signs, is granted roles, has no member list and no sync ID). **Account root**: the private thing beside it, read by the account's nodes only. **Profile**: name and dial addresses, read by contacts. **Inbox**: where others post to the account.
- **Home**: the app's, not core's: an ordinary thing a user's nodes may all hold.
- **Release**: a thing leaving a closure, and what holds it there dropping it. The one word; "unsync" is not a second term.
- **Post**: the lowest role (Post).
- **Tag**: the user-facing grouping, kept. `holds.0`: the core aspect that is a plain set of refs.
- Gone: group, subgroup, item, synced group, filing, shared here, retainer, release request, invitation as a core list, grant copy, acted, tied grant, devices (issues/deprecated-terms.md).

## Design
### References
- Three values, each its own CBOR tag; tag 1616 is retired and no value is a bare tid. Schema types `strong`, `weak`, `ticket`, and `ref` (a strong or a weak, the writer picks per value); the type `tid` goes. No default strength anywhere: encoding, API and schema each make the writer choose.
- Rust: `Strong`, `Weak`, `Ticket`, `Ref`. `Tid` converts into `Strong` and `Weak` with `.into()` and each converts back; a read returning a ref may return its `Tid`. A `ref` field makes `.into()` ambiguous, so the writer chooses.
- Types bind the local writer only (spec/versioning.md §5): a peer may write any ref where it may write, and nodes act on what is in the data.
- A strong and a weak to one tid are different values; a target is held when any strong to it counts. Schemas type map keys; no rule bars strong keys.
- **What counts**: every strong in the current state of a thing, in any aspect, at any depth and value size (issues/refs-in-chunked-elements.md), ephemeral aspects included while the value is held. History never counts. A signal has no current value, so a strong in a signal entry keeps nothing.
- **Index**: one index of every ref in data the node holds and may read, held signal entries included, with its kind. It serves the closure walk, the ticket lookup and backlinks. Backlinks list everything: no excluded aspect. Creation records and role records hold weaks.
- `osis://` links in text become weaks: issues/text-links-as-references.md (independent).
- `holds.0`: `set<ref>`, the plain container for the node root, the account root and tags. `tid.0` and `groups.0` stop being aspects (the API's calls stay).

### Pieces: what a sync ID carries
- T's piece: T, and each plain thing reached from T by strongs without passing through a thing with own keys. A plain thing T's keys cannot open is carried as a **leaf**: its own strongs are not followed.
- T's sync ID carries exactly T's piece. Every reader of T reads all the walk reads, so every reader computes the same piece.
- A thing with own keys is carried under its own sync ID and no other: always a boundary. (Today a subgroup its parent may read goes under both.)
- A plain thing is carried under every sync ID whose piece holds it, stored once per node. When a piece no longer holds it, holders of the delete key delete it there: gone for everyone under that sync ID. No plain thing is carried for being made under an actor.
- Making a thing: the commit must leave it strongly referenced from something in the node closure, or the write is refused. Nothing is filed by default.

### Holding and release
- The node root is local: it has no sync ID and nothing references it. It holds the node's strongs (`holds.0`), its settings, its ref to the account root, and what is local to a node today (`caps^.0`, `clients^.0`, the shared-here set as strongs).
- The node closure walks strongs. It enters a thing with own keys only where the node holds a ticket for it that it can open (found by tid in the index) or already holds its keys. With none the walk stops there: reading it is an error, nothing else is affected. With a ticket for the sync role only, the node stores the piece unread and the walk stops.
- Core gives sibling nodes no view of what a node holds. An app may publish a list of weaks.
- **Release**: a node drops what left its closure once the sync pass in flight with its connected peers has ended; with none connected, at once. It never waits for an absent peer. Its unsynced writes to a released thing go with it. A released thing is not destroyed: it may be fetched again where something references it.
- Purge and expiry are unchanged. Evidence of a destroyed thing is kept only while a held thing depends on it for authority (spec/commits.md §5 Destruction): the clauses for listed retainers and for references go.
- Limit, as today: in an admin dispute the sides differ on what is valid, and so on what belongs.

### Tickets
- A ticket holds: the target's tid, its sync ID, one secret of it (read, or sync for a holder that only stores) with its epoch, sealed to a named actor, and the issuer's profile tid. No addresses. About 150 B.
- It is a weak: it keeps nothing. It is ordinary data and works wherever the node holds it: an inbox entry, a message attachment, a document's source, the account root's ref to home.
- Only someone who may grant on the target can make one (the seal is to an actor holding a grant); anyone may copy one.
- **Accepting** is writing a strong to the target; the node finds the ticket. **Declining** is doing nothing, or deleting the ticket. There is no invitation list in core and no record of what was acted on.
- **Sharing Y with everyone who has X**: a grant giving X a role on Y, a ticket for Y sealed to X stored in X, and a strong. Three independent writes; nothing ties the grant to the strong.
- The profile tid in a ticket is a dial hint, never proof of the issuer: "invited by" is the verified author of the write that delivered it.
- Addresses live in one place per account, its profile's dial list. A node tries every connected peer for a sync ID it wants; a contact card is the one thing that carries addresses.

### Post and the inbox
- Roles: post < sync < read < write < admin. Post lets its holder fire signals marked `@` (as `my_signal@~0`; `@` is valid only with `~`) and nothing else: no read, no edit, no delete.
- A poster holds no read secret: its fire is sealed to the thing's public key and arrives as a deposit signed with the deposit key (the secret that comes with post), within the deposit budget. A writer's node promotes a valid one. To post one needs the thing's tid, sync ID, deposit seed and public key, and a node to deliver to.
- Every rule naming "a holder" or "any role" is read again with post in mind: a post-only holder never counts as one that may hold the data, see the member list or be waited for.
- **Inbox**: a thing per account, read by its nodes only, with two `@~` signals: arriving tickets, and removal notices (the signed removal; a node acts on it only after checking it against the member list it holds, then drops the thing or keeps a retained copy as the removal says). How long entries stay is the inbox's own history setting.
- **Contact card**: a link giving read on the profile and post on the inbox. An invitation from a stranger carries a ticket for the thing and one for the sender's profile.
- The account's things: the account root strongly references the profile, the inbox and the node things, and may hold a ticket to home.
- Storage budgets and rate limits are a separate project.

### What goes
- Spec: spec/requirements.md Terms (group, destroyed), the garbage-collection paragraph, the tied-grant sentence, "devices" at user level (Tess signs off the wording); spec/commits.md §5 Lifetimes and the release half of Destruction; spec/data-model.md §8, §9 (`group.0`, `groups.0`, `retainers^.0`, `released.0`, `synced^.0`, `acted^.0`, `kept^.0` where tickets replace it, the two never-logged aspects); spec/sync-set.md §1, §2, §4; spec/sync-inbox.md §2, §5; spec/permissions.md tied grants; the tid tag.
- Code: engine `retention/lifetimes.rs` and its rows, release paths in `retention/destroy.rs` and purge, `refs.rs` exclusions, `engine/groups.rs` as a group index; osis `Write::release`, `retaining`, `RETAINERS`, default filing, `Write::group`; osis-sync `life`, the inbox blob paths; held-model `lifetimes`; and every test of these.

### Storage
Every stored row hangs off something the node closure holds, a store entry of a sync ID it syncs, a peer record, or the node root; a row goes with its last owner. Releasing everything leaves the node root, the account root, the profile, the inbox and the node thing: nothing that grows with history. The audit of today's exceptions: issues/storage-follows-groups.md.

## Execution
Main may be broken for as long as this takes: nobody runs it. No small steps that keep things working, no long-lived branch.
1. **Spec first.** This plan and the rewritten spec sections land before code; a model beside them.
2. **Demolition**, one piece of work: delete everything under What goes and every test of it, including tests that could be ported. The tree only has to compile.
3. **Foundation**: one commit declaring the new types and empty modules, so the lanes do not collide.
4. **Rebuild in three lanes at once**, each one worker and one reviewer, committing to main: (a) ref and ticket values, schema, API and the index; (b) pieces, the node root, the closure walk and release; (c) post, the inbox, tickets in sync, removal notices. Then one agent brings app, kit and chat back.
5. **New tests last**, from the properties here: small and cheap, plus the count test of Storage.
6. **One gate**, at the end.

Rules:
- **No bridges**: no interim path, compatibility code or old thing kept until the new one works.
- **Less code**: `tools/loc.py` at 1d3d94ac7 reads 140,433 source and 120,784 test lines. Each step reports its change; both totals are lower at the end, or the work is not done.
- **Fewer and faster tests**: the default tests' count and CPU seconds are recorded before demolition; both are lower at the end.
- **"Group" is never renamed by search and replace.** Each use is read and becomes a closure, a piece, a tag, `holds.0`, or is deleted with what it described. Reviewers sample each outcome.
- About ten agents in all.

## Open
Decisions (Tess):
1. **A ticket whose secret is old.** An old secret alone opens nothing today: a reader behind catches up only by a peer opening on its role, and a holder that only stores gets each new key by its inbox. Proposed: keep both (a key change posts a fresh ticket to each holder that only stores and to a holder granted again after a gap); limit: a new node starts from an old ticket only where it reaches a peer that reads the thing. The alternative, sealed copies of new keys for every holder in the sync ID's own steps, is issues/one-open-proof.md.
2. **A node that only stores, and nested pieces.** With every thing with own keys a boundary, storing a closure unread needs a sync ticket for each piece in it, and such a node cannot read the parent to find them. Not yet asked.
3. **Reaching a thing's members.** Whoever changes a thing's keys or removes a member must post to that member's inbox, and may hold no contact card for it. Proposed: on accepting, a holder grants the thing post on its inbox, taken back on leaving. To model.
4. **Who posted.** A card holder's post is signed with the card's key, which says "someone with this card"; the sender's identity is signed inside the value. To design.

To check during the spec work:
- Whether `kept^.0` (the account's sync records) goes entirely with sync tickets.
- Whether reading a weak must tell "destroyed" from "not held".
- What "current" means for a role record in the index.
- The cost of removing a strong: a walk back from the target costs its fan-in while it is still held. Candidate: each held thing records one edge towards the root. Model.
- The requirements wording for Tess's sign-off.

Follow-ups, outside this plan: issues/links-as-tickets.md, issues/one-open-proof.md, issues/text-links-as-references.md, issues/refs-in-chunked-elements.md (needed by What counts).
