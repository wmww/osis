# Permissions and revocation
> Summary: Permission model (actors, membership on any thing, ownership; sharing within the owner's tree and verification via labeled membership commits decided 2026-10-11, hand-over only for moving out of it) and write revocation vs. concurrent offline edits (receipt-time rule, accepted by owner 2026-09-29, details proposal), with rejected alternatives and costs.

## Model (2026-09-29; proposal unless marked decided)
Owner's direction: a small set of concepts that compose; hierarchical; keys for nodes, actors and other scopes; private keys wrapped to a target to grant access; a set of things shared with a changing set of actors must be managed in one place; nested actors (e.g. tess -> tess-human, tess-agent) should be possible but not baked in. Spreadsheet and group chat differ, but both are many things whose permissions change together.

Three concepts:
- **Actor**: a thing with role secrets (and a signing key for key actors). Any thing becomes one when it needs members of its own: nodes, people, agents, teams, shared documents/chats, a single shared note. Identity is the tid, so keys can rotate. A node is a leaf actor whose private key never leaves the device.
- **Membership**: edge member actor -> thing with a role (read < write < admin), written by an admin of the target (for a plain thing: an admin of its owner). Target an actor: rights on everything it owns. Target a plain thing: rights on that thing only. Actors can be members of actors; effective role is the minimum along the chain. Nesting and "node acts for person" are the same edge.
- **Ownership**: every thing has exactly one owner actor, fixed by its tid; rights on the thing are rights in its owner plus the edges written on the thing itself. A shared doc is one actor owning all its things, so access changes in one place.

Vocabulary: read, write (editor) and admin are roles a member holds in an actor. Admin = write + change the actor's membership + transfer things it owns. Owner is not a role: it is which actor a thing belongs to. An actor's owner is another actor, so "alice owns P" is literal.

Top of an actor = its owner (decided by owner 2026-09-29). No new concept: an actor is a thing, so it has an owner actor like any other thing.
- An actor's owner is implicitly its admin, and the only one its other admins cannot remove. Handing over an actor works like any thing (Hand-over, below).
- The chain ends at a key actor (node or recovery key), which owns itself; its tid commits to its public key.
- Other admins are equals: any of them can add or remove members, including each other. If two remove each other both removals apply and the owner restores whoever should stay. A hostile admin is out of scope in the same way a hostile writer is; the owner is the recourse.
- UX vocabulary stays the familiar one: owner, admins, editors, viewers.
- Rejected: seniority ranking of admins (total order, remove only juniors). Handles disputes among non-top admins without the owner, but the ranking is unintuitive and would leak into UX (owner's objection).
- Conflicts between nodes acting for the same actor are ordinary merges (latest write wins): both are trusted members, so their clocks are too. Only a hostile node (stolen device) matters, and that is a removal from the person actor, which its owner can always do.
- So a person actor's owner should be a recovery key kept offline, with devices as admins: a stolen owner device wins everything, a lost one leaves nobody able to overrule the admins. Policy for apps, not protocol; to the protocol a recovery key is just another node actor.

## Sharing within the owner's tree (decided by owner 2026-10-11)
Sharing never changes a tid. Resolves the former issue "share existing thing".
- Edges on plain things (above). Bob gets write on note N owned by Alice's actor A: an admin of A writes "Bob: write" on N. Verification chain: Bob's node -> Bob -> edge on N -> A owns N (tid).
- Role secrets per thing: by default derived by KDF from the owner's secrets and the tid, so nothing is stored and owner members derive them. Once a thing has a non-owner member it gets explicit random secrets, wrapped to the owner and each member, so owner rotation does not cascade. A group thing with secrets is a sync label its members can use (notes/sync.md).
- Content: every blob has its own random key, wrapped under the read secret of each label it is uploaded under (notes/sync.md). Sharing history means adding wraps, never re-encrypting.
- One note: edge on N, explicit secrets on N, N is its own label. A set: a group thing with members and secrets (the "shared with Bob" folder), one edge per thing naming it, written in one commit. A set meant to be shared as a unit is better created under a common owner (shared-owner pattern).
- Why no tid change: the double-spend harm of a transfer is the former owner pulling the thing back. Moving a thing to an actor the owner owns has no such harm, so it is an ordinary write on the thing; the edge is the additive form of that write (a move would also drop A's own writers). Hand-over with a new tid remains only for moving a thing out of its owner's tree, which should be rare.
- Rejected: an actor per thing at creation (usage rule, doubles the thing count, does not cover existing things); a membership edge on a group thing extending to its contents (groups are an app tool and must carry no permission meaning); a grant-set thing listing shared tids (a verifier could only check N's writes after syncing the set; an edge on N travels with N); per-thing derived content keys plus an encrypted hint per blob and label (about 24 bytes cheaper than a wrap, loses crypto-shredding per blob and add-a-wrap sharing; a drop-in change if the wrap ever matters).

## Verifying writes without reading membership (decided by owner 2026-10-11)
Problem: checking a write on N needs the current membership of N's owner and of every actor above it up to the key actor, and of the author's own actors below; only members can read those aspects, and non-members do not sync their labels. So a grantee or a chat reader could neither verify writes nor learn of revocations, and nodes would diverge.

Resolution: the signed membership commits are the certificates; they travel under the labels where they are needed. No verify role, no certificate format, no extra key.
- Membership writes (grant, revoke, demotion, receipt statement) always get their own commit, never shared with other aspects of the actor, so a membership commit can sit under extra labels without exposing anything else. Internal rule like "one owner actor per commit"; apps never see it.
- When a node uploads under label L it also puts the membership commits proving its own chain under L: its edge into its person actor, that admin's edge into the owner, and so on up to the key actor. One extra wrap per blob, deduped by blob ID, so the cost is once per (node, label), not per commit (notes/sync.md, Labeling).
- Revokes and statements follow the same rule: any member who syncs L and holds one about an author seen under L adds the wrap. A grantee with write on N is an authorized actor for N, so its receipts count as witness statements for N.
- Chain checks need no secrets: each link is a node signature plus a tid committing to its owner, ending at a key actor whose tid commits to its public key. Readers of L decrypt with L's read secret; blind nodes see opaque blobs.
- A commit whose author chain has not arrived is held unverified until it does; same pending state as an out-of-order delta.

Leaks: a reader of L learns the chain of every author under L and the witness nodes that publish statements about them, never rosters. Author identity is inherent anyway (every write is node-signed, the receipt-time rule needs it).

Accepted limits: revocation reach is eventual (if no member of the revoking actor syncs L again, L's readers keep accepting the revoked node until one does, then un-merge); chain depth equals nesting depth (node -> person -> recovery key is two blobs, each org level adds one).

Rejected: a "verify" role whose key is handed out transitively with every edge (an outside collaborator on one note learns the team's and the company's full membership; every rotation above re-wraps to everyone below); per-commit certificate chains (a few hundred bytes per commit against a 200-byte floor; the same data is cheaper as labeled commits).

Hand-over (2026-09-29). Decided by owner:
- Ownership is immutable: an owner whose thing can be pulled or destroyed by a former owner is not really the owner. A former owner can always sign a second, competing transfer (double-spend; no fix without consensus), so a transfer must never be able to harm what the new owner holds.
- Hand-over must be cheap and must keep history (attribution, edit history, late edits). So not copy/re-create.

Lazy hand-over (owner 2026-09-29: "sounding better, if it will work"; from owner's "acting owner" idea). Data never moves; names change.
- Transfer record: names the record it follows (creation record or previous transfer) and the new owner; signed by an admin of the owner that record names. Stored on the thing. No timestamps.
- Permanent tid = hash(old tid, transfer record): "the thing as handed to X". X owns it immutably; a competing transfer hashes to a different tid and cannot touch it.
- Alias rule: the old tid resolves to the permanent tid while exactly one transfer follows the record. Deterministic and monotone, so it converges.
- Things owned by a handed-over actor are untouched; their owner resolves through the alias. Things created afterwards commit to the permanent tid directly.
- Fork (a second transfer follows the same record): the old tid dangles for good; each branch continues under its permanent tid. Things the actor owned get derived tids the same way, hash(tid, transfer record), computed locally. A node keeps the branch it follows and never stores the other unless something it tracks refers to it.
- Resolution of an old tid after a fork (proposal, generalising owner's rule "if someone has a valid claim to own a thing and other things they own refer to it, they mean the version they think they own"): walk up the owner chain of the thing holding the reference; if it has standing (owner, or member added after the hand-over) in exactly one branch, resolve to that branch. Covers things inside the branch and the claimant's own things elsewhere, with no rewriting. Standing in both or neither: the reference dangles. References using the permanent or derived tid are unaffected. May not be a sufficient decider; "someone" is deliberately loose.
- Writes are judged against the membership data of the branch a node follows. Members who predate the fork are valid in both branches; commits need not name a branch.
- Former owner's power: break outside links that still use the old tid. Cannot read new content, write, take over or destroy. Two honest nodes handing over to different targets give two things, not a loss.
- Rotating the key at the end of a person's chain is an ordinary hand-over of the person actor.
- Reference rewriting (decided by owner): after a hand-over, nodes rewrite old tids to permanent/derived ones in data they may write, shrinking what a later fork can break. When (at hand-over, on read, on write) is undecided and not urgent. Owner wants links inside markdown tracked and updated too (`osis://` prefix makes them findable; rewrite = text splice).
- Hand-over is therefore somewhat expensive (rewrites spread over every referencing thing, a name index per owned thing, and edge cases from a thing changing tids). Guidance for app design (owner): hand over only to move a thing out of its owner's tree. Sharing uses edges and membership (Sharing within the owner's tree, above).
- The new owner's members must be able to read old content: wrap the handed-over actor's read secrets (all epochs) to the new owner; for a single thing, add wraps for its blobs under the new owner's labels (no re-encryption; notes/sync.md).
- Backlink index per node (owner's idea): which things refer to which, over typed tids and markdown links. Serves rewriting and generic backlinks.
- Needs spec: derived-tid index (local, one hash per owned thing per hand-over or on fork), branch-relative resolution, chains of several hand-overs.
- Risks to settle before calling it decided:
  - A thing can have several tids (original, one per hand-over). Leaks into the API only for identity comparison of tids an app kept from earlier; lookups resolve implicitly (notes/api.md).
  - Split at birth: the former owner hands over to two targets at once and shows each to different members. No node can tell which is legitimate. Decided by owner: no loud report, a fork is something that can really happen and a peer can cause it; handled by the resolution rules, plus an event on the diagnostics channel (notes/api.md).
  - After a fork, a node rewrites its own still-aliased references to the branch it was following; that is an ordinary write, so a user's devices converge by normal merge.
- Rejected: copy/re-create under the new owner (loses history, cost proportional to size, owner's objection); fork deletes the thing (every former owner keeps a kill switch); picking a winner (former owner takes over); first-seen-wins per node on one tid (no convergence); finality by members' receipt time (no neutral witness when a thing has no members, symmetric claims); references always tagged with the owner (every hand-over breaks references).

Mechanism splits by direction (decided by owner):
- Write: signatures plus membership chain. A node always signs with its own key. Sharing an actor's private signing key is rejected: it erases which member wrote (the revocation rule needs the author) and makes every removal a key rotation.
- Read: key wrapping, as the owner described. An actor's read secret is wrapped to each member; each blob's own key is wrapped under the read secret of every label it sits under (notes/sync.md). Removal rotates the secret, lazily (old content was already readable).
- Per-role keys (proposal 2026-10-11): an actor has one secret per role (read, write, admin), each wrapped to the members holding that role or higher. Label keys derive from them, so blind nodes can distinguish roles by signature (notes/sync.md, Authorization). Demotion or removal rotates the affected secrets, lazily.

Owner: a tid commits to its owner by hash (self-certifying tids, decided, notes/data-model.md).

Falls out:
- Grant/revoke are ordinary writes to the actor thing, judged by the receipt-time rule like any other write.
- Keyed hashes use a per-thing dedup secret derived from the thing's creation nonce, so every reader hashes identically and sharing changes nothing (notes/crdt-sync.md). Chunk keys are random and stored in links (notes/local-store.md).
- Sync groups and owner actors stay separate: groups overlap and may be cyclic, ownership is single. A group may also be an actor (secrets and members) when it serves as a shared label.

Three patterns from the same concepts:
- Edge on a thing (ad-hoc share): one existing thing, or a few, shared with an actor; above.
- Shared owner (spreadsheet): one actor owns every thing, all writers edit everything, removal uses the receipt-time rule.
- Per-author owners with a hub (group chat, owner's design): each user has a participant actor they admin, owning their messages; the chat actor is a read member of each participant; users are read members of the chat; chat admins write the chat's data, including the participant set. Members read others' messages (user -> chat -> participant, minimum = read), admins cannot edit them. The app builds the timeline from the participant set.
  - Limits, left to app design: a removed user still controls their old messages and can keep writing new ones, and the app has no verifiable cutoff for those; removing a user rotates the chat's read key, after which each participant's own node must rotate and re-wrap its key (lazily, on next write).
  - Keeping a removed user's past messages is the chat's choice (keep the participant listed as former), not forced by the model.

Open:
- What nodes without read access see: settled 2026-10-09 as opaque blobs only, with efficient set reconciliation; see notes/sync.md. Label keys derive from the group thing's role secrets; rotation trigger open.
- Lazy hand-over is accepted conditionally; walk it through adversarial scenarios before marking it decided.
- When references are rewritten after a hand-over (at hand-over, on read, on write).
- A role on an actor covers both editing the actor thing's own data and acting as it. Fine so far; revisit if an example needs them apart.
- Nesting cost: removing a member low in the hierarchy rotates read keys of every actor above it.
- Recovery of a lost owning key: out of scope, a product decision not baked into the architecture (owner 2026-10-12).

## Purge rights (decided by owner 2026-10-11)
An explicit purge of preserved history may be issued by the author of a delta or by an admin of the thing's owner. Any writer can already destroy live state, but letting any writer purge would turn recoverable vandalism of `preserve` aspects into irrecoverable loss; purging only your own deltas gives no power you lacked by not writing them. The person who pasted a secret fixes it without an admin. A purge request naming an aspect's history purges the deltas the requester may purge; the purge record stays visible. Residue: a delta by another author that carries part of the content (a typo fix inside the pasted text, a re-chunked region of a large value) needs that author or an admin. Alternative considered: author-or-owner. At blind nodes authors act by per-entry delete token plus a current writer signature, admins by the label hard-delete key; for `purge`-class deltas the token is writer-derived so any current writer may finish the reset (notes/sync.md, Authorization).

## Revocation: reference scenario
Alice shares a doc with Bob (Mon). Bob goes offline (Tue), makes edit X (Wed). Alice revokes Bob without having seen X (Thu). Bob makes edit Y (Fri), returns and syncs (Sun). Variant: Carol is offline with Bob and syncs with him there.

## Decided
- The author's own timestamp never decides validity: forgeable, and meaningless even when honest.
- "Surface it to the app/user" is not a solution, here or for CRDT problems generally. No adoption UI, no app-visible conflict state. The diagnostics channel (notes/api.md) reports problems, but nothing may depend on it being read.
- Rejected writes may exist as an *invalid write* concept: invisible to the normal API, usable by a generic/forensic tool to recover lost data.
- Receipt-time rule (below) is the direction.

## Receipt-time rule
A write from a revoked actor is valid iff a node of a still-authorized actor *received* it before the revoke's timestamp. Both times come from members' clocks (trusted), never the author's. Centralized semantics with "any member's device" as the server.

- Reference scenario: X and Y both invalid. Carol variant: X valid (Carol got it Wed), Y invalid (Carol got it Fri); reads as "nothing Bob did after Thursday counts".
- A revoked actor cannot react to the revocation: by the time they know, the revoke time has passed.
- Clock skew between members leaves a window of at most the skew, and only against a node that has not heard yet. Judged fine by owner. If ever needed: backdate the revoke by a margin or delay sending it.
- Statement: a node learning of a revocation publishes a signed "as of the revoke time I held this actor's writes up to here" (per aspect, per author node). The revoke carries the revoker node's own. Only published if it covers something beyond statements already seen.
- Invalid -> valid can happen late (a witness comes online). Apps see an ordinary late merge.
- Valid -> invalid happens once, on a node that merged a write after the revoke time but before hearing of the revoke: it un-merges.
- A statement is itself a write by its author, judged by the same rule if that author is revoked. So if Carol is kicked too and no remaining member's node took X from her in time, X is invalid ("never reached the group"). Owner finds this dependency unintuitive but not blocking.

### Proposal details (not yet discussed)
- Validity = least fixpoint over revokes and statements, starting from currently authorized actors (two revoked actors vouching for each other validate nothing).
- Re-grant: writes made under the old grant and never witnessed stay invalid; the actor can redo them.

## Costs
- Receipt log: nodes record when each author frontier advanced (per aspect, per author node), pruned past some horizon.
- Un-merge: drop elements by author dot; restore register values the invalid write overwrote from peers or own retained bodies. Rare loss possible if neither has it.
- Invalid text inserts stay as content-less anchors (like deleted elements) so others' inserts anchored to them keep their place.
- Every state element carries an author dot (decided 2026-10-14, notes/crdt-sync.md), so un-merge and frontier statements are uniform.
- Backfill: a revoked writer can mint a write claiming a dot below a published statement. Contiguous dots make it a detectable reuse; needs a deterministic winner.
- A revoker can backdate a revoke to roll back more. Not a new power: any writer can already invert another's edits.
- Sync exchanges permission state before content; revocations are pushed with priority.
- No finality: a revoked actor's writes can turn valid while a witness is still offline. Same as any long-offline node returning.
- Retaining invalid writes is not needed for correctness (the witness delivers them).

## Rejected options
- Timestamp rule (valid if author HLC < revoke HLC): forgeable.
- Accept everything causally concurrent with the revoke: a hostile ex-writer never "sees" the revoke, so it never binds.
- Revoker's cutoff (only what the revoker's node had seen): depends on which node did the revoke; no reason the revoker's view should win.
- Learn-based witness rule (valid if a member's node accepted it before that node *learned* of the revoke): no un-merge, but the revoked actor can react, racing the revocation or reaching an offline node. Honest offline sync and a hostile push look identical to the receiver.

## Background
Merge has no agreed global order: join is order-free, (HLC, node) is author-claimed, used per register only, and has no finality. A trusted order would need consensus or a sequencer, which breaks offline editing.
