# Permissions, sharing, hand-over, revocation
> Summary: Three concepts (actor, membership, ownership); sharing within the owner's tree via edges on things and labeled membership commits (decided 2026-10-11); lazy hand-over with aliases for moving a thing out of its owner's tree (accepted conditionally 2026-09-29); write revocation vs concurrent offline edits by the receipt-time rule (accepted 2026-09-29, details proposal). Open points collected in issues/permissions-review.md.

## Model (2026-09-29; proposal unless marked decided)
Owner's direction: a small set of concepts that compose; hierarchical; keys for nodes, actors and other scopes; private keys wrapped to a target to grant access; a set of things shared with a changing set of actors must be managed in one place; nested actors (tess -> tess-human, tess-agent) possible but not baked in.

Three concepts:
- **Actor**: a thing with role secrets (and a signing key for key actors). Any thing becomes one when it needs members of its own: nodes, people, agents, teams, shared documents/chats, a single shared note. Identity is the tid, so keys can rotate. A node is a leaf actor whose private key never leaves the device.
- **Membership**: edge member actor -> thing with a role (read < write < admin), written by an admin of the target (for a plain thing: an admin of its owner). Target an actor: rights on everything it owns. Target a plain thing: rights on that thing only. Actors can be members of actors; effective role is the minimum along the chain. Nesting and "node acts for person" are the same edge.
- **Ownership**: every thing has exactly one owner actor, fixed by its tid (self-certifying tids, notes/data-model.md); rights on the thing are rights in its owner plus the edges written on the thing itself. A shared doc is one actor owning all its things, so access changes in one place.

Vocabulary: read, write (editor) and admin are roles. Admin = write + change membership + hand over things the actor owns. Owner is not a role but which actor a thing belongs to. UX vocabulary stays the familiar one: owner, admins, editors, viewers.

Top of an actor = its owner (decided 2026-09-29): an actor is a thing, so it has an owner actor like any other thing.
- An actor's owner is implicitly its admin, and the only one its other admins cannot remove.
- The chain ends at a key actor (node or recovery key), which owns itself; its tid commits to its public key.
- Other admins are equals: any can add or remove members, including each other. If two remove each other both removals apply and the owner restores whoever should stay. A hostile admin is out of scope like a hostile writer; the owner is the recourse. Rejected: seniority ranking of admins (unintuitive, leaks into UX).
- Conflicts between nodes acting for the same actor are ordinary merges. Only a hostile node (stolen device) matters, and that is a removal from the person actor, which its owner can always do.
- So a person actor's owner should be a recovery key kept offline, with devices as admins. App policy, not protocol: a recovery key is just another key actor. Recovery of a lost owning key is out of scope (product decision, owner 2026-10-12).
- A role on an actor covers both editing the actor thing's own data and acting as it. Fine so far; revisit if an example needs them apart.

## Keys
Mechanism splits by direction (decided):
- **Write**: node signature plus membership chain. A node always signs with its own key. Sharing an actor's signing key is rejected: it erases which member wrote (the revocation rule needs the author) and makes every removal a key rotation.
- **Read**: key wrapping. An actor has one secret per role (read, write, admin; proposal 2026-10-11), each wrapped to the members holding that role or higher. Each blob's own key is wrapped under the read secret of every label it sits under (notes/sync.md). Label operation keys (upload, soft-retire, hard-delete) derive from the role secrets, so blind nodes distinguish roles by signature; those are shared role keys, not authorship. Demotion or removal rotates the affected secrets lazily (old content was already readable), but label keys are re-registered eagerly (notes/sync.md).
- Role secrets of a plain thing: by default derived by KDF from the owner's secrets and the tid, so nothing is stored. Once a thing has a non-owner member it gets explicit random secrets, wrapped to the owner and each member, so owner rotation does not cascade.
- Keyed hashes use a per-thing dedup secret derived from the creation nonce, so every reader hashes identically and sharing changes nothing (notes/data-model.md).
- Grant/revoke are ordinary writes to the actor thing, judged by the receipt-time rule like any other write.

## Sharing within the owner's tree (decided 2026-10-11)
Sharing never changes a tid.
- Edges on plain things. Bob gets write on note N owned by Alice's actor A: an admin of A writes "Bob: write" on N. Verification chain: Bob's node -> Bob -> edge on N -> A owns N (tid).
- One note: edge on N, explicit secrets on N, N is its own label. A set: a group thing with members and secrets (the "shared with Bob" folder), made a read member of each thing by one edge per thing, written in one commit; its label then receives those things' blobs. A set meant to be shared as a unit is better created under a common owner (shared-owner pattern).
- Group membership grants no rights (2026-10-15, from the rejected "edge on a group extends to its contents"): an honest uploader wraps a thing's blobs for a label only if the label's actor may read the thing (notes/sync.md, Labeling). Groups stay an app tool; a group that should read its contents is made a member of them.
- Sharing history means adding wraps, never re-encrypting.
- Why no tid change: the double-spend harm of a transfer is the former owner pulling the thing back. Moving a thing to an actor the owner owns has no such harm, so it is an ordinary write on the thing; the edge is the additive form of that write. Hand-over with a new tid remains only for moving a thing out of its owner's tree, which should be rare.
- Rejected: an actor per thing at creation (usage rule, doubles the thing count); a membership edge on a group thing extending to its contents; a grant-set thing listing shared tids (a verifier could only check N's writes after syncing the set; an edge on N travels with N); per-thing derived content keys plus an encrypted hint per blob (about 24 bytes cheaper than a wrap, loses crypto-shredding and add-a-wrap sharing).

## Verifying writes without reading membership (decided 2026-10-11)
Problem: checking a write on N needs the current membership of N's owner and every actor above it up to the key actor, and of the author's own actors below; only members can read those aspects. So a grantee or a chat reader could neither verify writes nor learn of revocations.

Resolution: the signed membership commits are the certificates; they travel under the labels where they are needed. No verify role, no certificate format, no extra key.
- Membership writes (grant, revoke, demotion, receipt statement) always get their own commit, so a membership commit can sit under extra labels without exposing anything else. Internal rule; apps never see it.
- When a node uploads under label L it also puts the membership commits proving its own chain under L: its edge into its person actor, that admin's edge into the owner, and so on up to the key actor. One extra wrap per blob, deduped by blob ID, so the cost is once per (node, label).
- Revokes and statements follow the same rule: any member who syncs L and holds one about an author seen under L adds the wrap. A grantee with write on N is an authorized actor for N, so its receipts count as witness statements for N.
- Chain checks need no secrets: each link is a node signature plus a tid committing to its owner, ending at a key actor whose tid commits to its public key.
- A commit whose author chain has not arrived is held unverified until it does; same pending state as an out-of-order delta.

Leaks: a reader of L learns the chain of every author under L and the witness nodes that publish statements about them, never rosters. Author identity is inherent anyway (every write is node-signed).

Accepted limits: revocation reach is eventual (if no member of the revoking actor syncs L again, L's readers keep accepting the revoked node until one does, then un-merge); chain depth equals nesting depth (node -> person -> recovery key is two blobs, each org level adds one).

Rejected: a "verify" role handed out transitively with every edge (an outside collaborator learns the team's and company's full membership; every rotation above re-wraps to everyone below); per-commit certificate chains (a few hundred bytes per commit against a 200-byte floor).

## Hand-over (2026-09-29, accepted conditionally)
Decided: ownership is immutable, since a former owner can always sign a second, competing transfer (double-spend, no fix without consensus), so a hand-over must never be able to harm what the new owner holds. Hand-over must be cheap and keep history, so not copy/re-create.

Lazy hand-over: data never moves; names change.
- Hand-over record: names the record it follows (creation record or previous hand-over) and the new owner; signed by an admin of the owner that record names. Stored on the thing. No timestamps.
- Permanent tid = hash(old tid, hand-over record): "the thing as handed to X". X owns it immutably; a competing hand-over hashes to a different tid and cannot touch it.
- Alias rule: the old tid resolves to the permanent tid while exactly one hand-over follows the record. Deterministic and monotone, so it converges.
- Things owned by a handed-over actor are untouched; their owner resolves through the alias. Things created afterwards commit to the permanent tid directly.
- Fork (a second hand-over follows the same record): the old tid dangles for good; each branch continues under its permanent tid. Things the actor owned get derived tids the same way, computed locally. A node keeps the branch it follows and never stores the other unless something it tracks refers to it.
- Resolution of an old tid after a fork (proposal): walk up the owner chain of the thing holding the reference; if it has standing (owner, or member added after the hand-over) in exactly one branch, resolve to that branch. Standing in both or neither: the reference dangles. References using the permanent or derived tid are unaffected. May not be a sufficient decider.
- Writes are judged against the membership data of the branch a node follows. Members who predate the fork are valid in both branches; commits need not name a branch.
- Former owner's power: break outside links that still use the old tid. Cannot read new content, write, take over or destroy.
- Rotating the key at the end of a person's chain is an ordinary hand-over of the person actor.
- Reference rewriting (decided): after a hand-over, nodes rewrite old tids to permanent/derived ones in data they may write, including `osis://` links inside markdown (rewrite = text splice). When (at hand-over, on read, on write) is undecided and not urgent. After a fork, a node rewrites its own still-aliased references to the branch it follows; an ordinary write, so a user's devices converge by normal merge.
- Split at birth (former owner hands over to two targets and shows each to different members): no loud report, a fork is something a peer can cause; handled by the resolution rules plus a diagnostics event (notes/api.md).
- The new owner's members must read old content: wrap the handed-over actor's read secrets (all epochs) to the new owner; for a single thing, add wraps for its blobs under the new owner's labels.
- Backlink index per node (owner's idea): which things refer to which, over typed tids and markdown links. Serves rewriting and generic backlinks.
- Cost: rewrites across every referencing thing, a derived-tid index per owned thing, edge cases from a thing changing tids. Guidance (owner): hand over only to move a thing out of its owner's tree.
- Needs spec before decided: derived-tid index, branch-relative resolution, chains of several hand-overs, adversarial walk-through (issues/permissions-review.md).
- Rejected: copy/re-create (loses history, O(size)); fork deletes the thing (kill switch for every former owner); picking a winner; first-seen-wins per node (no convergence); finality by members' receipt time (no neutral witness when a thing has no members); references always tagged with the owner (every hand-over breaks references).

## Patterns
Three from the same concepts:
- Edge on a thing (ad-hoc share): one existing thing, or a few, shared with an actor.
- Shared owner (spreadsheet): one actor owns every thing, all writers edit everything, removal uses the receipt-time rule.
- Per-author owners with a hub (group chat, owner's design): each user has a participant actor they admin, owning their messages; the chat actor is a read member of each participant (so the chat label receives the messages); users are read members of the chat; chat admins write the chat's data, including the participant set. Members read others' messages (user -> chat -> participant, minimum = read), admins cannot edit them. The app builds the timeline from the participant set.
  - Limits, left to app design: a removed user still controls their old messages and can keep writing new ones, with no verifiable cutoff; removing a user rotates the chat's read key, after which each participant's node re-wraps lazily on next write. Keeping a removed user's past messages is the chat's choice.
- Sync groups and owner actors stay separate: groups overlap and may be cyclic, ownership is single. A group may also be an actor when it serves as a shared label.

## Purge rights (decided 2026-10-11)
An explicit purge of preserved history may be issued by the author of a delta or by an admin of the thing's owner. Any writer can already destroy live state, but letting any writer purge would turn recoverable vandalism of `preserve` aspects into irrecoverable loss; purging only your own deltas gives no power you lacked by not writing them. A purge request naming an aspect's history purges the deltas the requester may purge; the purge record stays visible. Residue: a delta by another author that carries part of the content (a typo fix inside the pasted text) needs that author or an admin. At blind nodes authors act by per-entry delete token plus a current writer signature, admins by the label hard-delete key; `purge`-class tokens are writer-derived so any current writer may finish the reset (notes/sync.md).

## Revocation vs concurrent offline edits
Reference scenario: Alice shares a doc with Bob (Mon). Bob goes offline (Tue), makes edit X (Wed). Alice revokes Bob without having seen X (Thu). Bob makes edit Y (Fri), returns and syncs (Sun). Variant: Carol is offline with Bob and syncs with him there.

Decided:
- The author's own timestamp never decides validity: forgeable, and meaningless even when honest.
- "Surface it to the user" is not a solution. No adoption UI, no app-visible conflict state. The diagnostics channel reports problems; nothing depends on it being read.
- Rejected writes may exist as an *invalid write* concept: invisible to the normal API, usable by a forensic tool.

### Receipt-time rule
A write from a revoked actor is valid iff a node of a still-authorized actor *received* it before the revoke's timestamp. Both times come from members' clocks, never the author's. Centralized semantics with "any member's device" as the server.
- Reference scenario: X and Y both invalid. Carol variant: X valid (Carol got it Wed), Y invalid; reads as "nothing Bob did after Thursday counts".
- A revoked actor cannot react to the revocation: by the time they know, the revoke time has passed.
- Clock skew between members leaves a window of at most the skew, only against a node that has not heard yet (constraints tension 9). If ever needed: backdate the revoke by a margin or delay sending it.
- Statement: a node learning of a revocation publishes a signed "as of the revoke time I held this actor's writes up to here" (per aspect, per author node). The revoke carries the revoker node's own. Only published if it covers something beyond statements already seen.
- Invalid -> valid can happen late (a witness comes online): an ordinary late merge. Valid -> invalid happens once, on a node that merged a write after the revoke time but before hearing of the revoke: it un-merges.
- A statement is itself a write by its author, judged by the same rule if that author is revoked. Owner finds this dependency unintuitive but not blocking.

Proposal details, not yet discussed:
- Validity = least fixpoint over revokes and statements, starting from currently authorized actors.
- Re-grant: writes made under the old grant and never witnessed stay invalid; the actor can redo them.
- Witnesses: statements are writes, so which members may publish them (readers cannot write to the actor thing) and where they live is open (issues/permissions-review.md).

Costs:
- Receipt log: nodes record when each author frontier advanced (per aspect, per author node), pruned past some horizon.
- Un-merge: drop elements by author dot; restore register values the invalid write overwrote from peers or own retained bodies. Rare loss possible if neither has it. Invalid text inserts stay as content-less anchors so others' inserts anchored to them keep their place. Every state element carries an author dot (notes/crdt-sync.md), so un-merge and frontier statements are uniform.
- Backfill: a revoked writer can mint a write claiming a dot below a published statement. Contiguous dots make it detectable. Rule (2026-10-14): a write at or below a witnessed frontier that the witness does not hold is invalid; if two witnesses hold different writes for one dot, the lower commit hash wins.
- A revoker can backdate a revoke to roll back more. Not a new power: any writer can already invert another's edits.
- Membership commits are applied before content (notes/sync.md).
- No finality: a revoked actor's writes can turn valid while a witness is still offline. Same as any long-offline node returning.

Rejected: timestamp rule (forgeable); accept everything causally concurrent with the revoke (a hostile ex-writer never "sees" it); revoker's cutoff (depends on which node revoked); learn-based witness rule (valid if a member accepted it before *learning* of the revoke: the revoked actor can race the revocation, and honest offline sync looks like a hostile push).

Background: merge has no agreed global order; (HLC, node) is author-claimed, used per register only, no finality. A trusted order would need consensus or a sequencer, which breaks offline editing.

## Open
See issues/permissions-review.md. Also: nesting cost (removing a member low in the hierarchy rotates read secrets of every actor it could read).
