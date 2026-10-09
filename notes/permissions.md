# Permissions and revocation
> Summary: Permission model (actors, membership, ownership; proposal) and write revocation vs. concurrent offline edits (receipt-time rule, accepted by owner 2026-09-29, details proposal), with rejected alternatives and costs.

## Model (2026-09-29; proposal unless marked decided)
Owner's direction: a small set of concepts that compose; hierarchical; keys for nodes, actors and other scopes; private keys wrapped to a target to grant access; a set of things shared with a changing set of actors must be managed in one place; nested actors (e.g. tess -> tess-human, tess-agent) should be possible but not baked in. Spreadsheet and group chat differ, but both are many things whose permissions change together.

Three concepts:
- **Actor**: a thing with keys (signing + encryption). Nodes, people, agents, teams and shared documents/chats are all actors. Identity is the tid, so keys can rotate. A node is a leaf actor whose private key never leaves the device.
- **Membership**: edge member actor -> actor with a role (read < write < admin), written by an admin of the target. Actors can be members of actors; effective role is the minimum along the chain. Nesting and "node acts for person" are the same edge.
- **Ownership**: every thing has exactly one owner actor, fixed by its tid; rights on the thing are rights in its owner. A shared doc is one actor owning all its things, so access changes in one place.

Vocabulary: read, write (editor) and admin are roles a member holds in an actor. Admin = write + change the actor's membership + transfer things it owns. Owner is not a role: it is which actor a thing belongs to. An actor's owner is another actor, so "alice owns P" is literal.

Top of an actor = its owner (decided by owner 2026-09-29). No new concept: an actor is a thing, so it has an owner actor like any other thing.
- An actor's owner is implicitly its admin, and the only one its other admins cannot remove. Handing over an actor works like any thing (Hand-over, below).
- The chain ends at a key actor (node or recovery key), which owns itself; its tid commits to its public key.
- Other admins are equals: any of them can add or remove members, including each other. If two remove each other both removals apply and the owner restores whoever should stay. A hostile admin is out of scope in the same way a hostile writer is; the owner is the recourse.
- UX vocabulary stays the familiar one: owner, admins, editors, viewers.
- Rejected: seniority ranking of admins (total order, remove only juniors). Handles disputes among non-top admins without the owner, but the ranking is unintuitive and would leak into UX (owner's objection).
- Conflicts between nodes acting for the same actor are ordinary merges (latest write wins): both are trusted members, so their clocks are too. Only a hostile node (stolen device) matters, and that is a removal from the person actor, which its owner can always do.
- So a person actor's owner should be a recovery key kept offline, with devices as admins: a stolen owner device wins everything, a lost one leaves nobody able to overrule the admins. Policy for apps, not protocol; to the protocol a recovery key is just another node actor.

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
- Hand-over is therefore somewhat expensive (rewrites spread over every referencing thing, a name index per owned thing). Guidance for app design (owner): avoid ownership changes where possible. Put shared data under an actor and change its membership instead of handing things between people.
- Backlink index per node (owner's idea): which things refer to which, over typed tids and markdown links. Serves rewriting and generic backlinks.
- Needs spec: derived-tid index (local, one hash per owned thing per hand-over or on fork), branch-relative resolution, chains of several hand-overs.
- Risks to settle before calling it decided:
  - A thing can have several tids (original, one per hand-over). Leaks into the API only for identity comparison of tids an app kept from earlier; lookups resolve implicitly (notes/api.md).
  - Split at birth: the former owner hands over to two targets at once and shows each to different members. No node can tell which is legitimate. Decided by owner: no loud report, a fork is something that can really happen and a peer can cause it; handled by the resolution rules, plus an event on the diagnostics channel (notes/api.md).
  - After a fork, a node rewrites its own still-aliased references to the branch it was following; that is an ordinary write, so a user's devices converge by normal merge.
- Rejected: copy/re-create under the new owner (loses history, cost proportional to size, owner's objection); fork deletes the thing (every former owner keeps a kill switch); picking a winner (former owner takes over); first-seen-wins per node on one tid (no convergence); finality by members' receipt time (no neutral witness when a thing has no members, symmetric claims); references always tagged with the owner (every hand-over breaks references).

Mechanism splits by direction (decided by owner):
- Write: signatures plus membership chain. A node always signs with its own key. Sharing an actor's private signing key is rejected: it erases which member wrote (the revocation rule needs the author) and makes every removal a key rotation.
- Read: key wrapping, as the owner described. An actor's private decryption key is wrapped to each member; content keys derive from the owner actor's read key. Removal rotates the key, lazily (old content was already readable).

Owner: a tid commits to its owner by hash (self-certifying tids, decided, notes/data-model.md).

Falls out:
- Grant/revoke are ordinary writes to the actor thing, judged by the receipt-time rule like any other write.
- Keyed hashes derive from the owner actor, not from groups (closes the multi-group open question in notes/crdt-sync.md).
- Sync groups and owner actors stay separate: groups overlap and may be cyclic, ownership is single.

Two patterns from the same concepts, no per-thing grants needed:
- Shared owner (spreadsheet): one actor owns every thing, all writers edit everything, removal uses the receipt-time rule.
- Per-author owners with a hub (group chat, owner's design): each user has a participant actor they admin, owning their messages; the chat actor is a read member of each participant; users are read members of the chat; chat admins write the chat's data, including the participant set. Members read others' messages (user -> chat -> participant, minimum = read), admins cannot edit them. The app builds the timeline from the participant set.
  - Limits, left to app design: a removed user still controls their old messages and can keep writing new ones, and the app has no verifiable cutoff for those; removing a user rotates the chat's read key, after which each participant's own node must rotate and re-wrap its key (lazily, on next write).
  - Keeping a removed user's past messages is the chat's choice (keep the participant listed as former), not forced by the model.

Open:
- What nodes without read access see: settled 2026-10-09 as opaque blobs only, with efficient set reconciliation; see notes/sync.md. Each group carries a sync keypair that authorizes uploads to blind nodes; rotation trigger open.
- Lazy hand-over is accepted conditionally; walk it through adversarial scenarios before marking it decided.
- When references are rewritten after a hand-over (at hand-over, on read, on write).
- A role on an actor covers both editing the actor thing's own data and acting as it. Fine so far; revisit if an example needs them apart.
- Nesting cost: removing a member low in the hierarchy rotates read keys of every actor above it.
- Recovery when the owning key at the end of the chain is lost.

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
- Every state element must be attributable to an author node and ordered per node. Registers currently carry only a timestamp (notes/crdt-sync.md), so they need a dot.
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
