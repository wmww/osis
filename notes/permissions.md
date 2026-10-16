# Permissions: rationale
> Summary: Why spec/permissions.md looks the way it does: owner direction, why each rule, costs and leaks, hand-over and revocation walk-throughs, the `tools/fixpoint` findings behind the membership timeline, sharing patterns, public content and anonymous writing ideas, rejected alternatives.

## Owner direction
A small set of concepts that compose; hierarchical; keys for nodes, actors and other scopes; private keys wrapped to a target to grant access; a set of things shared with a changing set of actors managed in one place; nested actors (tess -> tess-human, tess-agent) possible but not baked in. UX vocabulary stays familiar: owner, admins, editors, viewers.

## Concepts
- Any thing becomes an actor when it needs members of its own: people, agents, teams, shared documents, a single shared note. Identity is the tid, so keys rotate freely.
- A role on an actor covers both editing the actor thing and acting as it: only `/members`, `/secrets`, `/handover` would differ, and they are admin-gated anyway. Split only if an example needs writers who may act as the actor but not edit its profile.
- Admins are equals; seniority ranking was rejected (unintuitive, leaks into UX). A hostile admin is out of scope; the owner is the recourse. So a person actor's owner should be an offline recovery key, with devices as admins (app policy).
- Recovery of a lost owning key is out of scope (owner). The actor keeps working (admins can remove each other) but can no longer be handed over, roster-snapshotted, or settle an admin war. The hand-over authorization is an enum, so recovery can be added later.
- Recovery card: the seed alone cannot find the person actor (tid, labels and servers are not derivable), hence the card format; a delivery blob for a fresh device would need a label the key already reads, which is the bootstrap label.
- Nodes are things that own themselves and grant nobody anything; the node card under every label a node tracks shows exactly the readers of L which nodes sync L, never a roster. Rejected: a self-edge granting the person admin (covers only own devices); a devices group readable by contacts (leaks the device roster, misses read-only co-members). `/reach` is omitted under bearer/public labels because it carries IPs.

## Keys
- Writes are node-signed plus a membership chain. Sharing an actor's signing key erases which member wrote (revocation needs the author) and makes every removal a key rotation; it is reserved for deliberate anonymous writing.
- Reads are key wrapping, per role and every epoch: a later writer needs old write epochs to derive delete tokens of old `purge`-class entries; a later reader needs old read epochs for old wraps.
- Per-role secrets checked against the patterns: sharing (read and write wrapped to the grantee, admin only to the owner), demotion write -> read (rotate write only, re-register soft-retire), removal, the mixed-owner chat: all work without extra machinery. Rotation by several admins is idempotent since keys derive from the one new secret.
- A plain thing derives its secrets until it has a non-owner member, so nothing is stored; then explicit secrets, so owner rotation does not cascade.
- Nesting cost (accepted): removing a member rotates every actor whose secret it could open. Per rotated actor: one sealed box (about 1.2 KB) per direct member per rotated role, one re-registration per label per server. A company of 50 teams with 10 labels on 3 servers: 50 boxes and 30 signed messages per person removal. Inherent to lazy rotation (tension 21).
- A removed node erases what it can no longer read so a later compromise exposes nothing more; not enforceable against a hostile node. If the removal is undone, the node re-syncs.

## Sharing
- Sharing never changes a tid. Moving a thing to an actor its owner owns has no double-spend harm, so it is an ordinary write (an edge). Hand-over with a new tid is only for moving a thing out of its owner's tree, which should be rare.
- One note: an edge on N, explicit secrets on N, N its own label. A set: a group thing with members and secrets, made a read member of each thing (one edge per thing, one commit). A set meant to be shared as a unit is better created under a common owner.
- Group membership grants no rights (an edge on a group extending to its contents was rejected). Checked against the patterns: shared folder, own folder without secrets, chat all label correctly.
- Rejected: an actor per thing at creation (usage rule, doubles thing count); a grant-set thing listing shared tids (a verifier could only check N's writes after syncing the set); per-thing derived content keys plus an encrypted hint per blob (24 bytes cheaper than a wrap, loses crypto-shredding and add-a-wrap sharing).

## Certificates
- Problem: checking a write on N needs the membership of N's owner chain and of the author's own actors, which only members can read. Resolution: signed membership commits are the certificates and travel under the labels where needed. No verify role, no certificate format, no extra key.
- Leaks: a reader of L learns the chain of every author under L (one edge and the roster size per level, plus each `/created` record and hence that thing's dedup secret) and the witnesses that attest about them, never rosters. Author identity is inherent anyway.
- Roster snapshots in certificates are projected per edge: whole snapshots handed every reader of L the full device roster of each author's person actor and the rosters, `/label` IDs and servers of every team above it.
- Accepted: revocation reach is eventual (L's readers accept a revoked node until some member of the revoking actor syncs L); chain depth equals nesting depth.
- Rejected: a transitive "verify" role (outside collaborators learn full rosters; every rotation re-wraps to everyone below); per-commit certificate chains (a few hundred bytes per commit against a 300-byte floor).

## Revocation
Reference scenario: Alice shares a doc with Bob (Mon). Bob goes offline (Tue), makes edit X (Wed). Alice revokes Bob without having seen X (Thu). Bob makes edit Y (Fri), returns and syncs (Sun). Variant: Carol, offline with Bob, syncs with him.
- Owner decisions: the author's own timestamp never decides validity; "surface it to the user" is not a solution; rejected writes may exist as an invisible "invalid write" concept for forensic tools.
- Receipt-time rule results: X and Y invalid; Carol variant: X valid, Y invalid ("nothing Bob did after Thursday counts"). Centralized semantics with any member's device as the server. A revoked actor cannot react in time: by the time it knows, the revoke time has passed.
- Clock skew leaves a window of the skew (tension 9). If ever needed: backdate revokes by a margin.
- Invalid -> valid can happen late (a witness comes online); valid -> invalid happens once, by un-merge. No finality, like any long-offline node returning.
- Re-grant validates the gap: cheaper than grant epochs in the log, the actor could redo the writes anyway, and it makes recovery from a stolen device's backdated mass revoke lossless.
- A revoker can backdate to roll back more; not a new power, any writer can invert others' edits.
- Readers do not witness: a reader's attestation would let a reader plus an ex-writer jointly write. Blind nodes never witness (tension 6).
- An attestation by a later-revoked author is judged by the same rule; the owner finds this dependency unintuitive but not blocking.
- Attestation cost: one commit per witness per revoke, about 10 bytes per (aspect, author node) entry; ten thousand aspects is about 100 KB once.
- The revoker's attestation is a separate commit so the revoke can retire with a roster snapshot and the attestation with content snapshots.
- Sync-then-revoke closes most of tensions 6 and 15 (both stem from a frontier taken on an unsynced device). What remains: writes at blind nodes the revoker does not reach, writes in transit, revokes issued offline or backdated; all recoverable by re-grant.
- Rejected: timestamp rule (forgeable); accept everything causally concurrent with the revoke (a hostile ex-writer never "sees" it); revoker's cutoff (depends on which node revoked); learn-based witness rule (the revoked actor can race the revocation, and honest offline sync looks like a hostile push); membership by claimed time only (an ex-admin could mint backdated grants forever); attestations as aspect writes (readers and edge-grantees cannot write there).

## Membership timeline (fixpoint findings)
Model: `tools/fixpoint` (throwaway Rust, independent of any implementation). `cargo test` runs the scenarios; `cargo run --release [samples] [as|exempt|strat|stratw|frontier|snapshot]` searches: exhaustive up to 3 membership writes (owner, 2 admins, 1 writer, skewed receipts, offline nodes) plus millions of random histories (up to 4 admins, 2 writers, 8 writes). `snapshot` (`src/snapshot.rs`) is the two-level roster-snapshot model.
- **Third-party witnesses judged by end-of-walk membership fail**: about 14% of random histories never stabilize (period-2 loops), e.g. an admin removing itself that nobody received in time. Several stable answers are normal (1–2%), so the answer must come from a deterministic procedure. Layer 1 is inherently non-monotone in receipts; layer 2 was monotone in every sample.
- **Every third-party-witness variant has a self-witness hole**: an ex-admin's backdated grant whose only receiver is its beneficiary stands, since the beneficiary is a member by that grant; two forged grants can vouch for each other. Closing it needs a lot of rule for rare writes.
- **Demoter-frontier rule (chosen, agent's call)**: every expected outcome holds (mutual removal resolves to the earlier timestamp; the owner's further-backdated revoke cancels a stolen device's; re-grant validates content; a cycle of removed witnesses validates nothing; self-witness and mutual-vouching attacks fail; a demoter's testimony falls with the demoter). Terminates everywhere (at most 6 walks in 4M histories), order independent, nothing dropped when nobody is offline. Differs from the old rule in about 6% of histories, all "another admin or a writer received the write, the demoter had not". Drops are sticky within one evaluation; a from-scratch re-evaluation can oscillate.
- If third-party receipts for membership writes are ever wanted: `strat` (admin witnesses) and `stratw` (write+ witnesses) in the tool, both needing the self-witness fix; write+ witnesses also let a writer plus an ex-admin hold admin power.
- Consequences worth knowing: a stolen admin device's backdated removals stand iff the node removing the device had received them before its revoke time; an admin removed by a node that had not synced loses the grants that node had not seen, even if other admins saw them (re-grant recovers). Edge demotions never audit owner-chain writes, so an edge-admin cannot drop a roster snapshot.
- Not yet modeled: issues/fixpoint-coverage-gaps.md.

## Roster snapshots
- Bound membership history (tension 12). Only owner-chain snapshots can be epoch starts: their applicability depends only on the chain above N, never on N's own earlier writes, so a node holding only S and later writes computes what a full-history node does.
- A grant in flight while a snapshot is taken is dead (finality per snapshot); snapshot after a fresh sync, re-grant a victim.
- The retire horizon keeps the revoke long enough for every node offline less than the horizon to judge its receipts.
- Un-applied epoch start (author later removed with a backdated time or a frontier not covering S): a full-history node falls back, a compacted node sees an empty roster until a fresh snapshot; this only shrinks rosters toward the owner chain. Forgeries by a removed device never become epoch starts.
- Who compacts what: a person actor's own roster only when its recovery key signs (device churn is tiny); busy actors (teams, documents) should be owned by a person actor, so its devices can snapshot them. About 25 bytes per edge.
- Content via compaction snapshots: compacted and uncompacted nodes agree. Cost: a backdated revoke of a compactor also invalidates the revoked-author elements its snapshot carried.
- Checked in `tools/fixpoint` (`snapshot`): compaction at any applied snapshot never changes the result (0 mismatches in 2.5M compactions over 4M histories), order independent, at most 4 walks; compaction points later un-applied diverge until a fresh snapshot in about 0.3% of histories, as designed.
- Rejected: edge-admin snapshots as epoch starts (a compacted node cannot judge them, a removed admin could forge one); a snapshot chain (same problem, unbounded); "a dropped epoch start empties the roster for everyone" (a permanent wipe for any removed device); key-actor-only snapshots (an offline key cannot compact a busy roster).

## Hand-over
- Ownership is immutable: a former owner can always sign a competing transfer (double-spend; no fix without consensus), so a hand-over must never be able to harm what the new owner holds. It must be cheap and keep history, so not copy and re-create.
- Disowning: the former owner's chain can remove the signing device with a backdated time and a frontier omitting H, indistinguishable from stopping a stolen device. Hence the new identity is the new owner's by construction and H gates only the alias and inheritance; the acceptance snapshot makes inherited content X's own. The former owner's full power: fork or disown, which break outside links for readers without standing, nothing else (tension 1).
- Inherited admins are stripped, or a former owner could leave planted admins holding every secret. Until the new owner syncs with a server, the former owner keeps that server's label keys, so a received thing is also put under the new owner's own labels.
- Resolution is a read-time view, never a rewrite: an autonomous register rewrite is a no-op write with a fresh timestamp that beats a concurrent real edit; two devices splicing text links concurrently duplicate them; aliases are permanent anyway. Apps pin a reference by writing it. The backlink index indexes resolved tids and re-resolves on a fork.
- The derived-tid index (hash(t, H) -> (t, H) for every tracked t under the handed-over thing) costs O(tracked things) per record, local only.
- Walk-throughs: split at birth (A hands T to X and Y): each side resolves to its branch until it learns the other; X's members' writes are unauthorized in Y's branch; pre-hand-over readers fall to their follow choice. Late fork months after a clean hand-over: standing resolves everything inside X's branch, the follow choice (first seen = X for everyone who used it) the rest; only people who never had access lose links. Honest concurrent hand-over to one owner: lowest record hash. To two owners: a real fork, nothing merges them.
- Rotating the key at the end of a person's chain: hand over the key actor, not the person actor (handing over the person renames it in every `/members` that lists it).
- Hand over from an up-to-date node: writes by the former owner's other members that the signer had not received need a witness among the new owner's members. A cooperative transfer can re-grant the old members for a while.
- Rejected: copy/re-create (loses history, O(size)); fork deletes the thing (kill switch for every former owner); picking a winner; first-seen-wins per node as the primary rule (no convergence); finality by members' receipt time (no neutral witness for memberless things); references tagged with the owner (every hand-over breaks them); rewriting stored references; a frozen certificate bundle per record (lets ex-devices hand things out forever).

## Links
- Built from existing concepts: K (an actor) and L (a key actor). Several links = several (K, L) pairs. Revoke the link but keep joiners = remove L from K (sync K's label first); revoke link and joiners = remove K; remove one joiner = remove them from K.
- `until` instead of commit expiry, which would purge the certificate joiners' chains rest on.
- Finalization: L's claimed times are constrained by nobody's frontier (every holder signs as L). After `until` a holder can mint a backdated join; after a single-use redemption a second holder can mint an earlier redemption. So `until` and self-removal audit nothing until a sharer device writes a real removal; until then the link is honest-client-only. Alternative (no `until` or single use at all) loses nothing a hostile holder respects.
- Bearer use is read only: all bearers share L's node identity, so their dots would collide.
- Caveats: every holder is an admin of K: it sees who joined, can remove joiners (they can rejoin while the link lives), and holds K's label hard-delete key. Fix if it matters: an add-only admin role.

## Patterns
- **Edge on a thing**: ad-hoc share of one or a few things.
- **Shared owner** (spreadsheet): one actor owns everything, all writers edit everything, removal by the receipt-time rule.
- **Per-author owners with a hub** (group chat, owner's design): each user has a participant actor owning their messages; the chat actor is a read member of each participant; users are read members of the chat; chat admins write the chat's data and participant set. Members read others' messages, admins cannot edit them. Limits left to the app: a removed user still controls old messages and can keep writing with no verifiable cutoff; an app wanting a cutoff keeps a chat-written "accepted" marker per message. A removed user's uploads stop at blind nodes once the upload key is re-registered.
- Sync groups and owner actors stay separate; a group may also be an actor when it serves as a shared label.

## Purge rights
Author or admin only: any writer can already destroy live state, but letting any writer purge would make recoverable vandalism of `preserve` aspects irrecoverable; purging your own deltas gives no power you lacked by not writing them. Residue: a delta by another author that carries part of the content (a typo fix inside pasted text) needs that author or an admin. Edge-admins may purge since they hold the label hard-delete key anyway.

## Public content (proposal, not decided)
A public site off live osis data needs something holding the key to render. Options: (A) bearer link plus a static JS reader served by the blind node (server stays blind, invisible to search engines); (B) a rendering gateway: a trusted node holding only the public label's read secret, serving HTML (recommended for real sites); (C) publish the read secret so anyone can run a gateway. Leaks: author chains under the label become public and permanent, so a public label may want a dedicated publisher identity that re-signs snapshots; deletion is best effort.

## Anonymous writing (discussed with owner, not a priority)
Needs no new machinery beyond commit-form dots. Network, timing and style leaks apply to all.
- Pseudonymous member: a fresh actor with its own owning key and device keys, joined via a link or grant; the granting admin may record pseudonym -> person in admin-only data.
- Known writers, unlinkable edits: group X holds the signing key of key actor A, which has write on Y (cleaner: A's key derived from X's role secret). Members write as A in commit form. Caveats: any member can purge any A edit; unwitnessed offline A edits die at A's revoke, so clients re-sign pending ones; undo uses locally remembered own commits.
- Re-publisher: a trusted node re-signs members' edits under its own identity.
