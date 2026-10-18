# Permissions
> Summary: Actors, membership and ownership; role secrets and rotation; chain certificates and what travels under a label; the two-layer validity rule (membership timeline by demoter frontiers, content by receipt time with attestations); roster snapshots with their tenure ledger; hand-over records, derived tids and alias resolution; purge rights; share links.

## 1. Concepts
- **Actor**: a thing with role secrets (spec/crypto.md §3). A **key actor** (node, recovery key, link key) also has a signing key committed by its tid and owns itself. A node is a key actor whose seed never leaves its device.
- **Ownership**: every thing has exactly one owner actor, fixed by its creation record. An actor is a thing, so it has an owner too; owner chains end at a key actor.
- **Membership**: an edge (member actor, target, role) with roles read < write < admin, stored in the target's `/members`. On an actor it grants the role on everything the actor owns; on a plain thing, on that thing only.
- **Effective role** of a node on a thing at time t: the maximum over paths from the node to the thing of the minimum role along the path, where a path climbs membership edges and owner links (an owner holds admin on what it owns). Evaluated with each timeline (§4) at t.
- **Admin** = write + change membership + purge (§8) + hand over things the actor owns (§7). An admin edge on a plain thing grants membership changes and purge on that thing, not hand-over.
- An actor's owner is implicitly its admin and cannot be removed by other admins. Other admins are equal and may remove each other.
- The aspects `/members`, `/keys`, `/handover` of an actor are writable only by its admins, whatever other role a node holds, except invite grants and self-removals (§2). `/secrets` is written by admins, and by rotations (§3): a node with effective role r may rotate the roles ≤ r.
- Group membership (`/group`) grants no rights.

## 2. Membership writes
- Grant, change and removal of an edge are writes to the target's `/members`, each in its own membership commit (spec/commits.md §2), by a node with admin on the target.
- An edge may carry `until: timestamp`: the edge counts as removed at that time.
- An edge may carry `invite: role`, at most its role. A node's **effective invite** on T is the maximum over its paths to T of the minimum of the roles along the path before the last edge and that edge's invite. An **invite grant** adds an edge for an actor with no current edge on T (an expired edge counts as none), with role and invite at most the author's effective invite, and carries the grantee's boxes for those roles. Invite holders cannot change or remove any other edge.
- **Self-removal**: a node with admin on actor X may always remove X's edge on any target, or lower its role, invite or `until`.
- A membership write made under an edge into actor G MUST also be published under G's label.
- The roster apps read from `/members` is the membership timeline's roster (§4), not the CRDT join of the stored deltas.

## 3. Secrets and rotation
- Each role secret of an actor is sealed to every member holding that role or higher, every epoch (spec/crypto.md §4).
- A plain thing uses derived role secrets until it gets a non-owner member; it then gets random secrets of its own, boxed to its owner and each member.
- A removal or demotion (a device removal is one, on the person actor) requires rotating the role secrets the removed member could open, on the actor it left and on every actor above it; content is not re-encrypted.
- **Who rotates**: a node with effective role r on an actor may rotate its roles ≤ r (a writer rotates read and write, an admin all three; a reader rotates nothing). A rotation seals the new secrets to every current member of each rotated role and writes the history boxes (spec/crypto.md §4); roles it does not rotate carry over. Its validity is the author's role at its `ts` (§5.2).
- A node that may rotate a required rotation MUST do so before it next encrypts under a secret it would replace (spec/crypto.md §4); it MAY rotate eagerly. Eager rotation by many members at once forks the epoch harmlessly, but costs boxes per rotator.
- Label role keys (spec/sync.md §2) derive from the newest epoch, and only an admin can register them; an admin that holds an epoch newer than a label's registered step issues the step at once (spec/sync.md §5). Until then nodes use the registered epoch's keys at that server, and the removed member keeps the old sync key: it can fetch ciphertext it cannot open, and as an ex-writer stamp and delete under the old write key, until re-registration.
- A blind node serves a label only to holders of its current sync key, so every rotation delivers each member's new boxes to its mailbox (spec/sync.md §3).
- A node that learns it lost read access to an actor MUST drop those role secrets and every local unit it can no longer read by another path.

## 4. Verifying authors: certificates
- A write's authority is checked through the chain from the signing node up: each link is a membership write or an owner link (tid commits to the owner), ending at a key actor whose tid commits to its public key. No secrets are needed.
- **Chain certificates** of a node: for each thing on its chain, the `/created` record, the epoch start (§6, projected to the entries the chain needs), the later membership writes that establish each edge, and the current `/keys` commit of each actor on it. Its **node card**: its `/keys`, `/node` and `/reach` commits (each a commit of its own touching nothing else).
- When a node first places anything under a label, and whenever they change, it places its chain certificates and node card under that label (spec/sync.md §3; a non-writer of the label by deposit). `/reach` goes under every label by default; an app MAY exclude labels (e.g. public or bearer-read ones). Without it, co-readers of that label cannot dial the node off-LAN.
- Any member that syncs a label and holds a revoke, roster snapshot, hand-over record or attestation about an author seen under that label places it there (a non-writer by deposit), with the chain certificates of that commit's own author.
- A grant is accompanied by the target's current `/label` commit.
- A commit whose author's chain has not arrived is pending (spec/commits.md §4).
- A node that does not sync a thing applies the certificate deltas it holds; its timeline for that thing runs over the entries it was given.

## 5. Validity
Validity is a deterministic function of the commits, attestations and the node's own receipt log.

### 5.1 Layer 1: membership timeline (per thing that carries edges)
1. Order membership writes by (`ts`, author node). Start at the thing's epoch start (§6) if one applies, ignoring writes ordered before it; else at the first held write.
2. Walk the writes, skipping the drop set D (initially empty). A write applies iff its author has the required authority at that point: admin on the thing; for an invite grant, the effective invite it needs; for a self-removal, admin on the edge's member.
3. Attribute each membership write to the highest authority its author held at its point, owner chain before edge, admin before invite.
4. When an applied write R by node A at time T demotes actor X (from admin to below, or removes an edge with admin, or lowers or removes X's invite), every earlier applied membership write by X attributed to the removed authority that R's **frontier** does not cover is added to D, and the walk restarts. Removing X from actor G audits X's writes made as G's admin on G and on everything G owns; demoting X's edge on a thing audits only what X wrote on that thing by that edge.
Self-removals are never added to D. Each membership write of a commit is judged on its own.
5. The first walk that adds nothing to D is the timeline. D is rebuilt from scratch whenever the held set changes.
- R's frontier is A's receipt log over X's membership-write dots as of T, per node of X, embedded in R. A's own chain writes and R itself always count. No other receipts or attestations count for membership writes.
- A demotion by `until` or by self-removal audits nothing. The next explicit demotion of that member by another node audits with its frontier as if the member still held the role.
- The effective role of a chain at time t is the minimum over the timelines along it.

### 5.2 Layer 2: content
- A content write by an actor authorized at its time is valid.
- A write by an actor revoked at time T_r (by a valid removal or demotion) is valid iff one of: a valid attestation covers its dot before T_r; the evaluating node, if authorized and holding the revoke, received it before T_r by its own receipt log; or a valid compaction snapshot by an authorized writer carries it (§6, Content).
- A re-grant makes every write of the re-granted actor valid again, including those in the gap. Membership writes in the gap stay invalid.
- **Attestation**: a commit by a witness node: the revoke's commit ID, then entries (tid, ak, author node, frontier counter), or explicit commit lists for commit-form dots. Each entry is authorized by the attester's write right on that tid. Attestation validity is the least fixpoint of this layer over attestations, seeded by attestations of authorized actors.
- **Witnesses**: nodes of actors with write or above on the thing. Readers and blind nodes never witness.
- The revoking node publishes its own attestation alongside the revoke, as a separate commit. Other nodes that learn of a revoke publish an attestation only if it covers something not already covered.
- **Backfill**: a write at or below a witnessed frontier that the witness does not hold is invalid. If two witnesses hold different writes for one dot, the one with the lower commit ID is valid.
- **Receipt log**: received means decrypted and verified, not stored or relayed. Kept per commit for commit-form dots, otherwise per (aspect, author node) as checkpoints (own clock time, frontier counter); pruned beyond a horizon (local policy). Received-dot ranges per (aspect, author) are kept forever.
- A write that becomes invalid is un-merged (spec/crdt.md §4.6).

### 5.3 Revoking (client behavior)
Before stamping a role-lowering membership write a client SHOULD sync the labels it tracks for the affected actor and the things under it, with a short timeout, and take the write's `ts` after applying what it downloaded. An explicitly backdated revoke skips this.

## 6. Roster snapshots
- A **roster snapshot** of thing N is a membership commit with the roster-snapshot marker, by a node acting through N's owner chain (admin of N's owner actor or of an actor above it, or the key actor at the top; never by an edge on N). It carries reset-plus-full-state deltas of N's membership-class aspects as the author's timeline computes them: `/members` as one delta per edge (each carrying the reset stamp and that edge; an edge of role write or above also carries `since`, the (`ts`, author node) key of the write that established it, absent if unknown), plus `/label`, `/secrets`, `/keys`, and the **tenure ledger**. It has no frontier.
- **Tenure ledger**: one entry per tenure of role write or above on N that ended before S: member, role, `since` as above, `until` = the key of the ending demotion (a demotion from admin to write ends an admin tenure and starts a write tenure), and for an admin tenure the frontier of the explicit demotion that ended or last audited it (§5.1), absent while it ended by `until` or self-removal and nothing audited it since. The previous epoch start's ledger is carried forward whole; entries are never dropped.
- **Epoch start**: N's newest snapshot S whose author had owner-chain authority at S's time by the timelines above N, and that no later demotion of its author dropped (a demotion with a time before S, or a frontier not covering S). Writes ordered before S are ignored. S's roster and ledger answer what role anyone held on N before S: a member held a role at a point inside one of its ledger tenures of that role, or after its roster edge's `since` and after every ledger tenure of its own; a roster edge without `since` counts from the beginning. A membership write by X ordered before S, made by authority through N, is dropped iff the frontier of a ledger tenure of X ending after it does not cover it. A demotion of X after S audits X's writes before S too, including those under tenures without a frontier.
- A certificate copy of S is projected to the edges and ledger entries the verifier needs and omits `/secrets` and `/label` (spec/sync.md §3).
- S replaces N's membership commits ordered before it (their writes die at S's `ts`); their retention keeps them at least `MEMBERSHIP_KEEP` after that, and `/handover` records forever (spec/commits.md §5).
- **Content**: a compaction snapshot by writer W carries its elements on W's authority: an element is valid if the snapshot commit is valid as W's content write. Once a node holds a snapshot whose frontiers cover a commit, that commit's own validity no longer matters at that node, and attestation entries covering only such commits are dead.

## 7. Hand-over
- A thing's **record chain**: its creation record, then hand-over records. A **hand-over record** = (hash of the record it follows, new owner tid, authorization). Authorization is an enum; its one case is a signature by an admin of the owner the followed record names. The record is a membership write on the thing (`/handover`), kept forever.
- The hand-over commit is also a grant to the new owner X: the thing gets explicit secrets if it had derived ones, boxed to X; it is given a label X can read; the commit is delivered as a grant (spec/sync.md §3). X then rotates every role secret and re-registers label keys.
- **New identity**: after record H on thing T, `hash(T, H)` (TBD) is a tid owned by X by construction; writes under it verify through X's chain alone.
- H's validity (its signer's authority at H's time by the former owner's timeline) gates only the **alias** T → hash(T, H) and the **inheritance** of T's prior history into the new identity. X SHOULD write a content snapshot on acceptance, which carries the inherited elements on X's authority.
- A hand-over is a revoke of the former owner's members on the thing at the hand-over's `ts` (§5.2); the signing node publishes its attestation with it. Explicit admin edges on the handed-over thing are stripped; read and write edges carry over; an actor's own member edges are unaffected.
- **Fork**: a record with two or more valid successors. **Derived identities**: a thing K whose owner chain passes through a handed-over thing F has, in branch H_i, the identity hash(K, H_i), applied per fork level. Without a fork nothing below F is renamed.
- **Alias resolution** (read-time; stored values are never rewritten): a tid resolves one step while its record has exactly one known valid successor; if every successor names the same new owner, to the successor with the lowest record hash. A tid that does not resolve, held in a value of thing R, resolves (1) to the branch, if exactly one, in which R's owner chain holds rights (owns a thing in it, or is a member by an edge written in that branch after the fork; edges from before the fork count in every branch and decide nothing); else (2) by the reader's person actor's `/follows` entry for the fork record (written by the first of its devices that meets the fork, default first seen); else (3) it dangles.
- A commit names things by the identity its writer resolved. A bare tid applies in every branch where its author's chain is valid; a derived tid in its branch only.

## 8. Purge rights
A delta's retention names who may purge it (spec/commits.md §5), judged at the request's time: `admin` the thing's current admins; `author` also the actor directly above the author node in its chain while it holds write on the thing, acting through any of its nodes; `writer` also any current writer of the thing; `nobody` no one. A purge request drops a named delta iff its author held that right at the request's time. At blind nodes a token proves the right as of the delta and the label key current membership (spec/sync.md §5).

## 9. Links
- A link consists of K, an actor owned by the sharer and made a member of the target with the link's role, and L, a key actor whose seed is in the link, with edge (role r, invite r) on K for the link's role r. The sharer's actor is K's only admin. The link encodes: L's seed, the target tid, a server address, the target's label and K's label (layout TBD).
- **Redeem**: derive K's secrets and L's key from the seed (or, once K has rotated, open L's boxes from L's mailbox, spec/crypto.md §3), then, signing as L, invite-grant the redeemer's actor (or a fresh node) to K with role r and seal K's secrets to it. L writes in commit form and deposits the commit under K's label (spec/sync.md §5) unless r is write or above.
- `until` on L's edge expires the link; single use = the redemption also removes L's own edge in the same commit (a self-removal). Both are finalized by a sharer device writing a plain removal of L (§5.1).
- **Bearer use**: act as L without writing anything. Read only.
- The sharer keeps the seed on K under an admin-only aspect, registers L's mailbox at the link's server and writes L's `/keys`.
- **Recovery card**: recovery key seed, person actor tid, home label, server (layout TBD). The recovery key is a member of the person actor with a box in its `/secrets`; its mailbox at the card's server receives the person's rotations with `/label` and `/created` (spec/sync.md §3), so a device holding the card can rejoin.
