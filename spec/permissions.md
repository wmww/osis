# Permissions
> Summary: Actors, membership and ownership; role secrets and rotation; chain certificates and what travels under a label; the two-layer validity rule (membership timeline and content, both by the demoter's frontier); roster snapshots with their tenure ledger; moving a thing to a new owner (copy with imported history, `/moved` and `/was`); purge rights; share links.

## 1. Concepts
- **Actor**: a thing with role secrets (spec/crypto.md §3). A **key actor** (node, recovery key, link key) also has a signing key committed by its tid and owns itself. A **node** is a key actor whose seed never leaves its device. A **person actor** represents a user; its nodes are its members (by app convention its owner is a recovery key and its nodes are its admins).
- **Ownership**: every thing has exactly one owner actor, fixed by its creation record. An actor is a thing, so it has an owner too; owner chains end at a key actor.
- **Membership**: an edge (member actor, target, role) with roles read < write < admin, stored in the target's `/members`. On an actor it grants the role on everything the actor owns; on a plain thing, on that thing only.
- **Effective role** of a node on a thing at time t: the maximum over paths from the node to the thing of the minimum role along the path, where a path climbs membership edges and owner links (an owner holds admin on what it owns). Evaluated with each timeline (§5.1) at t.
- **Admin** = write + change membership + purge (§8). An admin edge on a plain thing grants membership changes and purge on that thing.
- An actor's owner is implicitly its admin and cannot be removed by other admins. Other admins are equal and may remove each other.
- The membership-class aspects of a thing (spec/data-model.md §9) are written only by its admins, whatever other role a node holds, except invite grants and self-removals (§2), and what rotations and re-seals write into `/secrets` and `/keys` (§3).
- Group membership (`/group`) grants no rights.

## 2. Membership writes
- Grant, change and removal of an edge are writes to the target's `/members`, each in its own membership commit (spec/commits.md §2), by a node with admin on the target.
- An edge may carry `until: timestamp`: the edge counts as removed at that time.
- An edge may carry `invite: role`, at most its role. A node's **effective invite** on T is the maximum over its paths to T of the minimum of the roles along the path before the last edge and that edge's invite. An **invite grant** adds an edge for an actor with no current edge on T (an expired edge counts as none), with role and invite at most the author's effective invite, and carries the grantee's boxes for those roles. Invite holders cannot change or remove any other edge.
- **Self-removal**: a node with admin on actor X may always remove X's edge on any target, or lower its role, invite or `until`.
- A write that grants, changes or removes an edge whose member is actor G MUST also be published under G's home label, so G's admins know what G is a member of.
- The roster apps read from `/members` is the membership timeline's roster (§5.1), not the CRDT join of the stored deltas.

## 3. Secrets and rotation
- Each role secret of an actor is sealed to every member holding that role or higher, every epoch (spec/crypto.md §4).
- A plain thing uses derived role secrets until it gets a non-owner member; it then gets random secrets of its own, boxed to its owner and each member.
- A removal or demotion of member M on actor A (a device removal is one, on the person actor) requires rotating every role secret M could open through A: on A the roles M held, and on every thing with secrets of its own that A's roles open (what A owns, the targets of A's edges, and so on transitively) the roles A holds there. Content is not re-encrypted. Each rotation is required of whoever may make it, when it next encrypts (below); nobody is required to sync anything to find it.
- **Who rotates**: a node with effective role write or above on an actor may rotate its roles at or below that role (a writer rotates read and write, an admin all three). A rotation seals the new secrets to every current member of each rotated role, writes the history boxes and the rotated roles' keysets in `/keys` (spec/crypto.md §3, §4); the other roles keep their epochs. Its validity is the author's role at its `ts` (§5.2).
- A node that may rotate a required rotation MUST do so before it next encrypts under a secret it would replace (spec/crypto.md §4); it MAY rotate eagerly.
- **Re-seal**: a node that may rotate a role may instead write a current member's boxes for that role's current epochs, changing nothing else (spec/crypto.md §4), delivered as a grant blob (spec/sync.md §3).
- Label role keys (spec/sync.md §2) derive from the newest epoch of each role; only an admin registers them, and an admin that holds an epoch newer than a server's head issues the next step at once (spec/sync.md §5).
- A blind node serves a label only to holders of its current sync key or of a claim key in its current step (spec/sync.md §5); a member that missed rotations claims its way through the steps it missed, then downloads them and opens each under the epoch before it (spec/crypto.md §5), or is re-sealed.
- A node that learns it lost read access to an actor MUST drop those role secrets and every local unit it can no longer read by another path.

## 4. Verifying authors: certificates
- A write's authority is checked through the chain from the signing node up: each link is a membership write or an owner link (tid commits to the owner), ending at a key actor whose tid commits to its public key. No secrets are needed.
- **Chain certificates** of a node: for each thing on its chain, the `/created` record, the epoch start (§6, projected to the entries the chain needs), the later membership writes that establish each edge, and the current `/keys` commit of each actor on it. Its **node card**: its `/keys`, `/node` and `/reach` commits (each a commit of its own touching nothing else).
- When a node first places anything under a label, and whenever they change, it places its chain certificates and node card under that label (spec/sync.md §3; a non-writer of the label by deposit). `/reach` goes under every label by default; an app MAY exclude labels (e.g. public or bearer-read ones). Without it, co-readers of that label cannot dial the node off-LAN.
- **Heartbeat**: a node MAY place under a label it tracks a commit writing `/seen` on its node thing (value: the commit's `ts`) with `expires` no earlier than `HEARTBEAT_MIN_LIFETIME` (1 day) and no later than `HEARTBEAT_MAX_LIFETIME` (14 days) after `ts`, at most once per `HEARTBEAT_MIN_INTERVAL` (6 hours) per label; a non-writer by deposit. The live `/seen` of a node under L is its last sync of L; absent means unknown. Heartbeats are never promoted (spec/sync.md §5). The node card itself is never re-placed unchanged.
- Any member that syncs a label and holds a revoke or roster snapshot about an author seen under that label places it there (a non-writer by deposit), with the chain certificates of that commit's own author.
- A grant is accompanied by the target's current `/label` commit; the grantee's current `/keys` commit goes under the target's label as a certificate, so every admin can seal and list the grantee.
- A commit whose author's chain has not arrived is pending (spec/commits.md §4).
- A node that does not sync a thing applies the certificate deltas it holds; its timeline for that thing runs over the entries it was given.

## 5. Validity
Validity is a deterministic function of the commits a node holds.

### 5.1 Layer 1: membership timeline (per thing that carries edges)
1. Order membership writes by (`ts`, author node). Start at the thing's epoch start (§6) if one applies, ignoring writes ordered before it; else at the first held write.
2. Walk the writes, skipping the drop set D (initially empty). A write applies iff its author has the required authority at that point: admin on the thing; for an invite grant, the effective invite it needs; for a self-removal, admin on the edge's member.
3. Attribute each membership write to the highest authority its author held at its point, owner chain before edge, admin before invite.
4. When an applied write R by node A at time T demotes actor X (from admin to below, or removes an edge with admin, or lowers or removes X's invite), every earlier applied membership write by X attributed to the removed authority that R's **frontier** does not cover is added to D, and the walk restarts. Removing X from actor G audits X's writes made as G's admin on G and on everything G owns; demoting X's edge on a thing audits only what X wrote on that thing by that edge.
Self-removals are never added to D. Each membership write of a commit is judged on its own.
5. The first walk that adds nothing to D is the timeline. D is rebuilt from scratch whenever the held set changes.
- **Frontier**: R embeds what A had received of X's writes as of T on the aspects R puts in question (membership-class aspects for any demotion; every aspect of the things the demoted authority gave write on, for a demotion below write): per (tid, ak, node of X) the counter up to which A had received X's writes contiguously, plus the commit IDs of X's commit-form writes. Received means decrypted and verified, not stored or relayed; a frontier MUST NOT cover what A had not received as of T. A's own chain writes and R itself always count. Nothing but the frontier decides what X's writes before T survive.
- A demotion by `until` or by self-removal audits nothing. The next explicit demotion of that member by another node audits with its frontier as if the member still held the role.
- The effective role of a chain at time t is the minimum over the timelines along it.

### 5.2 Layer 2: content
- A content write by an actor authorized at its time is valid.
- A write by an actor revoked at time T_r (by a valid removal or demotion below write) is valid iff the revoke's frontier covers its dot, the frontier of the ledger tenure it fell under covers it (§6), or a valid compaction snapshot by an authorized writer carries it (§6, Content).
- A re-grant makes every write of the re-granted actor valid again, including those in the gap. Membership writes in the gap stay invalid.
- A revoked actor cannot reuse a covered dot: two commits by one node with overlapping node-form ranges on one aspect are both invalid (spec/commits.md §4).
- A write that becomes invalid is un-merged (spec/crdt.md §4.6).

### 5.3 Revoking (client behavior)
Before stamping a role-lowering membership write a client SHOULD sync the labels it tracks for the affected actor and the things under it, with a short timeout, and take the write's `ts` after applying what it downloaded. An explicitly backdated revoke skips this.

## 6. Roster snapshots
- A **roster snapshot** of thing N is a membership commit with the roster-snapshot marker, by a node acting through N's owner chain (admin of N's owner actor or of an actor above it, or the key actor at the top; never by an edge on N). It carries reset-plus-full-state deltas of N's membership-class aspects as the author's timeline computes them: `/members` as one delta per edge (each carrying the reset stamp and that edge; an edge of role write or above also carries `since`, the (`ts`, author node) key of the write that established it, absent if unknown), plus `/label`, `/secrets`, `/keys`, and the **tenure ledger** (`/tenures`). It has no frontier.
- **Tenure ledger**: one entry per tenure of role write or above on N that ended before S: member, role, `since` as above, `until` = the key of the ending demotion (a demotion from admin to write ends an admin tenure and starts a write tenure), and the frontier of the explicit demotion that ended or last audited it (§5), absent while it ended by `until` or self-removal and nothing audited it since. The previous epoch start's ledger is carried forward whole; entries are never dropped.
- **Epoch start**: N's newest snapshot S whose author had owner-chain authority at S's time by the timelines above N, and that no later demotion of its author dropped (a demotion with a time before S, or a frontier not covering S). Writes ordered before S are ignored. S's roster and ledger answer what role anyone held on N before S: a member held a role at a point inside one of its ledger tenures of that role, or after its roster edge's `since` and after every ledger tenure of its own; a roster edge without `since` counts from the beginning. A membership write by X ordered before S, made by authority through N, is dropped iff the frontier of a ledger tenure of X ending after it does not cover it. A demotion of X after S audits X's writes before S too, including those under tenures without a frontier.
- A certificate copy of S is projected to the edges and ledger entries the verifier needs and omits `/secrets` and `/label` (spec/sync.md §3).
- S replaces N's membership commits ordered before it (their writes die at S's `ts`); their retention keeps them at least `MEMBERSHIP_KEEP` after that (spec/commits.md §5).
- **Content**: a compaction snapshot by writer W carries its elements on W's authority: an element is valid if the snapshot commit is valid as W's content write. Once a node holds a snapshot whose frontiers cover a commit, that commit's own validity no longer matters at that node.

## 7. Moving a thing
- A thing never changes owner. Moving thing T to a new owner X is a **copy**: X creates a thing M (owner X, fresh nonce) and imports T's history into it. Membership on M is X's to grant; nothing carries over by itself.
- `/was` on M (register, tid): the thing M continues. `/moved` on T (register, tid): the thing T continued as. Both are membership-class, written by the thing's admins.
- **Import commit**: a content commit on M with the import marker. It carries no own writes (empty counter ranges). Its deltas carry writes taken from commits of other things (the **origin commits**: ordinary commits, whose own-source writes are imported, or snapshots, whose carried writes are imported), re-sourced: a write of origin commit C gets the dot (`Commit(C)`, k), k its counter in C for an own-source write, else its rank by (source, counter) among the writes C carried on that aspect, and keeps its `ts`; dots the imported writes reference (anchors, reset stamps) are mapped the same way. A write is imported from one origin: its own commit where the importer holds it, else a snapshot carrying it. Native writes never use another commit's ID as a source, so imported dots collide with nothing and importing C twice yields the same dots. The header's **origins** table gives, per origin commit, its ID, author node, actor and `ts`. Each delta carries its origin delta's retention. Writes with an expiry, writes purged at the importer, and writes invalid at the importer are not imported.
- An import is valid iff it is valid as the importer's content write on M (§5.2); its elements stand on the importer's authority (§6, Content). For §8 and delete tokens (spec/crypto.md §7) the author of an imported delta is its origin commit's author.
- **Resolution** (read-time; stored values are never rewritten): a tid t held in a value of thing R resolves to the held thing M with `/was = t` in which R's owner chain holds rights (owns M, or holds an edge on M or on an actor that owns M), if exactly one; else to the tid t's `/moved` names, if the node holds t and it names one; else to t. Resolution repeats from the result up to a bound (TBD). A commit names things by the tid its writer resolved; an app pins a reference by writing it.
- Moving a thing between actors of one tree needs no copy: rights are edges (§1), only the owner is fixed.

## 8. Purge rights
A delta's retention names who may purge it (spec/commits.md §5), judged at the request's time: `admin` the thing's current admins; `author` also the actor directly above the author node in its chain while it holds write on the thing, acting through any of its nodes; `writer` also any current writer of the thing; `nobody` no one. A purge request drops a named delta iff its author held that right at the request's time. At blind nodes a token proves the right as of the delta and the label key current membership (spec/sync.md §5).

## 9. Links
- A link consists of K, an actor owned by the sharer and made a member of the target with the link's role, and L, a key actor whose seed is in the link, with edge (role r, invite r) on K for the link's role r. The sharer's actor is K's only admin. The link encodes: L's seed, the target tid, server addresses, the target's label and K's label (layout TBD).
- **Redeem**: derive K's secrets and L's key from the seed (or, once K has rotated, claim K's label by L's static entry, take K's read secret from the current step's entry box, then L's boxes from the rotations, spec/sync.md §2, §5), then, signing as L, invite-grant the redeemer's actor (or a fresh node) to K with role r and seal K's secrets to it. L writes in commit form and deposits the commit under K's label (spec/sync.md §5) unless r is write or above. A redeemer SHOULD discard the seed afterwards.
- `until` on L's edge expires the link; single use = the redemption also removes L's own edge in the same commit (a self-removal). Both are finalized by a sharer device writing a plain removal of L (§5.1).
- **Bearer use**: act as L without writing anything. Read only.
- A joiner that may still hold the seed is revoked only together with L (it could otherwise go on reading as L); a new link is a new L.
- The sharer keeps the seed on a thing only its own actor reads and writes L's `/keys`.
- **Recovery card**: recovery key seed, person actor tid, home label, several server addresses (layout TBD). The recovery key owns the person actor, so every step of the home label lists it with an entry box; a device holding the card claims the home label's current step by the key's static entry (spec/sync.md §5), takes the read secret from the entry box, then its boxes, `/label` and `/created`.
