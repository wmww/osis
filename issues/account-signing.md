# Sign as the account; no per-node data in groups
> Summary: Direction (Tess): outsiders verify a commit as from its account by an account signing key every node of it holds; the node's own signature travels encrypted to the account's own nodes, so only they see which node wrote it. Groups then carry no per-node data: no chain certificates of nodes, node cards, `reach.0` or heartbeats under every sync ID. Outside, the account is a key actor with rotating keys, its node list on a private devices actor (Account shape). Removing a node rotates the account's signing epoch; per-label lists the rotation commits to play the frontier's role, and own nodes vouch for siblings' late writes (Removal, proposed). Prerequisite of issues/net-rework.md.
> Priority: normal
> Tags: perm, crypto, sync, spec, tess-call

## Today
- Every commit is signed by a node key. Readers check it against the node's chain to an account with rights, so each node places its chain certificates and node card (`keys.0`, `node.0`, `reach.0`) under every label it syncs, readers by deposit, plus `seen.0` heartbeats (spec/permissions.md §4, spec/sync.md §3). Per (node, label); about 13 KB once and 2.4 MB a day under a 1000-member label (notes/chat-cases.md, footnote 44), redone under every label when a node is added or its card changes.

## Design (direction)
- **Signing**: each account has a signing key per epoch, held by every node that may act as it. A commit is signed with it; outside the account that is all there is. The commit also carries the node's own signature over the same digest, encrypted under a secret only the account's own nodes hold. They judge which node wrote it by the account's roster, as today.
- **Validating** outside the account: the account's signing epoch was valid for the commit, and the account's roles on the target, judged as any actor's (spec/permissions.md). No node list, no chain certificates of nodes. An author acting through other actors (an account holds write on a realm R, the group grants R) is validated through their rosters: every actor's roster is readable by readers of what it holds a role on (Tess; spec/requirements.md, Confidentiality between readers). An account has no such roster (Account shape, below).
- **Removing a node**: rotates the account's signing epoch (Removal, below).
- **Connections** prove the account by its signing key (issues/net-connect.md, net-shared-set.md); a node's identity is shown only to its own account's nodes.
- **Leaves groups**: chain certificates of nodes, node cards, reader deposits of them, heartbeats, `reach.0`. What each did, and where it goes:
  - authorization of a node: the account signature (above);
  - `reach.0`: own nodes' addresses under the account's own sync ID; other accounts' nodes are not found off the LAN for now (issues/net-connect.md);
  - heartbeat `stranded` (the re-seal trigger): exchanged with a connected holder that may re-seal, else a message to the group's admins' inboxes (design);
  - heartbeat suspect lists (repair, spec/sync.md §7): exchanged on a connection;
  - `last_sync`: the node's own record of its passes.
  - nodes that store a group without reading it (issues/net-one-peer.md): not listed in the group. An account lists the nodes that serve its data (key and addresses), written by its own nodes, on a thing its co-readers read (its profile); readers find them through the accounts the group names and open what they serve by key proof. Such a node is not one of the account's nodes (it holds no account key); the account administers it. Any account whose groups a node serves (its own box, or another's by that node's consent) may list it.
- **Stays**: write stamps for nodes that cannot read (per sync ID write keys); link keys sign as themselves.

## Account shape (proposed)
Readers of what an account holds roles on may read the rosters of actors holding roles there, and an account's holders are its nodes; contacts also read the account thing (its profile). So the node list cannot live in the account's own `roles.0`.
- **Outside, the account is a key actor with epochs**: per epoch a signing key and a KEM key, committed by a rotation chain from its tid (the DAG under Removal). It holds admin on itself and shows no roster. Boxes to it are sealed to its current KEM key. A node removal rotates both keys, so a removed node opens no later box to the account.
- **Inside**: the account's keys, its nodes' grants and the inner-signature secret live on a private thing only its own nodes read (its devices actor). That thing's roster is the node list; nothing outside the account syncs it.
- **Profile**: an ordinary thing the account is first admin of, read by contacts (name, the nodes that serve its data, issues/net-one-peer.md). Not an actor.
- **Teams, bots, shared identities** whose holders are accounts stay ordinary actors with readable rosters (like realms) and act through a member account's signature; only accounts sign. spec/permissions.md §1's "account" (anything apps treat as a user, team, bot or shared identity) splits accordingly.
- Key actors gain rotating keys; today's are fixed (spec/crypto.md §3). Link keys stay fixed.

## Removal (proposed)
Outsiders on a group see no demotion of anyone when account P removes node X, only P's signing rotation, and cannot tell X's commits from its siblings'. So the frontier moves from the demotion to the signing epoch.
- **Rule**: a commit signed by P at signing epoch e counts as P's while e is open at the reader; once a rotation superseding e closes it, only where a list or vouch (below) names it by commit ID. Never by `ts`, never by counters. It filters before spec/permissions.md §5: a commit that does not count is invalid in both layers; one that counts is judged as P's there, as today.
- **Removal is the rotation**: the edge write removing X from P and the rotation of P's signing epoch are one role commit (the signing epoch rotates in the rotation X's departure already requires, spec/permissions.md §3). X is not boxed the new epoch. Rotating what P holds roles on (G's roles) is unchanged.
- **Lists** (the frontier's role): per label L of P's that the rotator can open (synced, or read for receipts only, spec/permissions.md §5.3), the list for L: every commit of P at a superseded epoch with an entry under L (parts, certificates) the rotator had received as of the rotation, X's included (the revoker's receipts, spec/requirements.md Permissions).
  - Form: the rotated keyset carries a BLAKE3 Merkle root over per-label leaves (a blinded label key, the list's digest). L's list (a chunk tree of commit IDs, no cap) and its path ride in the rotation's copy under L, which goes under every label of P's anyway (P's new keyset must reach G's writers). L's readers learn L's list, and of other labels only about log2 of their number.
  - Closing is per label: e is closed for commits under L once the node holds a list for L of a counting rotation superseding e, or a closing vouch. Before that they count as before, as a removal not yet placed under L does today; so a reader that got the rotation under L1 drops nothing of L2 before L2's list arrives.
  - A list's authority is its rotation commit, never a later epoch, so later rotations never list it again: each commit is listed once over the account's life. Lists are role history, kept as the rotation is.
- **Vouches** (late writes): at the end of a complete pass of L, a node of P holding an open epoch writes a vouch under L: a role commit of P at that epoch whose frontier names commits of P under L at closed epochs that nothing counting names, each one of:
  - signed inside (inner signature) by a node holding P's signing role in P's timeline now: an offline sibling's late writes, of any kind (the account re-signing its own commit, not a third-party witness);
  - X's plain-content commits the voucher received before the rotation's `ts`: the addenda rule (issues/revocation-without-arbiter.md), once built. Until then X's count only as the rotator received them.
  - A vouch under a label the rotation listed nothing for closes it there too. A node of P that places the rotation under such a label writes one.
  - Carrying: a node of P that holds a counting list or vouch naming c and syncs a label holding a part of c where nothing names it vouches c there. Otherwise a thing in two groups, listed under one only, would read differently by which group a reader holds.
  - A vouch is an ordinary commit at its epoch: when that closes, the next rotation lists it (one ID for its whole list). Vouches compose by union, so a long one is several commits.
  - X re-added to P holds the role again, so its old commits are vouched, backdated ones included (today's re-grant revives all).
- **Bound**: per rotation and label, one ID per commit of P under L at the closed epochs, less covered ones (below), plus a path. Over the account's life, one ID per commit (two when a vouch saved it). No picked number. Against today: per account per epoch, not per node ever; no IDs of other labels; nothing in chain certificates. Retires issues/frontier-certificate-cost.md and, for node removals, the cap in issues/unbounded-frontier.md.
- **Covered commits**: leaving out a commit covered as spec/permissions.md §5.1 says keeps lists at the uncompacted tail and kept history; a valid snapshot vouches for what it carries (Open, Tess). Purge requests are listed, never left out; a purge counts iff its commit counts and P held the right (§6). Lists name no ephemeral commit: P's ephemeral commits at a closed epoch go, and its nodes write that state again at the open one.
- **Another account's snapshot** carrying X's late writes vouches for them, as today (stated limit).
- **Demoting an account** (A, an admin of G, demotes P): today's frontier, audits, trust set and disputes, with the author an account: A lists P's commits it received, at any epoch. The epoch rule and A's frontier are independent conjuncts; so are addenda.
- **Inside the account**: P's nodes judge P's commits by the same rule, so they read like outsiders. Inner signatures decide only what they write: whom they vouch for, which fork rotations they accept. P's grants to nodes stay under P's own label. The node removal carries no frontier of its own: X's commits under P's label close by that label's list like any other.
- **Forks and a thief**: P's signing epochs form a DAG of rotations, each signed at an epoch it supersedes.
  - Rotations at one epoch do not close each other: they fork, and a merge (spec/crypto.md §4) names the fork rotations it accepts. P's nodes accept one iff its inner signature is by a node with the right to rotate at it in P's timeline.
  - A fork rotation that a counting merge supersedes without naming is void, with every epoch descending only from it. So a fork by a removed or stolen node is void once the owner's merge arrives, at every node alike, as today's removal cuts a node that does not fight back.
  - A thief that answers with a merge omitting the owner's line makes two lines, each voiding the other: an account-level dispute, settled per node by trust set and reported (notes/disputes.md option F), keyed by the two merges. A thief that rotates first, leaving the owner out, is answered by the owner forking from the last epoch it holds; at first-received defaults a thief acting first wins where its fork came first, as today (accepted).

### What else names a node
- Header `author`: becomes the account, plus the signing epoch; the inner signature (node tid, signature over the commit ID) sealed to P's nodes beside `signature`.
- The §5.1 order key `(ts, author node, commit ID)`: the account; the commit ID already breaks ties.
- Session dots `Session(tid, nonce)` (spec/crdt.md §2.2) name the node in every content write and snapshot copy: the account's tid, the nonce still random per node session. One session's commits stay linkable to each other (stated).
- Departs mark `(ts, signing node)` (spec/crypto.md §4, Names): `(ts, author, blind)`, since siblings may sign role commits at one `ts`; `blind` is 16 random header bytes.
- Trust-set seeds "by M when M is a node or by any node that reaches M": actors.
- An account's creation record names the node that made it as first admin (spec/permissions.md §1): the account's tid commits to its first signing key instead, and a node names its account, not itself, as first admin of what it makes (a node first admin is per-node data in every chain; a node delete base signs with the node key, spec/crypto.md §7).
- No node: delete keys (level 2 is the header actor's write secret), frontiers (commit IDs), possession, label and upload signatures; boxes to nodes exist only in P's own `secrets.0`.
- Per node, outside groups: dialable keys (LAN announce, co-reader open: issues/net-connect.md), inbox blobs to a node over a direct connection.

### Rejected
- One account-wide received list: shows every label's readers the IDs of P's commits in other labels, and links P's groups at hosts.
- Lists as commits at the new epoch, not committed by the rotation: each needs listing again at every later rotation, under every label P ever wrote, forever.
- Closing everywhere once the rotation is held: a reader of L1 and L2 drops L2's commits until L2's list arrives.
- Revealing the removed node's marks (a tag key per node; verifier-local-revocation group signatures): an absent mark proves nothing unless every honest signature carries one, which shows every node; such group signatures are pairing crypto outside the suite.
- Per-node signing subkeys certified to readers: per-node data under every label.

## Open
- (Tess) Covered commits in lists. The addenda decision lists every commit, compacted or not. With account-wide epochs that keeps 32 B per commit P ever wrote at every reader, past compaction (spec/requirements.md Cost: nothing O(history)). Proposed: leave covered commits out, as today's node frontier does.
- (Tess) The default side in an account-level dispute; whether winning one should need something a thief lacks (the recovery redesign, issues/recovery-redesign.md).
- (Tess) spec/requirements.md Cost on removal: "the account's writes since its last signing rotation that compaction may not drop yet"; the 1.9 million limit goes.
- (design) The closing scope ("an entry under L") restated by data (things in L's closure, P's certificates placed there), so judging stays a function of held data.
- (design) Pad the Merkle path to a fixed depth (a picked number, minor consequence) or accept the label count's log.
- (design) Whether other accounts' writers' receipts vouch for P's closed-epoch commits (addenda across accounts). Proposed no: P's rotation is the account's own word.
- (design) Model before spec: roles-model with signing epochs, lists, vouches and forks (order independence, vouches never invalidate, thief and removed-sibling attacks).
- (design) Which role on the devices actor lets a node sign as its account; nodes acting for several accounts.
- (design) Session dots and the causal shape of commits (two concurrent commits of one account come from different nodes) still let readers group some commits by node; hosts and direct peers see which connection uploaded each. State the unlinkability guarantee at that scope in spec/requirements.md.
- (design) Inner-signature size per commit against spec/requirements.md Cost (a fixed overhead of a few hundred bytes).

## Spec to change
spec/requirements.md (Permissions: "attributable to a signing key actor (normally a node)" becomes an account, its node visible to its own nodes; Tess approved the direction; Confidentiality between readers: no node identities or account node lists to outsiders), spec/permissions.md §1 (account as a key actor with epochs, teams), §3 (removal placement), §4 (chain certificates, node card, placing, heartbeat), §5 (the epoch rule, lists, vouches, order key, seeds), spec/crypto.md (account signing keys, inner signature, the signing DAG and merges, departs mark), spec/crdt.md §2.2 (session source), spec/sync.md §3 (certificate blobs), spec/data-model.md §9 (`reach.0`, `seen.0` placement), spec/wire.md (commit header).
