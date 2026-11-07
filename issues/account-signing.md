# Sign as the account; no per-node data in groups
> Summary: Direction (Tess): outsiders verify a commit as from its account by an account signing key every node of it holds; the node's own signature travels encrypted to the account's own nodes, so only they see which node wrote it. Groups then carry no per-node data: no chain certificates of nodes, node cards, `reach.0` or heartbeats under every sync ID. Removing a node rotates the account key; own nodes vouch for siblings' late old-key writes. Prerequisite of issues/net-rework.md.
> Priority: normal
> Tags: perm, crypto, sync, spec, tess-call

## Today
- Every commit is signed by a node key. Readers check it against the node's chain to an account with rights, so each node places its chain certificates and node card (`keys.0`, `node.0`, `reach.0`) under every label it syncs, readers by deposit, plus `seen.0` heartbeats (spec/permissions.md §4, spec/sync.md §3). Per (node, label); about 13 KB once and 2.4 MB a day under a 1000-member label (notes/chat-cases.md, footnote 44), redone under every label when a node is added or its card changes.

## Design (direction)
- **Signing**: each account has a signing key per epoch, held by every node that may act as it. A commit is signed with it; outside the account that is all there is. The commit also carries the node's own signature over the same digest, encrypted under a secret only the account's own nodes hold. They judge which node wrote it by the account's roster, as today.
- **Validating** outside the account: the account's signing epoch was valid for the commit, and the account's roles on the target, judged as any actor's (spec/permissions.md). No node list, no chain certificates of nodes.
- **Removing a node**: rotate the account's signing key, like a read rotation. Old-epoch commits the rotator had received count, as for any removal. An old-epoch commit arriving later counts once an own node, seeing that its inner signature is not a removed node's, vouches for it under the new epoch. So an offline sibling's writes survive and the removed node's do not.
- **Connections** prove the account by its signing key (issues/net-connect.md, net-shared-set.md); a node's identity is shown only to its own account's nodes.
- **Leaves groups**: chain certificates of nodes, node cards, reader deposits of them, heartbeats, `reach.0`. What each did, and where it goes:
  - authorization of a node: the account signature (above);
  - `reach.0`: own nodes' addresses under the account's own sync ID; other accounts' nodes are not found off the LAN for now (issues/net-connect.md);
  - heartbeat `stranded` (the re-seal trigger): exchanged with a connected holder that may re-seal, else a message to the group's admins' inboxes (design);
  - heartbeat suspect lists (repair, spec/sync.md §7): exchanged on a connection;
  - `last_sync`: the node's own record of its passes.
- **Stays**: write stamps for nodes that cannot read (per sync ID write keys); key actors (link keys, recovery keys) sign as themselves.

## Open
- (Tess) A thief node rotating the account key concurrently with the owner: a fork outsiders cannot judge by node. Today's admin-dispute rule, at the account level; the account recovery system (later, known gap: issues/recovery-redesign.md) is the real answer.
- (Tess) An author acting through an intermediate actor (an account holds write on a realm R, the group grants R): validating needs R's roster at the account level. Whether every actor's roster is readable by readers of what it holds a role on.
- (Tess) issues/net-rework.md Decided lists peers that cannot read in a group's data by key plus hints: per-node data in a group. Proposed: list the account of such a box (an ordinary node with an account of its own, issues/net-one-peer.md), not the node.
- (design) Which role lets a node sign as its account; nodes acting for several accounts; the vouch commit's shape and bound (notes/arbitrary-values.md).
- (design) Inner-signature size per commit against spec/requirements.md Cost (a fixed overhead of a few hundred bytes).

## Spec to change
spec/requirements.md (Permissions: "attributable to a signing key actor (normally a node)" becomes an account, its node visible to its own nodes; Tess approved the direction), spec/permissions.md §4 (chain certificates, node card, placing, heartbeat), spec/crypto.md (account signing keys, inner signature), spec/sync.md §3 (certificate blobs), spec/data-model.md §9 (`reach.0`, `seen.0` placement), spec/wire.md (commit header).
