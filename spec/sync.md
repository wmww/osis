# Sync
> Summary: Overview of sync: its words, the one-node model, the two ways a node holds a sync ID (read, kept unread), the principle of each area and the map of the sync spec files.

## 1. Words
- **Sync ID** (S): the unit nodes sync, made by a thing with role secrets of its own (spec/sync-ids.md §2). Each such thing has exactly one, its **home sync ID**, for its life.
- **Entry**: a blob held under S in a node's own store, with its wrap and its stamp or deposit flag (spec/sync-ids.md §5). A node **logs** an entry in its own store; an entry is **held at** a peer when that peer's stream showed it there (spec/sync-streams.md §4); a peer **pulls** what it lacks.
- **Peer**: another node a node has a connection to. A **source** of S at a node: a peer with S open on a connection up now (spec/sync-opens.md §4). Connections, peers and sources are the only network roles; no node is of a kind.
- **Synced group**: the group the account lists for a node in `synced^.0` (spec/sync-set.md §1); the node's **sync set** is the sync IDs it syncs (spec/sync-set.md §2).
- **Read secret** of a thing: its read-role secret at some epoch (spec/crypto.md §4). **Sync secret**: its sync-role secret, held by every holder of sync or above (spec/permissions.md §1).
- **Writer** of S: a holder of S's head's write key; it **stamps** entries. A non-writer **deposits** (spec/sync-inbox.md §3).

## 2. One kind of node
- Every node runs the same protocol and the same rules. Whether a node reads data is a property of the pair (node, S), never of the node: per S a node either holds S **read**, holds it **kept unread**, or does not sync it (§3).
- Every node holding S keeps one store of S's ciphertext (spec/sync-ids.md §5), serves it to every peer S is open with, and pulls S from every source (spec/sync-streams.md §4), whoever dialed. A peer's store changes only by its own judgement of what it pulled and by the Deposit items, Registers and Deletes it takes (spec/sync-ids.md §6, spec/sync-inbox.md §3); nothing else writes into another node's store.
- What a node syncs is decided by its account alone (the synced group, spec/sync-set.md); which peer it syncs S with is decided by each side alone (the open rule, spec/sync-opens.md §4). No list of peers or of sync IDs to serve exists.
- Every feature works with no server, relay or internet: on a LAN, on a mesh, through any willing node.
- **Transport boundary**: sync sees only connections: an ordered, confidential byte stream with an authenticated static key per side, a route rank and a dial by key, and the dial candidates discovery finds (spec/sync-transport.md §1). Whether a peer is reached by QUIC, a relay, a LAN, Bluetooth or a mesh hop changes no rule above that boundary (a file carried by hand is a bundle, spec/sync-streams.md §6); a transport is added below it without touching sync.
- **Work in proportion to change**: every rule is driven by events (an entry logged, pulled, deleted or expired; a secret, roster, head or closure change; a connection up or down). Each event re-judges only what it touches: the entries of the commits and aspects it changes, the sync IDs whose credentials or closure it changes, the connections whose shared set it changes. No rule re-derives a whole sync ID, store or connection on a timer, and an idle node does no per-sync-ID work.

## 3. Two holdings
A node holds S of thing T, at each moment, by the secrets it holds of T:
- **Read**: it holds a read secret of T. It judges every entry by the full rules (spec/sync-judgement.md §2-§5): what S must hold, may hold and must not hold, and acts on it.
- **Kept unread**: it holds a sync secret of T and no read secret. Of T it holds only its account's **sync record** (below): no roster, chain, `keys.0`, commit or other state of what S carries. It keeps ciphertext, relays it, verifies stamps, deposit signatures and delete signatures, and follows only its own grant: the boxes that open here and the steps registered with it (spec/sync-judgement.md §6).
- One predicate decides: read exactly while a read secret of T is held. A change of holding never empties the store (spec/sync-judgement.md §6 Read and unread move).

**Sync record.** Principle: a node keeping T unread trusts only its own account. T's sync IDs come only from the account's own judgement, and a sync secret only once a step on the node's own path of such a sync ID bears its sync key. Nothing the granter, a roster or a chain says is needed or used.
- The account's sync record of T is its entry in `kept^.0` on its devices actor D (spec/data-model.md §9): T's **kept sync IDs** and its **recorded** sync secrets by epoch. Written by the account's nodes only, read by every node of the account, now or paired later, whatever inbox blobs have expired. Entries are only added.
- **A kept sync ID** is added only by:
  - an accept (spec/sync-set.md §4): the sync IDs every held boxes payload offering T names for T, but one the record keeps for another thing;
  - the account's own reading: a node that stops reading T while holding a sync secret of it (spec/sync-judgement.md §6 Read and unread move) adds the sync IDs T owns as it judged them (spec/sync-ids.md §4 Owner) and the sync secrets of T it held.
- **A recorded secret**: a node of the account adds the sync secret of epoch e of T that a box opening here gave (an inbox blob's, spec/sync-inbox.md §2; an entry box) once a step on its path of a kept sync ID (the steps registered with it, spec/sync-ids.md §6) bears that secret's sync key, unless recorded already. The secret is held as epoch e's (it names it, spec/crypto.md §4), which establishes nothing.
- **Held sync secrets** of T at a node keeping it unread: its recorded ones and those of the boxes of T in the inbox blobs it holds unexpired (spec/sync-inbox.md §2), whichever sync ID those name. Only these open S, are shown (spec/sync-opens.md §4) and keep S (spec/sync-judgement.md §6).
- It syncs only kept sync IDs (spec/sync-set.md §2).

## 4. Areas
Each area has one principle; every rule in its file follows from it, and a rule whose reason does not follow from its principle is a defect of the rule, not an exception to the principle.

| area | file | principle |
|---|---|---|
| 1. What a node syncs | spec/sync-set.md | A node syncs exactly the sync IDs of the things in its synced group's closure that it may hold; nothing else decides. |
| 2. Sync IDs | spec/sync-ids.md | A sync ID belongs to its thing: made once from the thing's own secrets, its keys derived from the thing's current role secrets, its path of steps verifiable from genesis by any node without trusting a peer. |
| 3. Connections and opens | spec/sync-opens.md | Each side opens S toward a peer only on its own proof, judged on what it holds now, that the peer may hold S; who dialed proves nothing. |
| 4. Judgement per sync ID | spec/sync-judgement.md, spec/sync-compaction.md | A reader's store of S holds what its own judgement says S needs, and a body leaves it only for a reason every holder sees after one exchange (expiry, purge, a right holder's covering snapshot, or S not needing it); a node acts at a peer only over what that peer's stream showed, deletes there only by a Delete signed for the right, and every delete and every logging again is bounded by a change of ground. A node keeping S unread judges nothing but signatures. |
| 5. Inbox, deposits, invites | spec/sync-inbox.md | An inbox is a sync ID like any other; a deposit is the one way a non-writer adds an entry, taken by any holder whose verification it passes, whoever offers it. |
| 6. Streams and flow control | spec/sync-streams.md | Every node pulls each open sync ID from each peer by one stream over that peer's node log; a push only continues a pull, and a gap is repaired by reading again, never by trusting order. |
| 7. Status | spec/sync-status.md | Status says only what is true now, per sync ID, of the sources connected now. |
| 8. Hostile peers | spec/sync-hostile.md | A peer's word changes only what that peer holds; nothing it says is taken as identity, authorization or deletion, and every message costs bounded work. |
| Transport | spec/sync-transport.md | Sync needs only an ordered, confidential byte stream with an authenticated peer key. |

## 5. Constants and policy
Constants are spec/wire.md §2. A node's own timing values (`resync_ms`, `REDIAL_MS`, `DIAL_TIMEOUT_MS` and the like) are local policy unless spec/wire.md §2 fixes them; each passes the zero-and-infinity test of its class (the rule that uses it states what happens at each end).
