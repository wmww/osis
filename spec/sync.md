# Sync
> Summary: Overview of sync: its words, the one-node model, the two ways a node holds a sync ID (read, kept unread), the principle of each area and the map of the sync spec files.

## 1. Words
- **Sync ID** (S): the unit nodes sync, made by a thing with role secrets of its own (spec/sync-ids.md §2). Each such thing has exactly one, for its life.
- **Entry**: a blob held under S in a node's own store, with its wrap and its stamp or deposit flag (spec/sync-ids.md §5). A node **logs** an entry in its own store; an entry is **held at** a peer when that peer's stream showed it there (spec/sync-streams.md §4); a peer **pulls** what it lacks.
- **Peer**: another node a node has a connection to. A **source** of S at a node: a peer with S open on a connection up now (spec/sync-opens.md §4). Connections, peers and sources are the only network roles; no node is of a kind.
- **Node closure**: what a node holds, walked from its node root by strongs (spec/sync-set.md §2); its **sync set** is the sync IDs it syncs; a sync ID carries its thing's **sync unit**.
- **Read secret** of a thing: its read-role secret at some epoch (spec/crypto.md §4). **Sync secret**: its sync-role secret, held by every holder of sync or above (spec/permissions.md §1).
- **Writer** of S: a holder of S's head's write key; it **stamps** entries. A non-writer **deposits** (spec/sync-inbox.md §3).

## 2. One kind of node
- Every node runs the same protocol and the same rules. Whether a node reads data is a property of the pair (node, S), never of the node: per S a node either holds S **read**, holds it **kept unread**, or does not sync it (§3).
- Every node holding S keeps one store of S's ciphertext (spec/sync-ids.md §5), serves it to every peer S is open with, and pulls S from every source (spec/sync-streams.md §4), whoever dialed. A peer's store changes only by its own judgement of what it pulled and by the Deposit items, Registers and Deletes it takes (spec/sync-ids.md §6, spec/sync-inbox.md §3); nothing else writes into another node's store.
- What a node syncs is decided by its node closure alone (spec/sync-set.md §2); which peer it syncs S with is decided by each side alone (the open rule, spec/sync-opens.md §4). No list of peers or of sync IDs to serve exists.
- Every feature works with no server, relay or internet: on a LAN, on a mesh, through any willing node.
- **Transport boundary**: sync sees only connections: an ordered, confidential byte stream with an authenticated static key per side, a route rank and a dial by key, and the dial candidates discovery finds (spec/sync-transport.md §1). Whether a peer is reached by QUIC, a relay, a LAN, Bluetooth or a mesh hop changes no rule above that boundary; a transport is added below it without touching sync.
- **Work in proportion to change**: every rule is driven by events (an entry logged, pulled, deleted or expired; a secret, roster, head or closure change; a connection up or down). Each event re-judges only what it touches: the entries of the commits and aspects it changes, the sync IDs whose credentials or closure it changes, the connections whose shared set it changes. No rule re-derives a whole sync ID, store or connection on a timer, and an idle node does no per-sync-ID work.

## 3. Two holdings
A node holds S of thing T, at each moment, by the secrets it holds of T:
- **Read**: it holds a read secret of T. It judges every entry by the full rules (spec/sync-judgement.md §2-§5): what S must hold, may hold and must not hold, and acts on it.
- **Kept unread**: it holds a sync secret of T and no read secret. Of T it holds only its sync secrets and the sync IDs it keeps for T (below): no roster, chain, `keys.0`, commit or other state of what S carries, but the role commits that judge its tickets (spec/sync-set.md §2 What a held ticket does). It keeps ciphertext, relays it, verifies stamps, deposit signatures and delete signatures, and follows only its own grant: the sync secrets it holds, from tickets that open here and its own earlier reading (Held sync secrets, below), and the steps registered with it (spec/sync-judgement.md §6).
- One predicate decides: read exactly while a read secret of T is held. A change of holding never empties the store (spec/sync-judgement.md §6 Read and unread move).

**Kept sync IDs.** Principle: a node keeping T unread trusts only what it holds: a ticket's sync ID is its issuer's word, kept for every thing whose ticket names it, whatever order the tickets came in; only a step on the node's own path bearing the sync key of a held secret keeps S's entries. Nothing the granter, a roster or a chain says is needed or used.
- **Kept for T**: the sync ID of each ticket for T the node holds and can open (spec/sync-set.md §2), but one closed here (spec/sync-judgement.md §6 Closes), and, from its own reading, the sync IDs T owned as it judged them (spec/sync-ids.md §4 Owner) when it stopped reading T while holding a sync secret of it (spec/sync-judgement.md §6 Read and unread move).
- **Held sync secrets** of T: those of the tickets for T it holds that open here, and those it held of T when it stopped reading it.
- **S's things**: every thing S is kept for (spec/sync-inbox.md §5 Ticket sync IDs). S is kept unread for each of them alike (spec/sync-set.md §2): the held sync secrets of each are shown (spec/sync-opens.md §4) and keep S at a head whose key one derives (spec/sync-judgement.md §6), and each one's tickets' profiles are dialed for S (spec/sync-opens.md §1). A secret no step of S's path bears keeps nothing and proves nothing there, so a thing claiming S by a forged ticket changes nothing a step decides.
- It syncs only the sync IDs it keeps; the node keeps this state as its own, and shares none of it with its account's other nodes but D's tickets for T (spec/sync-set.md §1 The account's tickets).

## 4. Areas
Each area has one principle; every rule in its file follows from it, and a rule whose reason does not follow from its principle is a defect of the rule, not an exception to the principle.

| area | file | principle |
|---|---|---|
| 1. What a node holds | spec/sync-set.md | A node holds exactly its node closure: what its node root reaches by strongs, entering a thing with own keys only by a ticket it can open or keys it holds; a sync ID carries exactly its thing's sync unit; nothing else decides. |
| 2. Sync IDs | spec/sync-ids.md | A sync ID belongs to its thing: made once from the thing's own secrets, its keys derived from the thing's current role secrets, its path of steps verifiable from genesis by any node without trusting a peer. |
| 3. Connections and opens | spec/sync-opens.md | Each side opens S toward a peer only on its own proof, judged on what it holds now, that the peer may hold S; who dialed proves nothing. |
| 4. Judgement per sync ID | spec/sync-judgement.md, spec/sync-compaction.md | A reader's store of S holds what its own judgement says S needs, and a body leaves it only for a reason every holder sees after one exchange (expiry, purge, a right holder's covering snapshot, or S not needing it); a node acts at a peer only over what that peer's stream showed, deletes there only by a Delete signed for the right, and every delete and every logging again is bounded by a change of ground. A node keeping S unread judges nothing but signatures. |
| 5. Inbox, open signals, deposits | spec/sync-inbox.md | An inbox is a thing like any other; a deposit is the one way a non-writer adds an entry, taken by any holder whose verification it passes, whoever offers it; a ticket grants nothing and makes nothing sync: only a strong in the node closure does. |
| 6. Streams and flow control | spec/sync-streams.md | Every node pulls each open sync ID from each peer by one stream over that peer's node log; a push only continues a pull, and a gap is repaired by reading again, never by trusting order. |
| 7. Status | spec/sync-status.md | Status says only what is true now, per sync ID, of the sources connected now. |
| 8. Hostile peers | spec/sync-hostile.md | A peer's word changes only what that peer holds; nothing it says is taken as identity, authorization or deletion, and every message costs bounded work. |
| Transport | spec/sync-transport.md | Sync needs only an ordered, confidential byte stream with an authenticated peer key. |

## 5. Constants and policy
Constants are spec/wire.md §2. A node's own timing values (`resync_ms`, `REDIAL_MS`, `DIAL_TIMEOUT_MS` and the like) are local policy unless spec/wire.md §2 fixes them; each passes the zero-and-infinity test of its class (the rule that uses it states what happens at each end).
