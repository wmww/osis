# Finding the shared sync IDs
> Summary: Design, after the identity exchange (issues/net-connect.md, Rules): with a peer that proved a known actor, each side sends a compact filter of secret beacons (one per held sync ID and current epoch) and offers by roles the sync IDs where it knows the peer's actor as a current holder, each offer carrying its epoch beacons. An offer opens when the receiver either shares one of its epochs as current or judges the offerer a holder. Covers every pair of holders that can be matched without showing a sync ID to its removed holders. Deposits: a deposit beacon in the filter. Two beacon kinds, three new messages. Reconnects send only changes (issues/net-reconnect.md). Part of issues/net-rework.md.
> Priority: normal
> Tags: sync, node, proto, crypto, spec, security, tess-call

## Today
Neither node sends its set. Each works out the overlap from data it holds: saved peers a `label.0` lists, and co-readers (node things with a held `reach.0` that may read the group, core/node/src/sync/conn.rs `wanted_labels`). The dialer then opens them one by one with a proof (proof 3 for co-readers). Two nodes whose node cards never crossed open nothing with each other, even both holding the same thing.

## Given (Tess)
- Connect, then identify, then share: both sides prove the actors they act for (node key, chain to its account, key actors such as a link key it redeems). The shared set runs only with a peer that proved a **known actor** (one whose keys this node holds). Two accounts that hold T but know neither's keys do not share directly (accepted for now). Identity is shown only to known actors (spec/requirements.md; the private handshake is issues/net-connect.md's).
- Who proves first: on a LAN, issues/net-connect.md's private recognition. Off the LAN the dialer first: it dialed a key from group data that the transport authenticated, so it knows whom it reached; the listener proves only to a dialer that proved a known actor, so dialing a node shows the dialer nothing.
- Shows nothing about sync IDs the peer does not hold; knowing a sync ID is not holding it; a removed holder stops matching; two current holders a rotation apart still match; no fallback path.

## What can be matched at all
A node may show a sync ID L to a peer only once it is sure the peer is not a removed holder of L it knows about. A removed holder E has every epoch, roster and step the node had before the removal; it lacks only epochs made after it and the private keys of current holders. The handshake now proves the keys; what is left is proving an epoch. So P's sync ID L opens with Q in exactly these cases:
1. **Shared current epoch**: P and Q hold a common current epoch of L (spec/crypto.md §4 Current). Needs no role knowledge.
2. **Ahead, knows the other**: Q knows P's proven actor as a current holder of L and holds P's current epoch (Q is ahead): Q offers, P accepts by the epoch proof.
3. **Each knows the other**: each judges the other's actor a current holder of L, whatever their epochs (concurrent rotations, a healed partition).

Not matched, and unmatchable without showing L to a possible removed holder: (a) a holder no node it meets knows as one and whose epoch none shares as current: a rotation that did not know its grant left it without a box, so it is stranded anyway, and any node that knows its grant finds it (case 2 or 3) and re-seals it (spec/permissions.md §3, §4); (b) two nodes on different branches of concurrent rotations where only one knows the other: the other cannot tell it from a removed holder; they sync once either meets a node it can match (old members of both branches match by 3 and merge the fork). A removed holder still matches a node that has not seen the removal: that node cannot tell, under any design.

Why this is not the rejected "overlap from roles" design: the role part only ever offers to a holder the offerer knows, and case 1, where both sides are stale about each other's grants, needs no roles at all.

## Beacons
A beacon is BLAKE3 keyed by a credential key over both proven node keys (sorted): stable for the pair (so the peer can keep it, issues/net-reconnect.md), meaningless to anyone else.
- **Secret beacon**, per held sync ID L and each current epoch e of L's read role: key `kdf("sync id beacon", read secret of e, sync ID)`. A link seed is the same kind for its K (issues/net-first-contact.md).
- **Deposit beacon**, per inbox with a pending delivery (an actor's sync ID the node cannot read, issues/net-role-sync.md): key `kdf("deposit beacon", X25519(own node KEM key, recipient's read-role KEM key), inbox sync ID)`. Only the recipient's holders can compute it.

## Messages
```
Beacons   [id, gen, Opt(base), [lo, hi, gcs], [removed*]]   -> Status   pages of the filter
Offer  [id, [[sync_id, [beacon*]]*]]                        -> Status [id, [code*]]
Lost   [[sync_id*]]
```
- **Beacons**: a Golomb-coded set (BIP 158 style) of the beacons' 64-bit hashes, Rice parameter P, in pages over disjoint ascending ranges `[lo, hi)` of the hash space, each within `MAX_MESSAGE`. First contact: every beacon, no base. Later: changes since `base` (issues/net-reconnect.md).
- **Testing**: the tester looks up its own secret beacons at its current epochs, and deposit beacons for the inboxes of its own actors.
- **Offer**, one item per sync ID, two sources:
  - a filter hit: the item carries the hit beacon;
  - by roles: for each sync ID not yet open where the offerer knows the peer's proven actor as a current holder, the item carries the offerer's secret beacons at every epoch of L it holds.
  The receiver opens L both ways when it holds L and either one listed beacon is its own at a current epoch (cases 1, 2) or it judges the offerer's actor a current holder (case 3). Holding L but neither: it refuses, showing nothing (the offerer's offer was to a holder it believed in, so the code says only what it already assumed). A filter hit that is no beacon of the receiver's (a false positive) is refused; it shows nothing, the beacon being a PRF output.
- **Lost**: a sync ID leaves the set (a removal, a credential that no longer holds, a sync ID dropped).
- A deposit-beacon hit is offered like a filter hit; the sender then deposits there (spec/sync.md §5 Deposit, no open). Until taken a delivery stays pending (issues/net-first-contact.md).
- Mid-connection, a node that gains a sync ID or epoch tests the filter it holds, sends a `Beacons` page of its new beacons, and offers by roles where it now knows the peer as a holder.

## Opens
An open by offer holds while the server would accept the offer again: a shared epoch still current there, or the requester's actor still a current holder there. On a rotation or role change the server judges again and, failing, ends the sync ID after pushing what ends it (the rotation commit and step, as spec/sync.md §5 does for a head), then sends `Lost`; a requester that holds the new epoch offers again. Readers serve a peer behind them by its actor, so claims and step walks are needed only at peers that cannot read.

## Peers that cannot read
They prove their node key like anyone, hold no secret and no role, and send or test no beacons. Readers know which groups such a peer serves from group data (decided) and open there by sync-key proof or claim, as today. Two such peers find nothing with each other; whether they replicate is issues/net-one-peer.md's.

## Costs
At first contact a side sends one entry per held sync ID and current epoch, about (P + 1.5)/8 bytes each: P = 8 gives about 1.2 B (12 KB at 10^4 sync IDs, 120 KB at 10^5), and the tester hashes once per own entry. Role offers go only for sync IDs the filter did not open (epochs apart), about 16 B plus 32 B per epoch each. Nothing scales with roster sizes.

## Leaks
- A known-actor peer that shares nothing learns the node's count of sync IDs and current epochs, and a few false-positive offers.
- The identity the handshake shows is the connecting layer's (issues/net-connect.md, issues/privacy.md).
- A deposit beacon shows a delivery only to the recipient's holders; a hit shows the depositor the peer serves that inbox (it delivers there, so it must learn that).

## DoS
- Pages out of order or overlapping are malformed (Error 2, close): each own query meets one page, so testing costs linear in bytes received plus one pass over own beacons. A sender cannot raise the false-positive rate (`1/2^P` per query whatever it sends).
- Offer and Lost items are O(1) each plus their beacons, within the per-message list caps.
- At most one test pass per peer in flight; pages arriving meanwhile join the next.

## Replaces
`wanted_labels`' co-reader and link-route parts and per-sync-ID Open between readers; open proof 3, `PeerStore::co_reader_open` and `reach_nodes` as a serving check; claims between readers (kept for peers that cannot read).

## Rejected
- Sending the whole list; working the overlap out from roles alone: misses both-stale holders (Tess).
- Member beacons (epoch key plus DH with the holder's actor key) and pair hellos (static DH per pair of known actors): needed only while actors were unproven; the handshake proves the keys, and role offers with epoch beacons cover the same cases at no per-roster cost.
- Accepting role offers without an epoch proof or role judgment: a removed holder offering to a holder it remembers would learn who still holds L.
- Beacons at past epochs in the filter: shows current holders to everyone who held an old epoch. (In a role offer they go only to a holder the offerer knows, who learns nothing from them.)
- DH private set intersection: exact, but 32 B and a scalar multiplication per entry per side; the filter shows a non-holder only a count.
- A Bloom filter: works; a Golomb-coded set is about 30% smaller at the same false-positive rate and has one canonical encoding.

## Picked values
P (about 8): performance switch. 0: every own beacon becomes a refused offer, still correct; infinite: exact 32-byte beacons.

## Mechanisms, counted
- Beacons: secret (the only way to match case 1, where neither side knows the other holds L), deposit (the only way to find an inbox's holders, whose sync ID the sender cannot read and whose holders may be accounts it does not know as such).
- Messages: Beacons (the filter), Offer (opens a sync ID, from a filter hit or by roles; one rule for both), Lost (unsolicited end). Status and Error are the existing ones.

## Unsure
- Deposit beacons go to any peer that proved an actor, known or not (Tess): only the recipient's holders can compute them, so a grant to someone else's group reaches it.
- The two unmatched cases above are accepted for now (Tess).
- (design) Exact definitions of a node's own actors and of "knows α as a current holder" through nested actors and key actors (issues/net-role-sync.md).
- (implementor) Ordering role offers after filter hits so most sync IDs open by the cheap path.

## Tests (tier 1, over issues/net-tests.md)
Two nodes that never met, of accounts that know each other, find T; a node a rotation behind meets a holder granted after it (case 2); two branches of concurrent rotations heal through two old members (case 3); a removed holder matches no node that has seen the removal and learns nothing from offers; a known peer that holds nothing learns nothing but counts; a grant to an account met only on a LAN arrives; a hostile filter (overlapping pages, maximal pages) is closed or costs linear work.
