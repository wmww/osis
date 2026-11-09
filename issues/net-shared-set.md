# Finding the shared sync IDs
> Summary: Settled design, one mechanism with issues/net-reconnect.md. Rule: a node shares a sync ID with a connected peer exactly while, on what it holds now, the peer may hold it; everything remembered only says what need not be sent again. A per-pair key, a per-peer Golomb-coded filter of secret beacons (additions only), confirmed hits, role offers to judged holders, a per-connection list of deposit beacons for inboxes. Nothing keyed by node identity; blocked on account signing step 6 only in what a session proves. Proposed where issues/net-peer-continuity.md and Open below (tess-call) apply. Model first. Part of issues/net-rework.md.
> Priority: normal
> Tags: sync, node, proto, crypto, spec, security, tess-call

## The rule
**A node shares sync ID L with a connected peer exactly while, on what it holds now, the peer may hold L: an actor the peer proved on this connection is a current holder of L, or the peer proved an admissible credential of L (Words).** Every other state is a cache of that judgment or of what was already sent: losing it costs bytes, never a result (issues/net-reconnect.md).

Named exceptions, each following from a principle stated with it:
- **Unknown actors get no secret beacons** (spec/requirements.md, Offline and network; Tess): the rule only runs with a peer that proved a **known actor**.
- **Deposit beacons share no sync ID**: a deposit is a delivery to an inbox; the depositor learns where to deposit (Deposits; what that shows: Open).
- **The event that ends sharing is still sent** (Opens): a holder that missed a rotation can only prove the new epoch by receiving it, as spec/sync.md §5 sends a head's last event. Liveness of a current holder; a removed holder learns a rotation happened, which it could not read.
- A node that has not received a removal cannot tell: the rule's "on what it holds now", under any design.

## Words
- **Proven actors** of a connection: the actors the peer proved on it (issues/net-connect.md, Rules): its account, key actors it holds (a link key it redeems), its own node to nodes of its own account.
- **Known actor**: one whose keys this node holds (own account, contacts, holders of anything it holds, a link key on a roster it administers).
- **Credential** of L: a secret only a holder can show. A node's credentials of L are: L's read secret at each of its current epochs (spec/crypto.md §4 Current); the seed of a link or recovery card on L's thing that it holds and whose key actor is still on L's roster in its view (spec/sync.md §5 Claim, issues/net-first-contact.md). At a peer that cannot read, the sync key or claim at its head (Peers that cannot read).
- **Judgment** J(L) of the connection, by the node's own view: holder if any proven actor is a current holder of L; else departed if any proven actor once held L and does not now; else unknown.
  - **Holder** is spec/crypto.md §4 "Holders for keys" on L's thing (the read role's holders, `until` disregarded), closed transitively through the rosters the node holds. An account on a roster holds through it; a key actor on a roster holds directly. A node's own account is a proven actor to its other nodes, its own node key only there.
  - **Departed**: every grant path the node has seen for the actor has ended by a removal or finalize it holds (Holders for keys: `until` disregarded). Keys read no clock (spec/crypto.md §4), so no clock enters J. A path the node cannot see (a roster it does not hold) is no path: departed means "known to have left by every path known here", not "left". Unknown is the answer for an actor reachable only through rosters this node lacks.
- **Admissible** credential of L for a connection: a current credential of L, unless J(L) = departed, where only a current epoch **covering** every departure of the proven actors from L it holds counts (spec/crypto.md §4 Covers: a rotator knowing the departure sealed that epoch to the holders it judged current, so a credential at it shows a path this node cannot see; a seed never overrides departed). Everything a node tests, sends or accepts for a peer is limited to admissible credentials; the admissible set is computed from what the node holds, per connection.
  - A node's credentials and J are functions of what it holds; nothing arrives by a peer's word.

## The pair key
Beacons are keyed over a pair key r, 32 random bytes shared by exactly the two nodes of a record (issues/net-reconnect.md): stable while the record lasts, so a peer can keep what it was sent; meaningless to anyone else; naming no node. A connection with no record derives r fresh (first contact). r goes only over the connection, after both sides' proofs.

## Beacons
```
beacon(secret, L, r) = BLAKE3(key = kdf("beacon", secret, L), r)
```
- **Secret beacon**: for L and each admissible credential of L. A filter sent to a peer holds only these.
- **Deposit beacon**: for each inbox L with a pending delivery from this node: `secret = X25519(sk, R)`, R the X25519 half of the recipient's read-role KEM key in its newest `keys.0` this node holds, sk a fresh random X25519 scalar drawn for the connection, kept only in memory, never derived from r (the peer knows r; a key from it would let the peer test any recipient it holds a `keys.0` of). Tested by holders of the recipient's read role, who compute `X25519(R's private key, pk)` for each read epoch of the inbox they hold. Only the holder of R's private key or of sk computes one. A non-contributory result omits it (spec/sync.md §2).
- A filter entry is the first `f` bits of a beacon. `f = ceil(log2(n)) + P` with n the entry count of the generation's whole filter (n = 0: `f = P`), fixed per generation; 256 caps it (P below).

## Account proofs across rotations
Rotations are self-verifying (each is signed at the epoch it rotates; `osis_perm::chain` counts them from held rotations and the side alone), so a peer hands them over with no trust and no sync connection, in the proof exchange of a connection, both ways:
- **Proof**: the prover names the epoch it signs at; the verifier says which rotations of that account it holds (its newest heads); the prover sends the signed rotations between. The verifier applies them by the chain rules, then checks the epoch. A verifier with no base for the account starts from the account's record (its root).
- **Refusal** carries the verifier's rotations the prover lacks (the same exchange the other way): an honest sibling that was offline catches up in that step and retries.
- **Removed against behind** needs no timestamp: an epoch is open only where it descends from every rotation held, so a removal closes a removed node's epoch, and once both sides hold the same rotations both answer alike.
- **Size** is the rotations since the verifier's head, not the history.
Message bytes are to be fixed with step 2; this issue owns them (issues/account-signing.md points here).

## Messages
```
Beacons  [id, gen, Opt(base), f, lo, hi, gcs, more]               -> Status [id, [code]]
Deposits [id, pk, [beacon*], more]                                 -> Status [id, [code]]
Offer    [id, [item*]]                                             -> Status [id, [[code, Opt(tag)]*]]
  item = [0, beacon] (Hit) | [1, sync_id, [beacon*]] (ByRole)
Lost     [id, [[sync_id, cursor]*]]                                -> Status [id, [code]]
```
- **Beacons**: one `gen` of a side's filter, in pages over disjoint ascending ranges `[lo, hi)` of the `f`-bit space, each a Golomb-Rice coded multiset (gap Rice parameter P, duplicates gap 0), each within `MAX_MESSAGE`; `more` until the last. The receiver accepts additions only up to n entries past the whole filter's n; past that the sender must send whole (density ≤ 2^(1-P)). No `base`: the whole filter, replacing what the peer held. A `base`: **additions** to generation `base`; nothing is ever removed from a stored filter. A peer whose stored generation is not `base` answers code 13 (unknown) and gets a whole filter.
- **Staleness**: a removed credential leaves an entry the sender no longer honours; a tester that hits it sends a Hit and is refused. A sender sends a whole filter, new generation, when the entries it has added since the last whole one pass the entries in that one (twice the density at most): false positives stay within a factor 2, amortized cost one re-send per doubling.
- **Stored filter**: the peer's latest generation, durably with the record (issues/net-reconnect.md).
- **Testing**: a node holds a stored filter of the peer and its own **pending** set: its admissible beacons whose `changed_at` is past `acked_pos` (the peer has not acknowledged them, or an Offer from testing them is unanswered, issues/net-reconnect.md The record). Every completed filter arrival, whole or additions, and every own change tests the pending set against the peer's latest stored filter; a whole first-contact filter tests every admissible beacon. The test merges sorted own values against the filter in one pass.
  - Why pending and not only the new: a pair (a at this node, b at the peer, a = b) is found if one side tests a after holding b. Each side keeps a pending until the peer acknowledges it (its ack is sent after receiving a) and its Offers are answered. If this side's test at b's arrival misses, a was acknowledged before b arrived; the peer's test of b at a's arrival then had b pending and found it. Two nodes gaining one credential at once cannot both miss.
  - A dropped connection or lost reply leaves `acked_pos` where it was: the pending set is tested again on the next connection.
- **Offer**, in hits-then-roles order: Hit items go first; ByRole only for L still not open once the Hits were answered.
  - **Hit** `[beacon]`: the full 32-byte beacon of the tester's own credential whose `f` bits hit. It names no sync ID, so a false positive shows nothing.
  - **ByRole** `[sync_id, [beacon*]]`: only where J(L) = holder at the sender, for L not open and held; the beacons are the sender's at every epoch of L it holds. It shows L to the actor it judges a holder.
  - A deposit-beacon hit is a Hit: the receiver of it deposits under the inbox (spec/sync.md §5 Deposit, no open).
- **Receiving** an Offer: a Hit opens L when its beacon is one of the receiver's admissible secret beacons (exact match, on a table of this connection's beacons built when the first Hit arrives, then kept for the connection); a deposit beacon → deposit, reply 0. A ByRole opens L when the receiver holds L and J(L) = holder, or a listed beacon is its own at an admissible credential. Otherwise refused, one code (14), never a reason.
- **Reply** to an accepted Hit carries `tag = BLAKE3(key = kdf("beacon reply", secret, L), beacon)`: the tester checks it, and that its beacon is still admissible for this connection, before it opens L on its side. An untagged 0 opens nothing for the tester. Without a tag a hostile peer answering 0 to a dense filter's every Hit would be served every sync ID. A ByRole's reply carries none: its sender already judged the peer a holder.
- **Lost** `[sync_id, cursor]`: the sender no longer shares L. `cursor` is where L stopped for the receiver (issues/net-reconnect.md, Rejoining). L was shared, so nothing is shown. Idempotent. The sender keeps L in its S marked ending until the Status arrives and sends it again on every connection until then.

## Opens
- An open stands while the rule still holds at the serving node, re-judged on any change to L's credentials or roster.
- A node sets `L` open with proof kind (shared credential, or holder judgment) per side, in the record (issues/net-reconnect.md).
- **Ending**: at any change of L's credentials or roster the serving node re-judges. An open by holder judgment is untouched while J = holder. An open whose proof was a credential now not admissible, with J ≠ holder: L is served through that rotation event inclusively (the stream's `until`, issues/net-reconnect.md), then `Lost`. A current holder applies the rotation, has a new credential (an added beacon, a Hit), L opens again at no first-sync cost. A removal of the peer's actor: J = departed: `Lost` at once.
- **Reopen by Offer**: the same rule; `L` rejoins (issues/net-reconnect.md).

## Peers that cannot read
A node holding no role in L holds no credential and no J: it sends and tests no beacons. Its serving of L is the rule with credential = sync key or claim at its head (spec/sync.md §5), judged by it, opened by Open per sync ID as spec/sync.md §5; the record keeps it (issues/net-reconnect.md). Readers learn which peers serve a group from group data (decided). Two peers that cannot read find nothing with each other; replication between them is issues/net-one-peer.md's.

## Deposits
Deposit beacons are a separate per-connection list, whole 32-byte beacons with no filter (few are ever pending; exact, no false positive). `Deposits` goes to every peer that proved an actor, known or not (Tess): the pending deliveries of this node at connection, then each new one. A peer that proved only unknown actors gets Deposits and no Beacons, under r from the connection (no record: nothing persists). `pk` is one per connection; a holder computes its `X25519(private, pk)` per held inbox read epoch once per connection, on the first Deposits, and compares every later list against that table; a list naming a beacon it matches is answered by a Hit; a delivery stays pending in status until taken (issues/net-first-contact.md). Inboxes at peers that cannot read: found by the group's data (issues/net-one-peer.md), no beacon.

## What each case gets
- Both current at a common epoch, whatever else: Hit.
- Epochs apart, one knows the other holds L: ByRole; the beacon list proves the epoch or J does (`Q ahead`).
- Concurrent rotations, each judges the other a holder: ByRole, J on both sides.
- A removed holder E with the current epoch (rotation is lazy, spec/crypto.md §4) meeting a node that has seen the removal: L is left out of E's filter and any Offer from E is refused (J = departed). Against a node that has not seen it: shared, no design can tell (above).
- Not matched: a holder no node it meets knows and whose epoch none shares current, stranded anyway; two branches of concurrent rotations where only one side knows the other, until either meets a node both can match. Both already accepted (Tess).

## Adversaries
- **Lying or flooding filter**: decoded gaps must stay within `[lo, hi)`, pages ordered, else Error 2 and close. The sender sends `f`; the receiver rejects a whole filter whose `f` is not `ceil(log2(n)) + P` for its decoded count n, an additions page whose `f` differs from its generation's, and additions past the whole filter's n (Messages): density stays at most `2^-P` whole, `2^(1-P)` after additions. A dense set hits every query only for values it could not choose without the credential; a hostile filter costs the tester a pass, and at most one 32-byte Hit each, per own credential: the peer gets PRF outputs it cannot use and no serving (no tag). At most one test pass in flight per peer; pages arriving wait.
- **Learning sync IDs beyond S**: a peer without a credential or J=holder gets the entry count and random bits. A secret false positive shows nothing (Hit names no L, and only a holder of the secret can compute the value). Deposit lists are exact: no false positives there. Beacons are PRF under a credential, scoped to r: different on every pair, unlinkable across peers. Only `ByRole` and `Lost` carry a sync ID, both to a holder the sender judged.
- **Revoked node X of a known actor**: it can prove the account only at a closed epoch, refused where the removal is held (issues/account-signing.md), and no filter runs. Fork window: as issues/account-signing.md (a removed node's fork counts until the owner's merge reaches the reader). Before step 6: X's removal from its account is a removal the verifier holds or not. X proving another actor it still holds (a link key whose seed it kept) and a still-current secret of L (rotation is lazy) matches and shares until L rotates: the verifier cannot tell X from a holder (the point of account signing), and X reads nothing new, as no writer encrypts under the old epoch after knowing the removal.
- **Restart, record loss, clock skew**: issues/net-reconnect.md. No clock anywhere above.
- **Departed actor keeps a stale copy of our filter**: stale entries hit, Hits are refused, one code: it learns only that L was once held (it was there).

## Leaks to accept
- A known-actor peer that shares nothing learns the node's count of current credentials, at first contact and as additions arrive (issues/net-reconnect.md). Padding counts shrinks the leak without closing it; the peer is a known actor.
- A deposit hit shows the depositor the peer serves that inbox: it delivers there, so it must (see Open for the extent).
- Any peer that proved an actor, a stranger included, learns the count of this node's pending deliveries from the length of its Deposits list, and that one exists from its presence. Neither names an inbox.

## Costs (N credentials at the node, N_p at the peer)
- **First contact**: filter N·(P+1 to P+2.5)/8 ≈ 1.2-1.3 B each at P = 8 (12-13 KB at 10^4, about 125 KB at 10^5), one BLAKE3 and one comparison per own credential, 32 B × N·2^-P ≈ 0.1 B per credential of false Hits, a few round trips. The side receiving Hits builds a table of its admissible beacons once per connection, O(N) (about 50 ms at 10^5). Role offers: only for L the filter did not open, 16 B + 32 B per epoch each.
- **Deposits**: at a peer with pending deliveries: one X25519 per held inbox read epoch per connection (every actor's sync ID is its inbox, issues/net-role-sync.md: about 3 s at 10^5 inboxes), bounded to one pass per connection and one per connection in flight; 32 B per pending delivery.
- **Per peer, durably**: 1.2 B per peer credential plus S (issues/net-reconnect.md). At 10^5 credentials and 10^3 known peers each with that many: 120 MB, the record budget's largest stated case.
- **Reconnect**: additions only, O(changes), plus the O(N) Hit table if any Hit arrives.
- **Verdict on issues/net-role-sync.md Cost**: extra sync IDs (one per directly shared thing, per link) cost here about 1.2 B per peer and one hash at first contact, nothing on an idle reconnect, and no registration or inbox budget between readers (those exist only at peers that cannot read and for deposits actually sent); an inbox also costs one X25519 per connection with a peer that has deliveries pending. They do not bound the pairing or this design; the remaining per-sync-ID cost is the local tick (issues/idle-pass-per-label.md), about 35 ms per minute at 10^4 sync IDs, due-indexing before 10^6.

## Picked values
- **P = 8** (performance switch): 0 makes every own credential a refused Hit (correct, more bytes); infinity sends the 32-byte beacons. Class: performance, both correct.
- **Whole-filter re-send at doubling** (performance switch): 0 (re-send each change) and infinity (never: false positives only) are both correct; the receiver's limit on additions is this same value.

## Open
- (tess-call) **Probing inboxes through deposit Hits.** A peer D proving any actor, a stranger included, chooses its Deposits list: it computes `beacon(X25519(sk, R_i), L_i, r)` for every recipient R_i whose `keys.0` it holds, with no delivery pending. A holder H answers a Hit for each inbox it serves. D then knows every actor among those R_i whose read role H holds: the sync IDs of those inboxes, and, as an account's inbox is its home, which accounts H belongs to. spec/requirements.md (Offline and network) allows showing which actor a node is only to nodes of actors it knows; the rule here allows sharing L only with a peer that may hold it. "Goes to every peer, known or not" (Tess) decided the sender's side, not this. Options: (a) a holder answers a deposit list only from a peer that proved a known actor: closes the stranger leak, keeps known-actor probing, and a grant from an account the recipient does not know yet waits for a node that knows both (a contact you never added cannot deliver over a LAN alone); (b) keep it and restate the requirement; (c) make every candidate deposit carry the blob blind, which costs each recipient-sized delivery per connected peer. Proposed: (a). Until decided, the Tests below assume (a).

## Model
Before building: a small exhaustive model, specified in issues/net-reconnect.md (Model).

## Replaces
`wanted_labels`' co-reader and link-route parts, per-sync-ID Open between readers, open proof 3, `PeerStore::co_reader_open`, `reach_nodes` as a serving check, claims between readers.

## Rejected
- Whole-list exchange, overlap from roles alone (misses both-stale holders); member beacons and pair hellos (need unproven actors or per-roster cost); removals from a stored filter (a collision removes another's entry, a false negative); deposit beacons from a static seed (anyone with `keys.0` could test them); hash-only Offer bodies without a confirming tag (a dense filter would be served everything); DH private set intersection (32 B and a scalar multiplication per entry); Bloom filter (about 30% larger, no canonical encoding); past epochs in the filter (shows current holders to everyone who held an old epoch); Hits naming sync IDs (a false positive shows L).

## Tests (tier 1, over issues/net-tests.md)
Two nodes that never met, of accounts that know each other, find T; a node a rotation behind meets a holder granted after it; two concurrent branches heal through two old members; a removed holder matches no node that has seen the removal and learns nothing from offers; a peer answering 0 to a dense filter's Hits opens nothing; a known peer sharing nothing learns only counts; two nodes gaining one credential at once, connected, open it; a lost Hit reply or Lost is retried; a tester that saw a removal opens nothing for the removed node; a holder through a roster this node lacks, removed from a path it knows, matches at the removal's rotation epoch; a grant from a known actor on a LAN arrives (a stranger's waits, Open); a depositor's chosen list shows nothing to a stranger (Open (a)); hostile filters (overlapping pages, oversized, adversarial density) close or cost linear work.

## Steps, in dependency order (with issues/net-reconnect.md)
1. **Model** (Model, issues/net-reconnect.md).
2. **Session proven actors**: `Session::proven()`, the actors a connection proved. Before step 6: node key and its chain to its account (issues/net-connect.md first build, listed gap on the LAN). One function; everything below reads only it.
3. **J and credentials**: holder/departed by actor over rosters; `credentials(L)`; the `changed_at` stamp (issues/net-reconnect.md).
4. **Records, r** (issues/net-reconnect.md, Resume).
5. **Beacons, Offer, Lost, first contact**; replaces proof 3 and `wanted_labels`' co-reader part.
6. **The node log, Pull, Push** (issues/net-reconnect.md).
7. **Reconnect**: base generations, S restore, until and lag.
8. **Deposit beacons** (with issues/net-first-contact.md).
9. **Peers that cannot read** through records (issues/net-one-peer.md).
10. **Account signing step 6**: `Session::proven()` proves the account signing key at its epoch; node key only to own nodes; departure of a node is its removal plus rotation. No other step changes.
