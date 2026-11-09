# Finding the shared sync IDs
> Summary: Settled design, one mechanism with issues/net-reconnect.md. Rule: a node shares a sync ID with a connected peer exactly while, on what it holds now, the peer may hold it; everything remembered only says what need not be sent again. A per-pair key, a per-peer Golomb-coded filter of secret beacons (additions only), confirmed hits, role offers to judged holders, deposit beacons by a pair DH for inboxes. Nothing keyed by node identity; blocked on account signing step 6 only in what a session proves. Proposed where issues/net-peer-continuity.md (tess-call) applies. Model first. Part of issues/net-rework.md.
> Priority: normal
> Tags: sync, node, proto, crypto, spec, security

## The rule
**A node shares sync ID L with a connected peer exactly while, on what it holds now, the peer may hold L: no actor the peer proved on this connection is known to have left L, and the peer either has such an actor as a current holder of L or has proved a current credential of L.** Every other state is a cache of that judgment or of what was already sent: losing it costs bytes, never a result (issues/net-reconnect.md).

Named exceptions, each following from a principle stated with it:
- **Unknown actors get no secret beacons** (spec/requirements.md, Offline and network; Tess): the rule only runs with a peer that proved a **known actor**.
- **Deposit beacons share nothing**: a deposit is a delivery to an inbox, not a shared sync ID; the sender learns only where to deposit (Deposits).
- **The event that ends sharing is still sent** (Opens): a holder that missed a rotation can only prove the new epoch by receiving it, as spec/sync.md §5 sends a head's last event. Liveness of a current holder; a removed holder learns a rotation happened, which it could not read.
- A node that has not received a removal cannot tell: the rule's "on what it holds now", under any design.

## Words
- **Proven actors** of a connection: the actors the peer proved on it (issues/net-connect.md, Rules): its account, key actors it holds (a link key it redeems), its own node to nodes of its own account.
- **Known actor**: one whose keys this node holds (own account, contacts, holders of anything it holds, a link key on a roster it administers).
- **Credential** of L: a secret only a holder can show. A node's credentials of L are: L's read secret at each of its current epochs (spec/crypto.md §4 Current); the seed of a link or recovery card on L's thing that it holds and whose key actor is still on L's roster in its view (spec/sync.md §5 Claim, issues/net-first-contact.md). At a peer that cannot read, the sync key or claim at its head (Peers that cannot read).
- **Judgment** J(L) of the connection, by the node's own view: holder if any proven actor is a current holder of L; else departed if any proven actor once held L and does not now; else unknown.
  - **Holder** is spec/crypto.md §4 "Holders for keys" on L's thing (the read role's holders, `until` disregarded), closed transitively through the rosters the node holds. An account on a roster holds through it; a key actor on a roster holds directly. A node's own account is a proven actor to its other nodes, its own node key only there.
  - **Departed**: every grant path the node has seen for the actor has ended (any removal or end of a grant it holds in role history). Keys read no clock (spec/crypto.md §4), so no clock enters J.
  - A node's credentials and J are functions of what it holds; nothing arrives by a peer's word.

## The pair key
Beacons are keyed over a pair key r, 32 random bytes shared by exactly the two nodes of a record (issues/net-reconnect.md): stable while the record lasts, so a peer can keep what it was sent; meaningless to anyone else; naming no node. A connection with no record derives r fresh (first contact). r goes only over the connection, after both sides' proofs.

## Beacons
```
beacon(secret, L, r) = BLAKE3(key = kdf("beacon", secret, L), r)
```
- **Secret beacon**: for L and each current credential of L. The filter sent to a peer leaves out L when J(L) = departed.
- **Deposit beacon**: for each inbox L with a pending delivery from this node: `secret = X25519(sk, R)`, R the X25519 half of the recipient's read-role KEM key in its newest `keys.0` this node holds, `sk = kdf("deposit dh", r)` read as an X25519 scalar. Tested by holders of the recipient's read role, who compute `X25519(R's private key, pk)` for each read epoch of the inbox they hold, pk = the public key of sk sent in the filter. Only the recipient's holders can compute one. A non-contributory result omits it (spec/sync.md §2).
- A filter entry is the first `f` bits of a beacon. `f = ceil(log2(n)) + P` with n the entry count when the filter is built whole, fixed per generation (P below).

## Messages
```
Beacons [id, gen, Opt(base), f, Opt(pk), lo, hi, gcs, more]        -> Status [id, [code]]
Offer   [id, [item*]]                                              -> Status [id, [[code, Opt(tag)]*]]
  item = [0, beacon] (Hit) | [1, sync_id, [beacon*]] (ByRole)
Lost    [0, [[sync_id, cursor]*]]
```
- **Beacons**: one `gen` of a side's filter, in pages over disjoint ascending ranges `[lo, hi)` of the `f`-bit space, each a Golomb-Rice coded multiset (gap Rice parameter P, duplicates gap 0), each within `MAX_MESSAGE`; `more` until the last. `pk` once, in the first page. No `base`: the whole filter, replacing what the peer held. A `base`: **additions** to generation `base`; nothing is ever removed from a stored filter. A peer whose stored generation is not `base` answers code 13 (unknown) and gets a whole filter.
- **Staleness**: a removed credential leaves an entry the sender no longer honours; a tester that hits it sends a Hit and is refused. A sender sends a whole filter, new generation, when the entries it has added since the last whole one pass the entries in that one (twice the density at most): false positives stay within a factor 2, amortized cost one re-send per doubling.
- **Stored filter**: the peer's latest generation, durably with the record (issues/net-reconnect.md).
- **Testing**: a node tests its own credentials' beacons against the peer's stored filter once the peer's latest filter is complete: every credential at first contact, afterward only additions (Reconnect). The test merges sorted own values against the filter in one pass. A tester needs no table of the peer's beacons; a Beacons additions page is tested by no one but the peer's own additions: each side tests its own additions against the other's filter.
- **Offer**, in hits-then-roles order: Hit items go first; ByRole only for L still not open once the Hits were answered.
  - **Hit** `[beacon]`: the full 32-byte beacon of the tester's own credential whose `f` bits hit. It names no sync ID, so a false positive shows nothing.
  - **ByRole** `[sync_id, [beacon*]]`: only where J(L) = holder at the sender, for L not open and held; the beacons are the sender's at every epoch of L it holds. It shows L to the actor it judges a holder.
  - A deposit-beacon hit is a Hit: the receiver of it deposits under the inbox (spec/sync.md §5 Deposit, no open).
- **Receiving** an Offer: J = departed: refused. A Hit opens L when its beacon is one of the receiver's current secret beacons (exact table match); a deposit beacon → deposit, reply 0. A ByRole opens L when the receiver holds L and J(L) = holder or a listed beacon is its own at a current credential. Otherwise refused, one code (14), never a reason.
- **Reply** to an accepted Hit carries `tag = BLAKE3(key = kdf("beacon reply", secret, L), beacon)`: the tester checks it before it opens L on its side. An untagged 0 opens nothing for the tester. Without a tag a hostile peer answering 0 to a dense filter's every Hit would be served every sync ID. A ByRole's reply carries none: its sender already judged the peer a holder.
- **Lost** `[sync_id, cursor]`: the sender no longer shares L. `cursor` is where L stopped for the receiver (issues/net-reconnect.md, Rejoining). L was shared, so nothing is shown. Idempotent.

## Opens
- An open stands while the rule still holds at the serving node, re-judged on any change to L's credentials or roster.
- A node sets `L` open with proof kind (shared credential, or holder judgment) per side, in the record (issues/net-reconnect.md).
- **Ending**: at a rotation the serving node re-judges. An open by holder judgment is untouched. An open whose proof was a credential now not current, with J ≠ holder: L is served through that rotation event inclusively (the stream's `until`, issues/net-reconnect.md), then `Lost`. A current holder applies the rotation, has a new credential (an added beacon, a Hit), L opens again at no first-sync cost. A removal of the peer's actor: J = departed: `Lost` at once.
- **Reopen by Offer**: the same rule; `L` rejoins (issues/net-reconnect.md).

## Peers that cannot read
A node holding no role in L holds no credential and no J: it sends and tests no beacons. Its serving of L is the rule with credential = sync key or claim at its head (spec/sync.md §5), judged by it, opened by Open per sync ID as spec/sync.md §5; the record keeps it (issues/net-reconnect.md). Readers learn which peers serve a group from group data (decided). Two peers that cannot read find nothing with each other; replication between them is issues/net-one-peer.md's.

## Deposits
A deposit beacon goes to every peer that proved an actor, known or not (Tess). So a peer that proved only unknown actors gets a filter holding only deposit beacons (r from the connection, no record: nothing persists). A peer that holds a recipient's read role finds a Hit, gets the deposit; a pending delivery stays pending in status until taken (issues/net-first-contact.md). Inboxes at peers that cannot read: found by the group's data (issues/net-one-peer.md), no beacon.

## What each case gets
- Both current at a common epoch, whatever else: Hit.
- Epochs apart, one knows the other holds L: ByRole; the beacon list proves the epoch or J does (`Q ahead`).
- Concurrent rotations, each judges the other a holder: ByRole, J on both sides.
- A removed holder E with the current epoch (rotation is lazy, spec/crypto.md §4) meeting a node that has seen the removal: L is left out of E's filter and any Offer from E is refused (J = departed). Against a node that has not seen it: shared, no design can tell (above).
- Not matched: a holder no node it meets knows and whose epoch none shares current, stranded anyway; two branches of concurrent rotations where only one side knows the other, until either meets a node both can match. Both already accepted (Tess).

## Adversaries
- **Lying or flooding filter**: decoded gaps must stay within `[lo, hi)`, pages ordered, total within the record budget (issues/net-reconnect.md), else Error 2 and close. Density cannot exceed `2^-P` by construction: entries are in `[0, 2^f)` and the receiver fixes `f` per generation. A dense set hits every query only for values it could not choose without the credential; a hostile filter costs the tester a pass, and at most one 32-byte Hit each, per own credential: the peer gets PRF outputs it cannot use and no serving (no tag). At most one test pass in flight per peer; pages arriving wait.
- **Learning sync IDs beyond S**: a peer without a credential or J=holder gets the entry count and random bits. A false positive shows nothing (Hit names no L). Beacons are PRF under a credential, scoped to r: different on every pair, unlinkable across peers. Only `ByRole` and `Lost` carry a sync ID, both to a holder the sender judged.
- **Revoked node X of a known actor**: it can prove the account only at a closed epoch, refused where the removal is held (issues/account-signing.md), and no filter runs. Fork window: as issues/account-signing.md (a removed node's fork counts until the owner's merge reaches the reader). Before step 6: X's removal from its account is a removal the verifier holds or not.
- **Restart, record loss, clock skew**: issues/net-reconnect.md. No clock anywhere above.
- **Departed actor keeps a stale copy of our filter**: stale entries hit, Hits are refused, one code: it learns only that L was once held (it was there).

## Leaks to accept
- A known-actor peer that shares nothing learns the node's count of current credentials, at first contact and as additions arrive (issues/net-reconnect.md). Padding counts shrinks the leak without closing it; the peer is a known actor.
- A deposit hit shows the depositor the peer serves that inbox: it delivers there, so it must.

## Costs (N credentials at the node, N_p at the peer)
- **First contact**: filter N·(P+1.5)/8 ≈ 1.2 B each at P = 8 (12 KB at 10^4, 120 KB at 10^5), one BLAKE3 and one comparison per own credential, a few round trips. Role offers: only for L the filter did not open, 16 B + 32 B per epoch each.
- **Per peer, durably**: 1.2 B per peer credential plus S (issues/net-reconnect.md). At 10^5 credentials and 10^3 known peers each with that many: 120 MB, the record budget's largest stated case.
- **Reconnect**: additions only, O(changes).
- **Verdict on issues/net-role-sync.md Cost**: extra sync IDs (one per directly shared thing, per link) cost here about 1.2 B per peer and one hash at first contact, nothing on an idle reconnect, and no registration or inbox budget between readers (those exist only at peers that cannot read and for deposits actually sent). They do not bound the pairing or this design; the remaining per-sync-ID cost is the local tick (issues/idle-pass-per-label.md), about 35 ms per minute at 10^4 sync IDs, due-indexing before 10^6.

## Picked values
- **P = 8** (performance switch): 0 makes every own credential a refused Hit (correct, more bytes); infinity sends the 32-byte beacons. Class: performance, both correct.
- **Whole-filter re-send at doubling** (performance switch): 0 (re-send each change) and infinity (never; stale entries raise false positives only) are both correct.

## Model
Before building: a small exhaustive model, specified in issues/net-reconnect.md (Model).

## Replaces
`wanted_labels`' co-reader and link-route parts, per-sync-ID Open between readers, open proof 3, `PeerStore::co_reader_open`, `reach_nodes` as a serving check, claims between readers.

## Rejected
- Whole-list exchange, overlap from roles alone (misses both-stale holders); member beacons and pair hellos (need unproven actors or per-roster cost); removals from a stored filter (a collision removes another's entry, a false negative); deposit beacons from a static seed (anyone with `keys.0` could test them); hash-only Offer bodies without a confirming tag (a dense filter would be served everything); DH private set intersection (32 B and a scalar multiplication per entry); Bloom filter (about 30% larger, no canonical encoding); past epochs in the filter (shows current holders to everyone who held an old epoch); Hits naming sync IDs (a false positive shows L).

## Tests (tier 1, over issues/net-tests.md)
Two nodes that never met, of accounts that know each other, find T; a node a rotation behind meets a holder granted after it; two concurrent branches heal through two old members; a removed holder matches no node that has seen the removal and learns nothing from offers; a peer answering 0 to a dense filter's Hits opens nothing; a known peer sharing nothing learns only counts; a grant to an account met only on a LAN arrives; hostile filters (overlapping pages, oversized, adversarial density) close or cost linear work.

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
