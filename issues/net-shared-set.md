# Finding the shared sync IDs
> Summary: The second layer (Tess): two connected nodes, each with many sync IDs, find the ones both hold, with nothing known of each other beforehand, showing nothing about the rest. Favoured: a compact filter of per-connection keyed tags; private set intersection the alternative. Rejected: sending the whole list, and working the overlap out from roles (misses cases). Design open. Part of issues/net-rework.md.
> Priority: normal
> Tags: sync, node, spec, tess-call

## Today
Neither node sends its set. Each works out the overlap from data it holds: saved peers a `label.0` lists, and co-readers (node things with a held `reach.0` that may read the group, core/node/src/sync/conn.rs `wanted_labels`). The dialer opens those one by one with a proof. So two nodes whose node cards never crossed open nothing with each other, even both holding the same thing. A sync-key open works at a node that does not know the dialer (`evaluate_open` serves every proof), so proving is not the problem: knowing what to open is.

## Wanted
- Works with no prior knowledge of the other node, in every case, no fallback path.
- Shows the other node nothing of sync IDs it does not hold, and nothing to a node that holds none.
- Cheap per connection; repeated connections are issues/net-reconnect.md's job and may avoid redoing this.
- Knowing a sync ID is not holding it: matching is on a value only holders compute.

## Options
- **Filter of keyed tags (favoured, Tess).** One side sends a compact filter (a Bloom filter or similar) of tags, each a hash of a secret of one of its sync IDs and a fresh per-connection value; the other tests its own sync IDs against it and opens the matches, proving by sync key. About 10 bits a sync ID (10^4: about 12 KB), hashes only. Non-holders learn nothing but the rough size; tags never repeat across connections. A false match costs one failed open.
- **Private set intersection (Tess: also good).** DH-based PSI over the same holder-only values: exact, shows only the intersection and the set sizes, about one scalar multiplication and 32 bytes per sync ID per side.
- Rejected: **sending the whole list** (shows everything; knowing an ID is not holding it; size every time).
- Rejected: **working it out from identity and roles** (each side opens what its role data says the other holds): misses a sync ID when neither side has seen the other's grant, so it needs a fallback, i.e. special cases (Tess).

## Unsure
- (design) Which secret keys a tag: the sync key of the current step (so a removed holder stops matching after a rotation), or something that survives rotations the other side has not seen yet (two holders a rotation apart must still match, or one is stranded).
- (design) One filter or both directions; sizes padded (to a power of two?) so a filter does not show the set size; false-match rate; cost at 10^5 sync IDs.
- (design) Peers that cannot read: they hold no read secret, so they cannot compute holder-only tags. They are listed in group data (decided), so readers know which groups each serves and need no discovery with them; between two such peers the same. Check that this covers every such case.
- (design) Deposits: a sender delivering to an inbox (issues/net-first-contact.md) holds no secret of the recipient's sync ID; it needs another way to find the recipient's nodes.
- (design) What goes with it: probably co-reader proof 3 and the co-reader part of `wanted_labels`; `peers()` as an API.
- (design) Batching: one message opening every match, not one Open each.
