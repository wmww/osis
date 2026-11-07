# Pending commits have no bound and no age
> Summary: spec/requirements.md says peer input never causes unbounded storage, but a reader of a label (or a connected inbox sender) can grow what a node keeps pending for good: a commit by an author whose record never comes is durable, unsigned as far as the node can tell, and nothing ages it out.  Needs a bound and an eviction rule.
> Priority: normal
> Tags: security, engine, sync

Bytes kept follow bytes delivered: each fresh header is a fresh commit ID, so per-commit limits bound nothing overall. An entry leaving the host does not free its pending row.

What can pend for good (whole-commits step 3: a node never waits for a part; a commit with no part held applies as its header): a commit whose author's record never comes, and parts waiting alone for a thing's record (or a chain record) that never comes, beside an applied commit or with every held part waiting. Both are label entries the node holds, under the host's per-label cap and the deposit budget, so the bound wanted is per label with oldest-first eviction.

Direction (Tess): pick whatever is simplest that closes the hole; agents may change it later if something better turns up. Any cap overflowing or eviction must surface a warning/error to the app, so a user who sees it knows something is wrong.

To pick: total bytes per label or author class, what is evicted (oldest unsigned first keeps a flood from pushing out what can verify), how a true commit evicted comes back (`SyncEngine::redeliver` can ingest its entry again).

Not a bound in itself, but the same call: a pending commit's other entries leave with the host's (`forget_blob`), so a true copy deleted from every host while junk holds its slot needs a holder's new upload. Keeping those blobs while the commit pends would let one sender grow one commit's copies by flood-and-delete.

Also: a waiting part keeps its body past its keep-at-most bound until it applies; a part that never applies keeps it for good at that node. The bound this issue asks for covers it.
