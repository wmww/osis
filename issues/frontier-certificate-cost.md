# Demotion frontiers are replicated as certificates under every label an account writes to, forever
> Summary: a node removal from account P carries a frontier over every (tid, ak) the node ever wrote (10 bytes each; 10^5-10^6 aspects for a long-lived node: megabytes, by link); that commit is a chain certificate of every later node that node granted, so its frontier chunks are re-encrypted and uploaded under every label those nodes write to (`place_linked`), and the removal is kept for good (role history is never compacted). Every verifier fetches the whole frontier to judge any one write. Cost grows as node churn × aspects written × labels, per account, and is never compacted away.
> Tags: performance, permissions, sync, spec

Mostly superseded by issues/session-sources.md step 1: demotion frontiers become commit IDs only (no per-aspect counters), listing the removed node's commits not yet covered by a snapshot. Re-measure after it lands; close if the split is no longer worth it.

Where it comes from: spec/permissions.md §4 (certificates include every held demotion of the chain's authors, with frontier), §5.1 (frontier covers every aspect of everything the demoted authority gave write on), spec/commits.md §5 (`roles.0` never compaction-snapshotted, so the removal stays), spec/sync.md §3 (frontier chunks go under the label as certificate blobs); notes/permissions.md Revocation ("a frontier can reach megabytes").

Order of magnitude: a heavy user with 10^5 aspects and a node replaced yearly: ~1 MB per removal, placed under every label the successor node writes (hundreds), and kept with the removal forever. A team label with 100 such holders accumulates ~1 GB of frontier chunks a decade in, which every new holder fetches to judge old writes.

## Recommended fix
Split the frontier into the two things verifiers use it for, and let certificates carry only the small one.
1. **Two linked values in the header** (spec/wire.md §4 `frontier`): `commits` (the commit IDs: the demoter's chain certificates at R's point and X's commit-form commits) and `writes` (per (tid, ak, node) counters), each inline below `CHUNK_THRESHOLD` else by link, both covered by the signed header.
2. **Chain certificates carry `commits` only.** A verifier of N's chain asks one question of a demotion on it: does its frontier list the write that N's grant rests on, by commit ID (spec/permissions.md §4 M1 rule). It never needs the per-aspect counters for that. So the certificate projection of a demotion places the `commits` chunks and omits `writes`. `commits` is O(chain certificates + X's role commits), tens of KB at most, against megabytes.
3. **`writes` goes only where X's content is**, which is already the rule for revokes about authors (spec/permissions.md §4: placed under a label when it changes a verdict there), so a label X never wrote to never receives it.
4. Optional, later: encode `writes` as a paged sorted map (spec/crdt.md §8 paging over the canonical bytes with a first-key per page) so a verifier judging one write fetches O(1) pages. Not needed for the storage cost; only for fetch cost on the labels X did write to.
Wire change in the header; perm's frontier type gains a `writes: Option` (absent in a projected copy means "not carried", never "empty"); `place_linked` follows the projection. The `commits` part of a copy must be complete (bad input otherwise), so a verifier never mistakes a projection for a short list.

Rejected: sharing frontier chunk blobs across labels (links every label of one account at the host, worse than the per-connection linkage); per-node global counters (changes dot semantics and text run compression for a gain this split already delivers).
