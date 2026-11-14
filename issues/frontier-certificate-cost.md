# Demotion frontiers are replicated as certificates under every sync ID an account writes to, forever
> Summary: a node removal from account P carries a frontier listing, by commit ID (32 B each), the removed node's received writes the removal puts in question; that commit is a chain certificate of every later node that node granted, so its frontier chunks go under every sync ID those nodes write to (their certificate copies, `Engine::own_certificates_now`), and role history is never compacted. Cost grows as node churn × uncovered commits × sync IDs per account. Not re-measured since frontiers became commit IDs only; measure, then split or close.
> Priority: low
> Tags: performance, permissions, sync, spec

Where it comes from: spec/permissions.md §4 (certificates include every held demotion of the chain's authors, with frontier), §5.1 Frontier (commit IDs, never counters; above `CHUNK_THRESHOLD` by link; every received commit listed, compacted or not, up to the list bound, the rest in the demoter's addenda), spec/commits.md §5 (`roles.0` never compaction-snapshotted, so the removal stays), spec/sync-judgement.md §1 (frontier chunks go under the sync ID as certificate blobs). Tess's decision: frontiers are commit IDs only, and the cost per received commit is a stated limit (spec/requirements.md Cost).

To measure: a long-lived node with many uncovered commits (kept-history aspects, or many aspects not yet compacted) removed from its account, a successor node writing under many sync IDs; count frontier bytes logged per sync ID and what a new holder fetches to judge one write.

## Candidate fix, if the measurement says so
A verifier of N's chain asks one question of a demotion on it: does its frontier list the commit N's grant rests on (spec/permissions.md §4). It never needs the removed node's content commits for that. So split the frontier in two linked values covered by the signed header: `chain` (the removed node's role commits and the demoter's chain certificates) and `content` (the rest). Chain certificates carry `chain` only; `content` goes only where the removed node's content is (the existing rule for revokes about authors, spec/permissions.md §4). A projected copy must mark `content` as "not carried", never "empty", and its `chain` part must be complete. Wire change in the header (spec/wire.md §4).

Rejected: sharing frontier chunk blobs across sync IDs (links every sync ID of one account at a node keeping them unread, worse than the per-connection linkage).
