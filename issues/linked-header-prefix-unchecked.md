# Prefix agreement is never checked for commits with linked header lists
> Summary: spec/commits.md §4 makes a commit blob whose clear prefix disagrees with its header bad input; `labeling::open_commit` skips the check while the header's lists are linked ("checked once node-core resolved them") and nothing checks it after resolution, so such a blob is accepted with any expiry and commitments.
> Tags: security, sync, node

Repro: by reading: the only callers of `Prefix::agrees`/`osis_commit::prefix_inputs` in osis-node are in `labeling/blobs.rs::open_commit`, which returns early when `!header.is_resolved()`; `apply/mod.rs::examine` resolves the lists without the prefix at hand. A test needs a commit whose aspect list exceeds `CHUNK_THRESHOLD` (thousands of aspects) uploaded under a forged prefix.

- Impact (malicious writer only): its large commit can carry no expiry (the server never expires it) or no token commitments (writers and authors cannot delete it at servers; only the label delete key can), and honest nodes count the blob as holding the body, so no correct projection goes up.
- Direction: keep the prefix (expiry, commitments) with the entry or re-read the stored blob, and check agreement once the header is resolved (before the body counts as held); a disagreeing blob becomes `Kind::Bad` and the body is judged missing there.
