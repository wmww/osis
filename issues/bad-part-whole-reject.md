# A part that hashes but does not decode rejects its whole blob, or only itself
> Summary: a part whose bytes match the header's hash but do not decode is bad input for everything examined with it. Delivered with another part the whole blob is refused and nothing of it held; delivered apart the other part applies. Hostile only (the author signed garbage); the same shape as the arrival-order waits that spec/commits.md §4 now judges per part, but the node refuses instead of holding, so it is not covered by that rule.
> Tags: security, engine, spec

Repro (fails): `cargo test -p osis-node --test it -- --ignored repro_bad_part_together`.

Severity: the same as the arrival-order waits this replaced, a role commit included: a node given such a blob refuses the edge write on G a node given the parts apart holds, one roster, two values, until a clean copy of the G part reaches the first node. Needs a signing author with a role on G. Not new with parts waiting alone.

Blobs under one label carry parts of one retention class per body, so "together" needs parts of two things in one body: a certificate copy or a single-label commit. A node refused such a blob may get the same parts split from elsewhere.

Fix sketch: a part that fails to decode, once it can be hash-checked, is dropped alone like a part that does not hash (`bad` in `apply::examine`), with the same diagnostic; `check_roster_parts`, `check_holders_parts` and `late` (carried write stamped after its commit) are whole-commit refusals to look at with it. Spec/commits.md §4 says a hash mismatch is bad input while the code drops that part alone: settle both together.
