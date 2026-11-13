# A non-writer's deposit of closure content is promoted and read
> Summary: `would_promote` (core/node/src/sync/pass/promote.rs) takes any valid deposited part on a closure thing its label's actor reads (`body_carried`), with no check that the author writes the label's actor, so a party with no write on a shared space (e.g. a departed writer editing its own old content on a thing it still administers) gets content promoted there and applied by readers. Breaks spec/requirements.md "posting into a shared space needs write on its actor".
> Priority: normal
> Tags: security, sync, node-sync

- Honest non-writers deposit only role commits (spec/sync.md §3, `may_deposit` in pass/bodies.rs), so a rule refusing content parts from a deposited entry costs honest nodes nothing. Proposed: a deposited entry's content deltas on closure things are neither promoted nor applied from that entry; what is left is junk deposits (issues/fresh-deposit-seed-readable-by-departed.md).
- Not traced: the apply path for an unpromoted deposit at readers, and whether a writer that also holds the commit by another route (the thing's own label) then carries it under the label anyway (`body_carried` judges closure and read only), which would make the check belong in the carry rule, not in promotion.
- Found in the chat design review; no reproducer yet. Test: a removed writer's edit of its own message deposited under the chat label is not read by the remaining participants.
