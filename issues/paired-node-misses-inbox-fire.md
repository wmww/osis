# A node paired later can hold an inbox fire's header but never its body
> Summary: in sync `flows::a_node_pairs_another_after_removing_its_pairer_spec_sync_inbox_1` (seed 0 world) the new node holds the account inbox's `ticket@~0` fire commit by header alone and judges its body may-hold under the inbox's sync ID, so never fetches it, while its sibling judges the same body must-hold and logs it; with another world seed the new node holds the body. Which happens depends on IDs or arrival order; not root-caused.
> Priority: low
> Tags: sync, inbox

- Seen after the fix for the paired node's missing secrets (holder pieces under D): nothing reads the fire's ticket any more there, so the test passes either way.
- Same commit, two readers of one sync ID, verdicts Must and May: either the sibling's Must or the new node's May is wrong (spec/sync-judgement.md §2 Loggable: a reader holding neither the content nor a blob cannot log it, so it never fetches what it lacks).
- Wanted: where the header-only copy comes from at the new node, and a constructed reproducer.
