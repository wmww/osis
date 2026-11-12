# Deletes past a host's rate are resent whole
> Summary: A pass sends every delete it judges due in one `Delete` command; the host applies up to `deletes` (20 000) per label per window and answers the rest `RATE_LIMITED`; the node resends all that remain every `RESEND_MS` (30 s). Dropping F pieces past the rate costs O(F) items sent (and freed rows judged) per resend, O(F²/rate) in all.
> Priority: low
> Tags: sync

- Seen in the chunk-tree-2 review (freed sets): the judgment now costs what a pass sends (`SyncEngine::freed_now` skips deletes in flight), so this is the send itself.
- Fix direction: send no more per window than the host takes (the host's policy is known only by its answers: stop at the first `RATE_LIMITED` of a command and resume when the window rolls), or have the host answer with when to come back. Either way the in-flight set stays the batch.
- Not measured in a test yet: a node test dropping a value of 3× the rate with a small test policy, counting items sent.
