# Pending commits keep expired values
> Summary: A commit (or a late part) held pending past its delta's expiry keeps the delta's values on disk until it applies, which may be never; spec/commits.md §5 wants no recoverable copy once T passes.
> Tags: security, engine, retention

Repro: `shred::repro_expired_while_pending_values_kept` (`#[ignore]`): a commit with an expiring write, pending for its thing's `created.0`, survives T and `tick` with its value recoverable. Same for a late part that waits (`apply::late_parts` `Exam::Pending`), including one of a delta already held value-less (`retention::takes_late`, branch valueless-gaps): its pending copy carries the values until the wait ends. Purge has the same shape only until the named commit applies (`purged_after_pending_unrecoverable_spec_commits_5` covers the applied case).

Fix sketch: at T (a timer per pending expiring part, or the expiry pass over pending records) and before `put_pending`, rewrite the pending blob without parts whose `expires` passed or whose delta a held purge request names (they count as held for atomic apply anyway, spec/commits.md §4), shredded. A late copy of such a part is then joined value-less when it comes again (`takes_late`).
