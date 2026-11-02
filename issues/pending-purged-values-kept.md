# Pending commits keep purged values
> Summary: A commit held pending that a held purge request names keeps the purged values in its stored pending copy until it applies (maybe never); expiry has the rule (a part pending at T goes, spec/commits.md §5), purge does not.
> Tags: security, engine, retention

The purge request's verdict needs perm's judgment of the request at its time and the named delta's identity, which a pending commit (unknown `created.0`, chain) may not give yet. Option: the same rule as expiry (a named part leaves the pending copy, counts as never received, the aspect flagged suspect, `retention::pending_expiry`), judged once the request can be judged against the header. Repro to write: `shred::` with a purge request held before the commit's thing's creation record.

Same gap for a **parked** pending copy (`PendingKind::Parked`, a part this build cannot decode): `retention::strip_pending` only strips `PendingKind::Pending` copies, so a parked blob keeps an expired part's bytes past T.
