# Audit every arbitrary value
> Summary: Sweep code and spec for thresholds, caps, grace periods, timeouts, retry counts and cache sizes; classify each per notes/arbitrary-values.md (0/infinity test); fix those that only make a bug unlikely; list owner-agreed tradeoffs for sign-off. Non-urgent (owner).
> Tags: security, tests

Scope: every crate, spec/wire.md constants, test thresholds that gate correctness checks (a test floor that hides a bug counts too). Output: each value named as a constant with its class comment; a table in notes/arbitrary-values.md of the owner-agreed tradeoffs (value, what it trades, where specced) for the owner to confirm; fixes with tests for the unjustified ones.
