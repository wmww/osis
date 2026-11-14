# A body's keep bound passing re-judges nothing
> Summary: A covered body kept in history (a setting keeping it D after replaced) is judged must-hold while kept; when the bound passes, no wake or effect re-judges it, so its entries stay in every store (own logs and nodes keeping S unread) until some unrelated change on the aspect moves the judgement.
> Priority: normal
> Tags: sync, engine

## Reproducer
osis-sync `retention::repro_a_covered_body_leaves_by_time_alone_spec_commits_5` (ignored): node 0 keeps thing 0's value an hour after replaced, writes "one", replaces it and snapshots; past the hour and `MAX_DRIFT`, the facade says `kept: false, covered: Some(true)`, yet "one"'s entries stay at nodes 0, 1 and 2. A later write on the aspect makes them leave at once.

## Cause
`BodyFacts::kept` is read against the clock (`part_keeps`, `k > now`) but the value read sets no wake at `k` (nor at `k + MAX_DRIFT` for deletes at nodes keeping S unread), so `Effects` never makes the body due again by time. Every expiry must set a wake (notes/sync.md principle; spec/sync.md §2): the read module's judgement of a kept body should wake at its bound (and the delete at sources keeping it unread at the bound plus `MAX_DRIFT`, spec/commits.md §5 unread delete margin, which `BodyFacts::kept` does not carry: a separate check once this is fixed).
