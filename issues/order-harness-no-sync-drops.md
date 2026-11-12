# The order harness never drops a live body, so held-model's live-bound check goes unreached
> Summary: `held::compare` flags a body dropped as covered while in history or live before its aspect's live bound (spec/commits.md §5 Kept while live), but the order harness's judged nodes are bare engines (`LocalPeer`): the durable covered drop of a live body, and of a replaced one out of history, is node-sync's (`sync/local.rs` `drop_covered`), which they never run. Only purge-on-replace drops (`settle_none`) reach the check ("covered drops judged"); "live drops judged" stays 0 over plain and exhaustive runs, and only the scripted `harness_flags_a_live_drop_before_its_live_bound_spec_commits_5` (a drop by hand) exercises it.
> Priority: normal
> Tags: tests, node, retention

## Direction
Give the judged nodes node-sync's local covered-drop pass (every held snapshot judged against the bodies it may drop, as `drop_covered` does after a sync step), or an engine entry doing the same, so the property's nodes drop what the spec lets them and held-model judges each drop; then a floor on "live drops judged" for the emphasis that compacts unkept aspects (Settled). Keep the keep-every-body node as it is: the read oracle is unchanged by drops that only cover.
