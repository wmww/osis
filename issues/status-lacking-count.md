# Status: a source's lacking count is taken again whole
> Summary: `status` counts what a source keeping S unread lacks as S's stamped entries here its stream did not show, taken again whole (O(S's stamped entries)) whenever that source's stream or S's entries move; a trickle of single entries to a large S costs O(entries) each.
> Priority: low
> Tags: sync, status

The count is display only (`SourceStatus::lacking`); waits and held elsewhere never read it. To make it O(change): follow the store's entry feed and streams' `known` per (S, blob) as `Effects` keys whose value is the set of store sources lacking that blob, and keep the per-(S, source) count from their differences (as inbox's `held` follows entries). Costs an `Effects` key per stamped entry held.
