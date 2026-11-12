# dead-pub
- Many `#[doc(hidden)]` engine/node test hooks had no caller at all (drop_counts, drop_set, edge_applied, headers_decoded): hooks outlive the tests they served. tools/dead_pub.py now flags them.
- The store's per-peer `judged_pos` was written as 0 and never read (its only riser had no caller): a store field nothing fills is invisible to every lint. issues/net-reconnect.md keeps the plan for it.
- About half the hits sit in areas other branches are changing (sync, eph-paging, retention, rotation/keys); they are `deferred:` in tools/dead_pub_allow.txt, to clear when those land.
