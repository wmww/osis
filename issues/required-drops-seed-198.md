# Required drops seed 198: a deleted text element's content lost after bodies return
> Summary: `order::required_drops_read_alike_large_spec_perm_8` (general histories) fails at seed 198, inside its default 0..200 range, on main too: after drop_broken and the bodies held again, the as-made order's `t:text.0` keeps a deleted element (`eab96370:3`, deleted by `713dc434:2`, `undel: Some('v')`) with `content: None` where the reference has `Char('v')`. Not investigated.
> Tags: engine, retention, tests

Replay: `OSIS_ORDER_SEED=198 cargo test -p osis-node --test it -- --ignored --exact order::required_drops_read_alike_large_spec_perm_8` (the required-history half passes; the `(general)` half fails on order 0, "bodies again"). Found by the tier1-trim review running the per-branch twins; reproduced with main's binary (`tools/bin-at main`), so not caused by that branch.
