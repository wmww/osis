# keep::any_order_until_keeps_no_more fails a seed on main
> Summary: Seed 636109736897 of `keep::any_order_until_keeps_no_more_large` keeps a copy of an ended grant's thing only by delivery order (`kept only by order`: delivered one at a time, the node keeps both things; all at once, only one). Fails on main as on the deposit-fill branch; not looked into.
> Priority: normal
> Tags: tests, engine, retention

Replay: `OSIS_KEEP_START=636109736897 OSIS_KEEP_SEEDS=1 cargo test -p osis-node --test it -- --ignored --exact keep::any_order_until_keeps_no_more_large` (0.3 s). Property: notes/permissions.md (`any_order_until_keeps_no_more`): an `until` ending can end a copy at a later judging, never bring one back.
