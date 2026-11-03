# A new device reads an older value when a commit's expired part comes without its covered part
> Summary: `order::new_device_alike_large` seed 883125, on main (2964db75) and on session-25 alike: the node given a commit without its covered part drops the expired part with no stamp, the node given every body keeps the value-less stamp, so `t:reg.0` reads differently.
> Tags: engine, tests

`OSIS_ORDER_START=883125 OSIS_ORDER_SEEDS=1`, `order::new_device_alike_large_spec_permissions_5_1`. Shrinks to `h = vec![Aim(Typed { by: 0, t: 5, op: 27, k: 2, v: 2 }), Aim(Compact { by: 0, t: 3, op: 15 }), Advance { who: None, ms: 1000 }]`: a two-part commit c (`t:reg.0` expiring in 1 s, `t:rec.0`), a `t:rec.0` snapshot after it, then the advance past T. Every pack reaches both nodes after T.

The node given everything reads `t:reg.0` as c's value-less stamp (`None`). The node given c without its covered `t:rec.0` part reads the earlier `"g"`: c's expired part left no stamp. It looks like the order of arrival there: c waits for its missing part, so its part past T goes (spec/commits.md §5), and only then does the snapshot count that part as held. Not investigated further. Found in the session-25 review, in issues/order-seeds-found-on-main.md until that issue was closed without it.
