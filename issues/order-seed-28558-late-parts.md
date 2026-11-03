# Order seed 28558: a commit applied or pending by arrival order
> Summary: `arrival_order_alike_large` seed 28558 (length 60) fails on main at 2964db75 and on session-25 alike: one commit waits for a missing part as made and applies when delivered reversed with late parts. Not caused by session sources. Cause not found.
> Tags: engine, tests

Replay: `OSIS_ORDER_SEED=28558 OSIS_ORDER_LEN=60`, test `order::arrival_order_alike_large_spec_permissions_5_2` (about 8 minutes at load 60, most of it shrinking). `with_syncs` gives the node only part of some commits (seed % 3 = 1).

Seen on session-25: the commit writes `t:reg.0` and `t:gone.0` on one thing and its pack holds only `t:gone.0`. Delivered as made or plainly reversed it stays `WaitDeltas`, also after `reexamine` and a restart, so this is no stale wait. Delivered reversed with other commits' parts late (`deliver_split`), it applies and stays applied.

Unchecked lead: `counts_held` reads the held set, so some intermediate held set (a role commit with only some parts here) may count the missing part as held, for example through `removed_author`, and applying cannot be taken back. Print which `counts_held` arm answers true during the split delivery.
