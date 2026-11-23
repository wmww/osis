# The order harness: a node shows a message the node keeping every body does not
> Summary: osis-engine `order::held_set_decides_plain` at `OSIS_ORDER_SEED=512007751 OSIS_ORDER_LEN=60` (Addenda): after the sync exchange a node holding part of the history reads `t:msg.0` as `m9` where the node keeping every body reads nothing. Not shrunk; cause not read.
> Priority: normal
> Tags: engine, tests

Replay: `OSIS_ORDER_SEED=512007751 OSIS_ORDER_LEN=60 cargo test -p osis-engine --test it -- --ignored --exact order::held_set_decides_plain` (`OSIS_ORDER_DUMP=1` prints the index differences). It fails with main's engine too once the harness's `applied differs` check is off: the stated-path wait (notes/engine-apply.md, Chain certificates missing) uncovered it, it did not make it.

What the dump shows (held 85 of 110 commits, order #8, "now, after the sync exchange"): two `t:msg.0` commits of peer 1 on the thing (#86, #92) are held stripped at the node keeping every body (a purge request names them) and are dropped `Other` at the node, valid at both; three other commits on the thing have parts dropped as covered at the node only. Both nodes pend the same commits. So the node's read keeps a value the purge took at the other: a body dropped before the request arrived, whose value then came back another way (a snapshot's copy, or the sync exchange's refetch), is the lead.

A shrink (`OSIS_ORDER_SHRINK=1`) did not end within 26 minutes of hold: shrink with `OSIS_SHRINK_MATCH='shows other than the node keeping every body'` in a hold of its own.
