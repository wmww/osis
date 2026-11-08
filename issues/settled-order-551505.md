# Settled order histories at seed 551505 read apart from the keep-everything node
> Summary: `order::arrival_order_settled_large_spec_commits_5` and `..._settled_purges_large_...` fail at seed 551505 (60 steps): after the settling compactions a fresh node reads a `t:reg.0` (`"g"` against `"also"`) or a `t:list.0` (`None` against `["v8"]`) other than the node keeping every body. Not shrunk or root-caused.
> Priority: normal
> Tags: engine, tests

Replay: `OSIS_ORDER_SEED=551505 OSIS_ORDER_LEN=60 cargo test -p osis-node --test it -- --ignored --exact order::arrival_order_settled_large_spec_commits_5` (`OSIS_ORDER_SHRINK=1` to shrink).

Found by a tier-2 order run from offset 551501. The plain settled history writes no signals and takes no path the signal-firing change touched (it only removed signal payloads from `Event::Applied`/`Joined`), so it predates that change. Failing order: all 47 commits held, order #6, "now, settled".
