# The required-retention order harness's floor fails at plain size
> Summary: `order::arrival_order_required_large_spec_commits_5` at plain size (4 seeds) asserts some delta broke a required retention and fell; `OSIS_ORDER_START=3086` reaches none (broken 0, fallen 5), on main too. A floor that a lucky seed range flips, against "every check runs at every size".
> Priority: low
> Tags: tests, order

Replay: `OSIS_ORDER_START=3086 cargo test -p osis-node --test it -- --ignored order::arrival_order_required_large`. Fix by deriving the floor from the run's size (or summing over a fixed tier-1 range), or by aiming the generator so every seed breaks one (`Seen::floors`, core/node/tests/it/order.rs).
