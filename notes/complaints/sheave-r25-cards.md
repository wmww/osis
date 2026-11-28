# sheave-r25-cards
> Summary: the gate showed 17 NEW failures that were all on main already; triage cost two base rebuilds.

- The gate on a cards-only change reported 17 NEW: osis-sim scenarios and sim-sweep (`two_nodes_converge`: node 1 lacks node 0's write at quiescence), osis-chat `edit_is_own_and_purges_as_the_set_lets_*` (a fire refused as history), `rotation::tests_deep::deep_departure_holds_*` (V reads G before its removal), `rotation::tests::arrival_order_holds_alike_*` (seeds 1, 2), `order::held_set_decides_plain` (no Addenda list reset judged), a new differential storm-cap text. Each one I tried also failed on the base without my commit; none is in tools/known_failures.txt or an issue.
- What would have prevented it: a main that is red only with listed failures (the landing that broke these lists them), or a gate summary that marks a failure "also on base" from a recent main gate.
