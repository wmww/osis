# Two full-size differential histories fail on main
> Summary: The full-size sync differential (`OSIS_FULL=1`, 100 seeds) fails 2 of 100 at f4789280a: a node reads a value the model says it does not hold, and status counting sources that are no member at quiet. Both reproduce on that commit alone.
> Priority: normal
> Tags: sync, tests

- `differential::histories_hold_their_closure`, full size: one history ends with node 4 reading thing 0 as `"v3"`, which held-model says that node does not hold; another with node 3's status counting a connection's sources for sync IDs that are no member at quiet (`harness::mod` sources check).
- Not from keel-thing-cost2 (both fail on origin/main f4789280a without it); passed 100/100 at 580ca063e, so one of the three landings between (mutation audit, history by the current setting, custody seed) brought them. Next: shrink each (`OSIS_SYNC_SHRINK=1`) and write the minimal reproducers.
