# Complaints: storm-cap
> Summary: a storming differential seed costs about 150 CPU-s per candidate, so its shrink runs about a minute a candidate; the storm panic names no node or input kind; `unsafe` is forbidden in tests, so a probe cannot switch on an env var mid-run.

- The storm panic printed `still flowing (first 8 of 0): []` and the wakes: the loop was one node ticking at a wake equal to now, which the message does not say. A line naming the node ticked most in the last deliveries and its last wake against the clock would have pointed at it at once.
- Shrinking a storm: each candidate that still storms runs to the 30,000-delivery cap (about 60 CPU-s), so 45 candidates took about 40 minutes in a hold. Probing the engine's `next_timer` parts on the 13-step script found the cause faster than the shrink got from 13 to 11 steps.
- A harness probe wanting to switch a product probe on near the cap cannot `std::env::set_var` (`unsafe` forbidden in tests): the product probe prints on every call and the log is cut with `tail`.
