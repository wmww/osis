# sim-chain-review
- `Core::timer_floor = 0` does not wake a daemon: node-sync wakes at `next_timer` (`Node::next_wake`); only the osis handle's `expire_due` reads `timers_due`. "Make a tick due" means making `next_timer` say now.
