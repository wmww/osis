# net-lan-inprocess
> Summary: The LAN loop's timers were tokio wall time; a repeat could only be tested via a config field or paused time (needs tokio `test-util`, which feature unification and `block_in_place` rule out).

- The repeat interval had to become `LanConfig::announce`: tier-1 lost-announcement test needs it short.
