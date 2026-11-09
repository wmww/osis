# net-lan-inprocess
> Summary: The LAN loop's timers were tokio wall time; a repeat could only be tested via a config field or paused time (needs tokio `test-util`, which feature unification and `block_in_place` rule out).

- The repeat interval had to become `LanConfig::announce`: tier-1 lost-announcement test needs it short.
- Review: `tools/heavy` is on main only, not on a branch cut before it: it exited 127 until the rebase, so rebase before the tier-2 run. The per-branch net filter `lan` matches `repro_lan_any_source_connects`, which fails by design and stops cargo before the later crates (`--skip repro_` added to the notes).
