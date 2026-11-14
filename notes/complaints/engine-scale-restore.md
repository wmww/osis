# engine-scale-restore
- Timing a phase with `osis_base::costs::take()` inside a `measured` closure zeroes the counts the closure is measured by: every check then passes with 0 at n and 10n. Probe with `costs::take` outside the measured region only.
- `group_change_is_flat` spends most of its time in uncounted debug checks (`groups::check_refreshed`, O(group) per change); counts are flat, wall time is linear, and only n cuts it.
