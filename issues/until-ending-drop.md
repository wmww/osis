# An edge's `until` ending drops nothing by itself
> Summary: Lost access by an `until` passing is only judged at the next role commit on the thing or a manual `drop_lost`. Automating it has traps; what the keep-after-removal branch learned before it backed the attempt out.
> Tags: engine, node, security

Requirement: a node whose edge's `until` passed should drop (or keep, as the thing's default said at the ending) what it lost without needing another role commit or a manual `SyncEngine::drop_lost`. Reads by clients already end at the `until`, the node's own secrets and content do not.

Attempt (keep-after-removal, reviews 1, 3, 4; backed out): due scopes re-armed each target for its roster's next `until`, then gates. Each fix added states.

Traps:
- **Offline holder loses valid writes.** Re-arming alone: `until` passes offline, a renewal is on its way or unsent writes wait, the drop erases them. Dropping needs "heard its labels out" (every label with hosts idle, or stranded or refused).
- **A received commit bypasses that gate.** A role commit on the thing arrives beside the expired edge; the trigger judges the actor lost at once, though the commit says nothing of that edge. This one exists on main today. The fix needs telling a loss by time alone from a real one: the walk with every edge's time ahead (`lost_by_time`).
- **Stuck states.** A host down, or one that never lets a pass finish, holds the gate shut, so it needs a bound. `LOST_HEARD_WAIT_MS` = `ROLE_KEEP` (90 days): at 0 every offline holder loses those writes, at infinity a dead host keeps every expired share for good.
- **Dead host trade-off.** The gate is per node, not per thing: one dead host delays all timed losses of the node up to that bound. A per-label gate needs the labels of a thing's readers, more state.
- **Client view.** A thin client reads nothing past the `until` and a copy only once made, so an offline app sees a keep share vanish, then return when the node hears out.
- A renewal made after the drop comes back by a re-seal through the stranded heartbeat: works, slow, tested once (`a_late_renewal_comes_back_by_a_re_seal`, removed with the path).

Costs measured: the work list holds one entry per thing with an `until` ahead (23 B each, a growth row): a scan took 22 µs at 10^4 entries and 0.6 ms at 10^5, per step, so that attempt added a by-time index. `heard_out` is O(labels x connections) per step while an expired edge waits on a host down.

Not part of this: a removal saying keep is written with `until` 0, so it is a plain loss at every clock (spec/permissions.md §2). An `until` ending reads the default in force at its key.
