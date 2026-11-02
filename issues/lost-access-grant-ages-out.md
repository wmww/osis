# A loss kept by a pending grant has no trigger once the grant ages out
> Summary: when the lost-access trigger (`LostScope::Due`) finds an actor kept only by a plausible pending grant, it consumes the work list; if the grant never applies and passes `PENDING_GRANT_WAIT_MS`, nothing re-runs the check until another received role commit touches the actor (or an explicit `drop_lost`), so the node keeps secrets it lost.
> Tags: node-sync, security

## Notes
- Self-removal losses are covered: node-sync's `drop_left` stays armed with a wake at `Leaving::recheck_at`. The same shape would work for the trigger: `judge` (rotation/lost.rs) already returns when each kept actor's plausible grants age out; keep those tids in `l/` (or a timer) until then.
