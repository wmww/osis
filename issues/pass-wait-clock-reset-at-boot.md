# A pass's wait is never credited where every boot sets the wall clock back to one time
> Summary: a resumed pass credits only the wall time since its row; a node whose wall clock reads the same time at every boot (no RTC, no saved time) and that restarts more often than `PASS_WAIT_MS` with a recorded peer away never ends the pass.
> Priority: low
> Tags: sync

spec/sync-status.md §1: a pass under way at a stop is begun again having waited what the wall clock shows since its row, the row rewritten to now when ahead. A boot clock set back by at least the last run's length shows nothing waited, so each run starts the full wait again. The monotonic clock restarts too, so nothing durable says how long a run lasted. A fix needs that recorded during the run (the row moved back by what was waited, rewritten as the pass runs or at a clean stop), at a write cost per pass under way; a clock this wrong also stalls other wall-dated rows (tombstones, `ROLE_KEEP`).
