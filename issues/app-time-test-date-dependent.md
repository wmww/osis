# App test time::week_and_nudge fails depending on the date
> Summary: `app/tests/it/time.rs` `week_and_nudge` creates an event at "now" and expects a nudge of (DAY, +30 min) to give a 90-minute event; run at 00:47 PDT on 2026-10-31 it got 30 minutes (start 18:00, end 18:30 the next day), on main both before and after round 13 item 131, so the gate fails for every branch while it lasts. Likely the default event start/end near the day's end or the DST change of 2026-11-01. Low, but it blocks the gate.
> Tags: app, tests

Repro: `cd kit && cargo test --workspace --locked time::week_and_nudge` (fails at f22efc12). Fix: build the event at a fixed local time instead of now, and cover a DST day explicitly.
