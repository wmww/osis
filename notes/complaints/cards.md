# cards
- `memo::Table` has no name, so finding which read keeps an `Effects` key due (issues/sync-read-rejudges-every-step.md) needs hand instrumentation; a table name in `Effects::due`'s debug path would make it one env var.
- libtest prints no CPU time; per-module comparisons need `tools/icount BIN module:: -q` on a copied binary of each revision (about 5 min for both).
- The harness counts a `Taken` input per `Bytes`, so delivery counts are about twice the message count; per-kind counts need a probe decoding frames in `World::deliver`.
- (review) The world cache plays a history twice on copies of one cached world, so the replay check no longer catches a world build that is not a function of its seed; a replay in another process trusts it.
- (integrator) `OSIS_SYNC_SHRINK=1` on seed 11 hung past the 600 s seed timeout without output (a shrunk candidate livelocked); a by-hand ddmin over the script (one test per candidate, run in parallel from a copied binary under `timeout`) got it to 26 steps.
