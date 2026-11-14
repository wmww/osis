# cards
- `memo::Table` has no name, so finding which read keeps an `Effects` key due (issues/sync-read-rejudges-every-step.md) needs hand instrumentation; a table name in `Effects::due`'s debug path would make it one env var.
- libtest prints no CPU time; per-module comparisons need `tools/icount BIN module:: -q` on a copied binary of each revision (about 5 min for both).
- The harness counts a `Taken` input per `Bytes`, so delivery counts are about twice the message count; per-kind counts need a probe decoding frames in `World::deliver`.
