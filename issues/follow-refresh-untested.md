# Engine::follow's refreshes partly reached by no test
> Summary: Two `Cutoff` refreshes are reached by no test: the sync driver's `Engine::follow` calls (every move in today's tests also brings a commit whose judgement refreshes the rows) and the held-writes rows' refresh in `follow` (every date asked refreshes them first); a missing refresh would not fail any test.
> Priority: normal
> Tags: tests, engine, sync

notes/engine.md, Per-key rows: a reader depends on the rows as last refreshed, and the driver calls `Engine::follow` before each module's settle (core/sync/src/driver/mod.rs). Removing those calls, or `follow_held_writes` from `Engine::follow` (core/engine/src/sync/mod.rs), fails no test.

Owed:
- a sync test where only a row's input moves (no commit judged after it: a clock passing an `until`, a ticket or link alone) and a follower must act after the driver's follow alone;
- an engine test that a follower reading `Core::held_writes_rows` is due after `follow` alone, with no date asked first (as `rotation::tests_stranded::whether_a_body_wraps_moves_at_a_grants_until_spec_crypto_4` does for the wrap blocks).
