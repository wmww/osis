# `first_superseding` by stamp disagrees with the from-scratch earliest on a rare seed
> Summary: osis-crdt's default proptest `tests_winners::winners_from_scratch_spec_4_8` fails on some of its fresh seeds: for a Value write in a list element of a struct field, `ByWrite::first_superseding` dated by stamp gives a later Ts than the earliest superseding write found from scratch (`first_superseding_check`). Fails on main's code; cause not read yet.
> Priority: normal
> Tags: crdt, tests

**Seen**: a merge gate's default tests (proptest draws fresh seeds per run). `winners_check(15267363352661508123, &[sink_no_seq()], false)` fails (also the shrunk `15267363352661508122` with `true`): "the earliest write superseding Raw { w: Won { path: [Field(6), Elem(STid(..AB)/00000000:4), In], kind: Value, stamp: (196608, ..) }, text_creation: false, .. }": index `Some(Ts(1900544))`, from scratch `Some(Ts(983042))`. Replay: call `winners_check` with that seed from a `#[test]` in core/crdt/src/tests_winners.rs.

**Matters because** the engine dates a death by `first_superseding` (`Killed::note`, spec/crdt.md §4.8 When): a later date than the earliest superseding write held moves when a dead write is read as dead. Either the index misses a superseder (a `hiders` or nesting case under `In`) or the check's `kills` reads one the spec does not count: read both against §4.8 first.
