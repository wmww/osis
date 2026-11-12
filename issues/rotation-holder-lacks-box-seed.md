# rotation_holds fails a seed on main: a holder with key access lacks a box
> Summary: Seed 1044279127 of `rotation::tests_property::rotation_holds_large_spec_crypto_4` ends with a holder of an actor, with key access, boxed at no current epoch at its first admin after the due rotations (liveness, `all_boxed`). Fails alike with `Departure::later` empty (main's covers rule); not looked into.
> Priority: normal
> Tags: tests, rotation

Replay: `OSIS_ROTATION_START=1044279127 OSIS_ROTATION_SEEDS=1 cargo test -p osis-engine --lib -- --ignored --exact rotation::tests_property::rotation_holds_large_spec_crypto_4` (2 s). Panic: `seed 1044279127: a holder of Tid(..) with key access lacks a box`. One of 300 seeds from 1044278940.
