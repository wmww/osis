# forged-copy-review
- `tools/bin-at` with `--take` for the branch's new test module (plus crdt-model gen.rs, mod.rs) ran the new tests on main's code in one step: the cheapest teeth check; 5.5 min build on a loaded box.
- A forged copy can't be built with `DeltaBuilder` `Add v` when `v` is already live in the base (it writes nothing, `finish` is `None`): pick a value the base lacks.
- No osis encoder writes a `PosW` stamped with its element's dot, so a decoder test needs hand-patched bytes (decode to `Value`, change the counter, re-encode).
