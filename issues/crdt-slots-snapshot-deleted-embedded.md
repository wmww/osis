# A snapshot of an upgraded text with a deleted embedded char does not decode
> Summary: At a `Slots` position (a `string` upgraded to `text`, spec/crdt.md §7) whose text member holds a deleted embedded char (`Derived` dot), the snapshot drops the char (§3.3 rule 5) and every decoder, the model's included, rejects it as a non-canonical `Slots` (rule 7: re-embedding the register would restore the char). Encodings are byte-identical, so it is a spec conflict, not a divergence.
> Tags: crdt, wire, tests

Repro: model writer creates text "xy" (ts 50), a register write "ab" at the position (ts 100), then a text delete of the first visible element (the embedded 'a', ts 102); join, `encode_snapshot`, `decode_snapshot` → `Malformed("slots not canonical: pruning changes it")`; models/crdt `decode_snapshot` → `Bad("non-canonical slots")`. The generator never writes string registers (`random_value(Ty::Register)` is an int), so no differential test reaches embedded chars except hand-built ones; `tests_seq::snapshot_then_edit(upgraded)` avoids the snapshot for this reason.

- Fix options (spec, owner sign-off not needed before release): rule 5 keeps the chars of deleted `Derived` elements in a snapshot (they are implied by the register's value anyway), or rule 7's "pruning would change it" check ignores chars of deleted elements. The first changes snapshot bytes only where embedded chars are deleted.
- Then: a string-valued register in `crdt_model::gen` so the lockstep and wire differentials meet embedded chars.
