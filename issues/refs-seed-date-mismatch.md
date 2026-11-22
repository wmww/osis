# A refs-property world dates a body unlike the state's deaths
> Summary: osis-engine `refs::known_references_are_a_scan_of_held_values_plain_spec_data_model_8` panics at seed 645570404248 in the dating debug check (`whole_date`): "dated from the held writes vs the state's deaths" on aspect `x:a.0`; fails alike on main's binary (979f98cd0). The single-form dating (e9106288b) keeps that check an equality, so the held writes and the joined state disagree on which write died. Cause not read.
> Priority: normal
> Tags: engine, crdt

Replay: `OSIS_KNOWN_REFS_START=645570404248 OSIS_KNOWN_REFS_SEEDS=1 cargo test -p osis-engine --test it -- --ignored --exact refs::known_references_are_a_scan_of_held_values_plain_spec_data_model_8`. First find the value shape on `x:a.0` (sets with equal values? c0dba57a1 changed equal set values to read once; the forged embedding case was the last such mismatch), then which side matches spec/crdt.md.
