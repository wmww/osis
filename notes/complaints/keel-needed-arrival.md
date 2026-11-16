# keel-needed-arrival
> Summary: mishaps and slow spots met while building "references are needs, dropped when the pass ends".

- Judging at the end of each arrival transaction broke parent-first delivery (an ancestor's record arrives before what needs it) and forced refetch machinery into every one-shot delivery; a day went into that before Keel moved the judgement to the pass end. Ask about the judgement point before building one.
- A full `cargo test -p osis-engine` takes 10+ minutes on a loaded box (the lib tests alone 6-11 min).
- Scripted edits (inserting `lp.hold(..)` after raw `new_thing` commits; a sed over `arrived`) hit loop-scoped variables and unrelated words; check the build and `git diff` after every bulk edit.
- Several engine tests depend on incidental setup: any extra commit in a shared setup (the introductions' weaks) moves tids and `own[]` indexes, which broke a purge test's `back` index, a scripted dispute, and `tickets::a_sync_id_two_things_*` (fails on main too under one extra commit: issues/ticket-sync-id-incidental.md).
