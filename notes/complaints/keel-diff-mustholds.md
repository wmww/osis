# keel-diff-mustholds
- The must-hold check (`unreached_must_holds`) names holder, reader, S and commit only; finding why took a hand-added dump of the reader's verdict, part holds (`commit_parts_missing`), `blob_of` and `holds_body` per blob. A failing check printing those for the first lost body would save a debug build per question.
- The sync trace shows no lost-access drop (a forget leaves only `-commit` lines with no cause); I needed a backtrace in `take_meta` to find `rotation::lost`. A trace line per lost actor would have shown it at once.
- The brief's premise (T0 has two sync IDs) was wrong: T0 had one; the second keying was T1's. Check a shrunk script's story against the store's `syncs()` before building on it.
- Full-size seed runs waited 475 s on the heavy lock behind another all-core run.
