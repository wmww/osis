# A cold edit then move loses a placement the whole state keeps
> Summary: engine pages `seq_cold_edits_keep_placement_plain` fails on main at `OSIS_SEQ_COLD_START=96284297739 OSIS_SEQ_COLD_SEEDS=1`: step 123 "placement kept" (writer 0: edit, move 3494 2 2860): the paged run's placement differs from the whole-state run's. Cause not read; seen at the prop-cost gate, fails alike on main's binary.
> Priority: normal
> Tags: engine, crdt
