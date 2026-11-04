# A list element's value-less copy loses its mark in an un-merge
> Summary: The rule "a copy of a creation without a mark beats it" (spec/crdt.md §4.7, §5.7) takes no mark to mean valued. An un-merge breaks that: `seq::remove_dots` takes the flag of a fallen writer, leaving a value-less creation with no mark, which then beats a valid copy's mark by arrival order, and a reset that replaced a mark takes the mark with it when it falls. Order-dependent state; a nested write would read shown or hidden accordingly. Needs a writer falling; the older order oracles draw no expiring list element and miss it.
> Tags: crdt, engine

Repro: `OSIS_ORDER_SEED=7520033 OSIS_ORDER_LEN=40 cargo test -p osis-node --test it -- --ignored --exact order::arrival_order_list_expiry_large_spec_crdt_4_7` (also 7520028). Both pass at the base without marks.

Tried in review: `remove_dots` leaves the mark when a flag falls or its creator is removed, implementation and model. Those seeds pass, but `seq_unmerge_spec_4_6`, `seq_remove_writes_rejoins_spec_4_8`, `seq_copies_agree_and_rejoin_spec_perm_5_2` and `hostile_list_matches_model_spec_6_2` fail: stripping then rejoining no longer gives the state (the likely cause, not traced: a stripped copy now reads ended where no valued copy rejoins).

Simplest rule left to try: the state bit the old issue named. Value-less is its own field, joined with valued winning, carried on the wire beside any reset, so no reset or un-merge can lose it.
