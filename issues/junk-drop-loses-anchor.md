# Dropping junk hides valid sequence elements anchored on it
> Summary: With the state exactly the join of the held bodies, dropping a delta that broke a required retention (spec/permissions.md §6, `Engine::drop_broken`) also drops its element records; a valid element anchored on one of them is then hidden, so the node reads less than one that kept the junk, for good (junk is never fetched again while invalid). Repro `order::repro_junk_drop_hides_valid_element_seed_675857810820`.
> Priority: normal
> Tags: engine, retention, permissions, tess-call

An invalid delta's sequence elements stay in the join as hidden anchors (spec/crdt.md §4.6 un-merge keeps records). A valid delta may insert after such an element (its writer saw the element before the `required.0^` that breaks it). Held, the junk body gives the anchor and the valid element reads; dropped, nothing gives it.

`required_drops_read_alike_large_spec_perm_6` (general half) finds it at plain size (seed 675857810820, `OSIS_ORDER_START=675857810819 OSIS_ORDER_SEEDS=60`). The oracle compares reads only after a re-drop: the dropped junk's hidden records leave the state, which no read shows.

The same shape faces issues/invalid-bodies-drop-at-once.md ("an invalid write contributes nothing to the state" is false for sequence records). Simple rules to choose from:
- a node never drops junk (§6 is a MAY; the third drop kind goes, every drop is covered, expiry or purge);
- junk drops only when no held valid write anchors on or nests under its records (a judgment that can flip as bodies arrive);
- a dropped invalid delta leaves its element records as a leftover body (the records, no writes), like an expired delta's leftover.
