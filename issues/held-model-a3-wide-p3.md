# held-model: A3 fails P3 in a wide world with split commits and late path entries
> Summary: `spec_gaps::evidence_reach_and_generator_gaps_*` fails at A3 (vouches counting) in `wide` world 14204407699 with `Wide { split: true, late: true }`: P3 (an honest removal the full closure of S's bodies holds is missing from S's reader's required set) at step 25, sync ID 11; against notes/evidence-model-findings.md's "A3 holds everything".
> Priority: normal
> Tags: tests, held-model

Repro (main's binary fails alike, 6 s): `OSIS_HELD_START=14204407699 tools/heavy --short cargo test -p held-model --test it -- --ignored --exact spec_gaps::evidence_reach_and_generator_gaps_plain`; output `2 fail, first: a3 vouches true wide Wide { split: true, late: true } 14204407699: Fail { prop: "P3", step: 25, sid: 11, id: 11, reader: None, full: None }`. Found by the pre-wiring gate (seed offset 14204407677, `_large`), on a branch not touching held-model.

To do: shrink the world, then decide whether A3's rule (errand, reach, a split part's or late entry's evidence) misses a removal or the generator makes a world the property misreads; the findings' A3 claim waits on it.
