# The end-of-history index check's rebuild cost
> Summary: The index check at each engine's drop (`Engine::check_index`) opens from the persisted index (with the open's secrets sweep) and rebuilds from the commit records: 15-20% of engine lib tests and over half of many engine `it` tests, the biggest debug-check cost. Checking only the rows each transaction wrote misses what the rebuild finds, so a cheaper check needs another design.
> Priority: low
> Tags: tests, engine

The check opens from the persisted index and rebuilds from the commit records (a second judging of the whole history, its records and parts not decoded again). What the rebuild catches that the open does not is a row the incremental code should have written and did not (planted: an edit's place left out of `originals`: 37 tests catch it, 16 without the rebuild). A per-transaction check of the rows a transaction wrote is blind to exactly that (17 of 37), so it is no replacement. A cheaper check keeping the property needs one of:
- a per-record derivation: for each record a transaction touched, every row it derives from that record alone, compared both ways (catches missing and stray rows of direct derivations; rows judged from other records, the arrival-order class, stay the rebuild's);
- the rebuild's own cost cut: it opens every live history entry again (`osis_keys` `open_histories` at every ingest) and decodes every state again (`observe_state`); cheaper loads are the product's open (issues/long-aspect-cost.md, Engine levers).

Where it goes (cpuprof, engine `it` `expiry_model::expiry_takes_its_commits_writes_spec_crdt_4_7`, 24 G at 2114d59ad): `checked_index` 69%, its `apply::load` 58%; verifying every recorded step's signatures again at each load (`Core::steps_recorded`, `sync_ids::steps::Recorded::of`) 18%; the open's sweep (`flows::reopen_all`, decoding every `secrets.0` state: `secrets_decoded`) 10%. Against 12056fd91 the check's samples grew 3.7x (the test's 2.8x), the recorded-step verification 5x.

Rejected: reusing the live engine's decoded states (needs a bytes compare per state) or its opened boxes (memoized crypto: issues/test-time.md). Sampling the check is a Tess call (issues/test-time.md, Levers that need Tess).
