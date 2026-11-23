# crdt model: expiry does not commute with join on some histories
> Summary: osis-crdt `tests_model::crdt_equals_model_plain` fails "expiry commutes with join" on some seeds since 6e78e71fc (value-less sequence records held compact): a sequence element's `created` stamp differs between expiring then joining and joining then expiring. The same replay passes at 6e78e71fc^.
> Priority: normal
> Tags: crdt, tests

Replay: `OSIS_CRDT_START=34 OSIS_CRDT_SEEDS=1 OSIS_CRDT_SEED=157455058980 cargo test -p osis-crdt --lib -- --ignored --exact tests_model::crdt_equals_model_large` (1 of 100 plain seeds in a gate). Panics at core/crdt/src/tests_model.rs (`expiry commutes with join`): the two sides' `Seq` agree but for one element's `created` (stamps 917504 vs 983040, different creating dots), so which creation an element keeps depends on whether expiry ran before the join. Turn the shrunk history into a seed-0 hand test with the fix.
