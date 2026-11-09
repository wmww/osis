# held_set_decides fails at full plain size
> Summary: `OSIS_FULL=1 OSIS_ORDER_START=5000 held_set_decides_plain` (80 seeds) fails 5: two held-model validity disagreements (5021 PartsAway, 5026 Required) and three settled histories reading other than the keep-everything node before the exchange (5014, 5022, 5078). The tenth-size runs pass; nobody had run full size.
> Priority: normal
> Tags: tests, engine, held-model

Replay: `OSIS_ORDER_SEED=<seed> OSIS_ORDER_LEN=60 cargo test -p osis-node --test it -- --ignored --exact order::held_set_decides_plain` (`OSIS_ORDER_SHRINK=1` shrinks).
- 5021 (PartsAway): validity of a `t:sig~0` write: model invalid, node valid.
- 5026 (Required): validity of a `t:text.0` write (#31) at an earlier clock after 29 ingests, a held set without some commits: model valid, node invalid. The thing has a required-retention setting.
- 5014, 5022, 5078 (Settled): `settled: shows other than the node keeping every body` on `t:tags.0`, `t:book.0`, `t:gonemap.0`. Possibly the class of issues/settled-purges-3751.md (pre-exchange only there); check whether the node agrees after its exchange.
Each is a property violation whatever the rate: judge it as the rule it breaks.
