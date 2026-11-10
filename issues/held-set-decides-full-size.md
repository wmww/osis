# held_set_decides fails two seeds at full plain size
> Summary: Plain runs fail a few seeds, not root-caused (1166974899 at plain size too): 743309 (PartsAway) reads a value after the sync exchange where the keep-everything node reads none; 575825961926 (Settled) reads other than the keep-everything node before the exchange.
> Priority: normal
> Tags: tests, engine

Replay: `OSIS_ORDER_SEED=<seed> OSIS_ORDER_LEN=60 cargo test -p osis-node --test it -- --ignored --exact order::held_set_decides_plain` (`OSIS_ORDER_SHRINK=1` shrinks, 10-18 min). Each is a property violation whatever the rate: judge it as the rule it breaks.
- 743309 (PartsAway), order as made: `now, after the sync exchange` on `t:reg.0`, want `None`, got `"v7"` (spec/requirements.md Deterministic, no excuse applies). Shrinks to 36 steps with the same symptom, without the emphasis's start: two-part commits (`Two`, `Mixed`), `BadPart`, `Forged`, purges by name and author, `Breaking` writes, a record edge removal.
- 575825961926 (Settled), order as made: `now, settled` on `t:docs.0` (a map of texts), want `{k2: "v5v1"}`, got `{k2: "v1"}`; shrunk to 17 steps plus the settling tail: want `{k2: "v1"}`, got `None`. The tail is delivered last as made, so a compaction dropped while invalid does not explain it; check which rule leaves the body missing before the exchange, and whether the node agrees after it.
- 1166974899 (RecordOnly), order as made: `now, after the sync exchange` on `t:map.0`, want `{k2}`, got `{k0, k2}`; the same with own replaces turned off (found on zero-growth-1, so not from them). Shrinks only to 46 steps (16 min): demotions, `Forged`, `PurgeAuthor`, `Breaking`, `Compact`.
- 1413496614 (Settled), plain size, on main 5f1db6e1f too: `t:map.0`, want `{k0: "v4v1", k1: "v8v9"}`, got `{k0: "v4v1", k1: "v8"}` (a text missing one write). Not shrunk.
