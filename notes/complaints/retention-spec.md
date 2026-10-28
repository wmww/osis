# retention-spec complaints
> Summary: Footguns met on the retention-spec branch.

- A background loop of single-seed order replays, started while I kept editing engine code, produced nothing (each seed's cargo call rebuilt mid-edit or failed to compile); start such loops only after the code is final.
- A failing order seed's replay spends most of its time shrinking (1-2 min per seed even with `OSIS_ORDER_SEED`); checking one known history is faster through a scratch test calling `check(seed, &h, cfg)` directly.
- The order harness compared whole texts, so tolerating one documented difference meant parsing its own debug output (`alike` parses index death and commit lines); structured judged output would be easier to tolerate against.
- Scope changed mid-branch (per-node death dating approved): the dropped-superseder tolerance was built, verified on 2000..2200, then removed; about an hour of exhaustive runs wasted. Owner calls pending on a branch's own item are worth settling before the worker starts it.
