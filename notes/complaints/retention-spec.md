# retention-spec complaints
> Summary: Footguns met on the retention-spec branch.

- A background loop of single-seed order replays, started while I kept editing engine code, produced nothing (each seed's cargo call rebuilt mid-edit or failed to compile); start such loops only after the code is final.
- A failing order seed's replay spends most of its time shrinking (1-2 min per seed even with `OSIS_ORDER_SEED`); checking one known history is faster through a scratch test calling `check(seed, &h, cfg)` directly.
- The order harness compared whole texts, so tolerating one documented difference meant parsing its own debug output (`alike` parses index death and commit lines); structured judged output would be easier to tolerate against.
- Scope changed mid-branch (per-node death dating approved): the dropped-superseder tolerance was built, verified on 2000..2200, then removed; about an hour of exhaustive runs wasted. Owner calls pending on a branch's own item are worth settling before the worker starts it.
- Review: `pkill -f <pattern>` killed my own background harness run (the documented footgun in notes/build.md, met anyway); a 2-min rerun.
- Review: `eprintln!` instrumentation in engine code is invisible in a passing order run unless `--nocapture`; I first read zero hits as "never reached".
- Review: building constructions out of order-harness `Step`s is slow going: `Demote ... at` counts only content writes (`marks`), so demoting an admin with no content writes backdates to T0, and same-millisecond clocks make "as of" include the next commit; an `Advance` between steps fixes it.
