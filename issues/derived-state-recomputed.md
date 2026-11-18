# Derived state still recomputed coarsely
> Summary: The engine derives most values through `osis_base::memo` memos that record what they read (notes/engine.md, Derived values); left: hand-kept change counters (`Core::generation`, `memory_generation`) read by `Engine::point`, coarse reads that rerun memos (aspect state rows, whole timeline components), validity's five stale sets, the cost of debug comparisons, and per-ask derivations not yet memos.
> Priority: normal
> Tags: engine, performance, tests

## The rule (notes/principles.md, Fast by construction)
- A function of something immutable is computed where the input enters and kept beside it while the input lives.
- A function of mutable facts is a memo that records what it read, stamped where the facts are written (store rows, blob holds, `Core`'s indexes, held set, timelines at the grain each read sees).
- A function of time reads the time through `Core::time`: whole, or `until` when its answer holds (issues/clock-reads-unstamped.md).

## Left
1. **`Engine::point`** (`ReadPoint`, the sim's convergence check caches each node's reads by it) reads `generation` and `memory_generation`, the last hand-kept counters: replacing that reader lets them go (and one of row-class's jobs, issues/row-class-by-hand.md).
2. **Aspect state rows are stamped per aspect**, so a join moves every part's replaced-at date on its aspect (of 5500 `part_keeps` judgments in member churn, 2000 stale, nearly all by a join). The lever: a part's date stamped by the positions it read (`state_part_at` and its dead writes' entries in `HeldWrites`), so a write re-dates only parts whose writes it can supersede; worth it only after item 4 cuts the comparisons and a count still shows dating high.
3. **Whole-component reads**: `ensure rotated` and `reseal: scan` rerun on `Core::horizon`'s whole read of the actor's component though their answers only bound the clock; `epochs` reruns on `ix.secrets`. `Engine::tree_refs`' counted reaches are incremental state, not a memo; each question re-reads the blobs a count lacked and scans the thing's aspect rows.
4. **Validity's five stale sets** (`stale_things`, `stale_authors`, `stale_under`, `stale_commits`, `stale_all`): validity per part runs on `memo::Effects`, but a part's judgement reads its author's authority as the whole component (`timelines.get`), so a memo per part would re-judge every part on the component where the stale sets re-judge only the authors whose role moved. Reading at step 4's grain (`roles_on`, `on`) first.
5. **Debug comparisons**: `apply::check_rebuilt` after every changing transaction, and the memos' own comparisons (at hits 1, 4, 16, ... after a read container changed, and 16, 256, 4096 regardless; about 6% of member churn, 4% of osis `it`). Not tried: memos proven stamped by construction (each takes the whole `Tx`/`Engine`/`Core`; would need a narrower view type per function).

## Not memos, by audit
- Clock-relative, per ask: `rotation::blocked_roles_of`, `Engine::pass_end` (an effect: split the value it derives from the effect run when it moves; its reads were 5-8% of multi-node workloads), `rotation_due`, `own_secrets_candidates`, `Core::may_read`, `finalizable`, `roster_of`, `links_due`.
- Not clock-relative, per ask: `sync_ids::certs::{latest_by, destroyed_upstream, history_certificates}` (`destroyed_upstream` walks the destroyed things held, `Indexes::destroyed`), `giving_wrap_epoch`, `part_body`, `Engine::inbox` and `deposit_seed`, `keys_write_unapplied`, `Engine::epochs`' fallback. None above 3% in profiles.
- Blocked by unstamped reads: `readable_by` (`sourced_elsewhere`), `next_timer`/`timers_due`, `freed_wants`.
- Hand-kept state that stays, with its reason: `Core::states`/`pages` (the transaction's working copy), `undo::touch::Touches`, `tree_refs::Reach`, `epochs_judged_from` (an effect trigger), perm's `Timeline::memo` and walk cache, `Core::memory_waits`, `apply::reach::Walks`.

Counted checks for each change (work, never time): a step with nothing new derives no key, checks no signature, decodes no commit. Method: issues/test-time.md.
