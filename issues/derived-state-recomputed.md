# Derived state still recomputed coarsely
> Summary: The engine derives most values through `osis_base::memo` memos that record what they read (notes/engine.md, Derived values); left: hand-kept change counters read by `Engine::point`, coarse reads that rerun memos (aspect state rows, whole timeline components), validity's five stale sets, the cost of debug comparisons, and per-ask derivations not yet memos.
> Priority: normal
> Tags: engine, performance, tests

## The rule (notes/principles.md, Fast by construction)
- A function of something immutable is computed where the input enters and kept beside it while the input lives.
- A function of mutable facts is a memo that records what it read, stamped where the facts are written (store rows, blob holds, `Core`'s indexes, held set, timelines at the grain each read sees).
- A function of time reads the time on the memo clock (notes/engine.md, The time inside a judgement): whole, or bounded by `Clock::at`/`bound` when its answer holds to a deadline.

## Left
1. **`Engine::point`** (`ReadPoint`; the sim's convergence check caches each node's reads by it) reads `generation` and `memory_generation`, the last hand-kept counters: replacing that reader lets them go (and one of the storage-class mode's jobs, issues/row-class-by-hand.md).
2. **Aspect state rows are stamped per aspect**, so a join moves every part's replaced-at date on its aspect. Lever: a part's date stamped by the positions it read (`state_part_at` and its dead writes' rows in `osis_crdt::Held`), so a write re-dates only parts whose writes it can supersede; worth it only after item 4.
3. **Whole-component reads**: `ensure rotated` and `reseal: scan` rerun on `Core::bound_to_horizon`'s whole read of the thing's component though their answers only bound the clock; `may_rotate` likewise; `epochs` reruns on `ix.secrets`. `Engine::tree_refs`' counted reaches are incremental state, not a memo: each question re-reads the blobs a count lacked. `body_facts` tries every snapshot ever held of an aspect against each body.
4. **Validity's five stale sets** (`stale_things`, `stale_authors`, `stale_under`, `stale_commits`, `stale_all`): a part's judgement reads its author's authority as the whole component (`timelines.get`), so a memo per part would re-judge every part on the component where the stale sets re-judge only the authors whose role moved. Reading at step 4's grain (`roles_on`, `on`) first.
5. **Debug comparisons**: `apply::check_rebuilt` after every changing transaction, and the memos' own comparisons (a few % of test time). Not tried: memos proven stamped by construction (each takes the whole `Tx`/`Engine`/`Core`; would need a narrower view type per function).

## Not memos, by audit
- Clock-relative, per ask: `rotation::blocked_roles_of`, `Engine::pass_end`, `rotation_due`, `own_secrets_candidates`, `Core::may_read`, `finalizable`, `roster_of`, `links_due`.
- Not clock-relative, per ask: `sync_ids::certs::{latest_by, destroyed_upstream, history_certificates}`, `giving_wrap_epoch`, `part_body`, `deposit_seed`, `keys_write_unapplied`, `Engine::epochs`' fallback.
- Blocked by unstamped reads: `readable_by` (`sourced_elsewhere`), `next_timer`/`timers_due`, `freed_wants`.

Each change is checked by counted work (a step with nothing new derives no key, checks no signature, decodes no commit), never time.
