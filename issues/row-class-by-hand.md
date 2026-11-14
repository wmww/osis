# Callers pick a row's storage class by hand
> Summary: About 37 engine call sites choose memory vs durable storage themselves (`Tx::set_memory`, `Tx::in_class(..)`), though the commit or aspect a row belongs to already decides it; the same mode also drives change counters, node-sync marks and clock persistence, and is kept twice (`Core::memory_tx` mirrors the store transaction's mode). Needs a design pass: derive each row's class from what it belongs to, then one flag or none.
> Priority: low
> Tags: engine, store, ephemeral

## Current shape
- The store places a row by its transaction's mode (`Transaction::set_memory`), by an aspect key's `+` marker (`Ak::ephemeral`), or by where the row already is (notes/local-store.md, Memory overlay).
- Engine code sets the mode around work on memory-class data: `set_memory()` at entry points (`ingest_memory`, `apply_waiting_memory`, `memory_charge`, ephemeral snapshots, compaction weighing, blob reads), `in_class(is_memory_commit(c), ..)` around single rows (`set_timer`, aspect records, `forget_commits`, reverts), and the "if `ak.ephemeral()` set memory" pattern in compaction and snapshot code and their tests.
- The same mode also decides, through `Core::memory_tx`: which counter moves (`generation` or `memory_generation`, `Core::touch`, `rollback_to`), whether node-sync is told an aspect changed (`mark_aspect_changed`), whether the HLC is persisted at apply, whether `group.0` cuts are noted, and which end-of-transaction work runs (`wake_covers`, `apply_destructions`, persisted indexes).
- `Core::memory_tx` copies the store transaction's mode so Core methods without the transaction can read it. `set_memory`, `in_class`, the rollback mark and two resets keep the copies in step.

## Direction
- A row's class follows from what it belongs to: a commit's rows and timers from its header's ephemeral marker, an aspect's from its key, a blob from the commit that lists it. Rows written by `put_commit`, `set_timer`, `put_aspect_record`, `put_blob` pick their class themselves; no caller sets a mode for placement.
- What the mode also drives becomes a question about the work, not the storage: "did this transaction change durable state" is whether it wrote a durable row (the store knows), so the counters, marks and end-of-transaction work read that. Then `Core::memory_tx`, `Tx::set_memory` and most `in_class` calls go.
- Wait for issues/derived-state-recomputed.md step 3: memos are replacing `generation`/`memory_generation`, which removes one of the mode's jobs.

## Why not now
- The memory flag alone (one copy, not two) needs the mode passed to about 45 `touch` sites and the Core-only callers (`apply/keys.rs`, `Engine` methods), touching many files for little gain. Better done with the placement rule above.
- Placement errors are silent: a memory row in the durable store survives a restart, and a durable row in memory is lost. Any change needs a check that compares every row's class with its owner's (the store's debug asserts cover only a few cases).
