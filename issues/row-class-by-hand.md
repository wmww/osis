# Callers pick a row's storage class by hand
> Summary: About 47 engine call sites choose memory vs durable storage themselves (`Tx::set_memory`, `Tx::in_class(..)`), though the commit or aspect a row belongs to already decides it; the same mode also drives clock persistence and end work, and is kept twice (`Core::memory_tx` mirrors the store transaction's mode). Fix: derive each row's class from what it belongs to, then one flag or none.
> Priority: low
> Tags: engine, store, ephemeral

## Now
- The store places a row by its transaction's mode (`Transaction::set_memory`), by an aspect key's `+` marker (`Ak::ephemeral`), or by where the row already is (notes/local-store.md, Memory overlay).
- Engine code sets the mode around memory-class work: `set_memory()` at entry points (`ingest_memory`, `apply_waiting_memory`, `memory_charge`, ephemeral snapshots, compaction weighing, blob reads), `in_class(is_memory_commit(c), ..)` around single rows, and "if `ak.ephemeral()` set memory" in compaction and snapshot code.
- Through `Core::memory_tx` the mode also decides whether the HLC is persisted at apply, and which end-of-transaction work runs (`wake_covers`, `apply_destructions`, persisted indexes).

## Direction
- A row's class follows from its owner: a commit's rows and timers from its header's ephemeral marker, an aspect's from its key, a blob from the commit listing it; `put_commit` and the timer, aspect-record and blob writers pick it themselves.
- "Did this transaction change durable state" becomes whether it wrote a durable row (the store knows), read by the end work. Then `Core::memory_tx`, `Tx::set_memory` and most `in_class` calls go.
- Placement errors are silent (a memory row in the durable store survives a restart; a durable row in memory is lost), so the change needs a check comparing every row's class with its owner's.
