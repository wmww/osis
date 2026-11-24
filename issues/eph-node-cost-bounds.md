# Ephemeral holder costs left
> Summary: The ephemeral pre-decode bound is loose per part, so one big honest part is refused well below the cap; a waiting memory commit is checked by it again when it applies; the CRDT's in-memory size per element (about 2 KiB a tiny map entry) is what makes the decode ratio; waiting entries that never resolve stay charged until restart.
> Priority: low
> Tags: security, engine, crdt, ephemeral

Built: notes/ephemeral.md, Bounds. Durable deltas: issues/durable-decode-bound.md.
- **Loose bound**: `osis_crdt::decoded_bound` cannot tell a map key from other values, so every map head and set tag pays a value node three times (3x to 13x the charge for small parts); a single part needs its bound in the room, not its charge, so with the 16 MiB cap one part of tiny entries past about 5 MiB decoded is refused. A grammar-aware bound (key positions, struct maps) would relax it.
- **Re-check at apply**: a waiting memory commit is charged its bytes while it waits and must fit the room again by the loose bound when it applies (`Engine::apply_waiting_memory`): a big honest commit arriving while the sync ID's memory is nearly full is refused then and fetched again once room appears.
- **Memory per element**: a tiny map entry about 2 KiB decoded (`Eid` and its key index copy, `Entry`, a boxed `Fragment` per value, B-tree nodes). A leaner layout would shrink every cap's real meaning, durable states while loaded included.
- **Waiting entries that never resolve** (a part on a thing whose record never comes, a demoted writer's commits) stay in Core's pending, charged against the sync ID's memory cap, until restart or their entries go. An admin demoting and re-promoting a writer makes holders drop and re-download that writer's entries once per cycle.
