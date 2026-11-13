# Ephemeral holder costs left
> Summary: the ephemeral pre-decode bound is loose per part (and a waiting commit is checked again by it when it applies); a replayed take still scans the held parts of its aspects; the CRDT's in-memory size per map entry (about 2 KiB) is what makes the decode ratio.
> Priority: low
> Tags: security, engine, node, crdt, ephemeral

Built: notes/ephemeral.md Bounds. Measurements: `memory::eph_*` (release, by hand).

- Durable deltas: issues/durable-decode-bound.md.
- The ephemeral pre-decode bound (`osis_crdt::decoded_bound`) is loose per part (it cannot tell a map key from other values, so every map head and set tag pays a value node three times: about 3 times the charge for tiny map entries, 5.5 for a map of small structs, 13 for a small register part), so one part needs its bound in the room, not its charge: with the 16 MiB cap a single part of tiny entries past about 5 MiB decoded is refused, of small structs past about 3 MiB. A grammar-aware bound (key positions, struct maps) would relax that.
- A waiting memory commit (the blobs it links, its `ts`, an epoch) is charged its bytes while it waits and must fit the room again by the same loose bound when it applies (`apply_waiting`): a big honest commit arriving while the label is nearly full is refused then, and fetched again once room appears.
- Unverified: a promoted waiting blob whose label this node no longer knows, or whose key no longer unwraps, is applied within no label's room (`apply_waiting` finds no charged entry) and waits until `sweep_pending` drops it. Losing a label clears its memory entries, `refused` and `unfit` (`SyncEngine::forget_lost`).
- CRDT memory per element: a tiny map entry takes about 2 KiB decoded (`Eid` 120 B and its key index copy, `Entry` 56 B, a boxed `Fragment` 176 B per value, B-tree nodes), a small register part with its engine records about 2.3 KiB. That is what makes ephemeral (and durable, while loaded) states large; a leaner layout would shrink every cap's real meaning.
- Waiting entries that never resolve (a part on a thing whose record never comes, a demoted writer's commits) stay in Core's pending, charged their bytes against the label's cap, until restart or their entries go. Also, an admin demoting and re-promoting a writer makes holders drop and re-download that writer's entries once per cycle (up to the label's cap; cost to the admin: two durable commits with rotations).
