# Test and gate time
> Summary: Targets (Tess): default tests 4x cheaper than the 8,553 G per-test reference profile (about 2,140 G) without losing coverage that matters, and the whole gate in 10 minutes on ostrich, reached by fixing perf, not shrinking sizes. The per-test figure is about 6,500 G (1.3x); a third of it is fixtures rebuilt per process. Gates selecting roles-model run over the cap at load. The ranked levers, the patterns behind slow tests, and the method.
> Priority: normal
> Tags: tests, performance, sync, engine

Each binary's budget is its line in tools/test_cost.txt; each new default test needs a cut beside it. Profiles: `/home/ai/osis-profiles/` (newest `pertest-*`; `tools/pertest.py top` / `compare`).

## Where it goes
- **Per-process fixtures are a third of the per-test figure**: each test process of the three big binaries (osis-sync `it`, engine `it`, engine lib) builds its cached worlds again (`history::world_of`, `LocalPeer::cached`). A gate pays them once per binary, so caching across processes cuts nothing real; making a fixture cheaper cuts both.
- Most of the cost is in tests of 5-20 G (about 300 of them). Heaviest modules: engine lib `rotation`, `apply`; osis-sync `holding`, `deletes`, `growth`, `delete_keys`, `idle`; engine `it` `validity`, `order`, `scale`, `flows`, `shred`.
- **Gate**: gates selecting roles-model are over `gate.properties` CPU (story searches' cost per world: `random_worlds_hold_large`, `small_family_holds_large`) and over the 10 minutes at load near 50; the order properties (`held_set_decides_plain`, `_exhaustive`) are the costliest single properties.

## Levers, by evidence
1. **Cheaper fixtures**: osis-sync's `world_of` (nearly all `introduce`'s redeems over real sync, so mostly lever 2 seen through the fixtures) and engine lib rotation's cached setups; fewer distinct fixtures (tests sharing one world) also count.
2. **osis-sync per-delivery work** (issues/read-rejudges-per-delivery.md): a settle of every module per delivery (`Read::settle` about 40% of a world test after its fixture); `follow_certificates` at every follow; a store commit per opened entry. `may_log`'s body derivation reads roles at now through `held::Timelines::role_now`, which stamps every holder's read, so a role change on any holder moves every `may_log` under the sync ID: narrow `role_now` to the edges walked, or let `may_log` take read's settled body.
   - In osis-sync `it`: `Read::settle` about 27% (`may_log`, `wrap_secret`/`epoch_under`, `read_facts`), the drop's `check_index` 11%, `introduce` 7%, the quiet checks 6%, the differential's `quiet_model` re-handing refused packages 4.5% (each a full ingest whose end flows run).
3. **Debug end checks**: the drop's `check_index` is 17-23% of engine modules (issues/index-check-rebuild-cost.md); its loads are mostly KEM opens. Every-transaction checks with super-linear cost: `flows::addenda::missed` scans every held commit after each durable transaction (run it in full only after a transaction changing a role edge, a role commit's validity or held parts, or passing a removal's window end, and at drop); `check_walks(false)` rebuilds the whole blob-wait index per transaction (check the walks touched, the whole at drop).
4. **Held writes per join** (`osis_crdt::Held::change` over `PagedRows`): about 11% of engine lib `rotation::`, the product's cost of every superseding write. Row reads are about 4 per write, flat in the writes held (positions' tops per kind, read once per change: crdt `a_join_reads_rows_by_what_it_changes_spec_4_8`); what is left is `PagedRows` itself: each change re-encodes every page it wrote (`row_pages::encode`, a quarter of a change), page decodes and per-lookup navigation (`page_of`), and the change's position cache lookups. Levers: pages written once per transaction instead of per change; cheaper lookups.
5. **`LocalPeer::packages_hashed`** (9% of engine `it` `validity::`, lib `rotation::`): each changed sender re-asks every held commit; the lever is per-commit invalidation, which needs the engine to name the commits a transaction or tick moved for `sync_bodies` (a product change).
6. **A body's facts derived again per write on its aspect**: a part's date reads the aspect's state row, own covers read the author's newest own replace: O(n) per write (issues/derived-state-recomputed.md item 2).
7. **Memos re-run on unchanged answers**: `Core::bound_to_horizon` and `may_rotate` read a component's whole timeline (issues/derived-state-recomputed.md item 3).
8. **The forensic attack** in a sync world (`deletes::a_purged_or_replaced_part_*`): the path it guards exists only in a sync world, so it stays; its cost is candidates times sealed sections (`Trial`'s section key derivation, `Keystream::new`, zeroizing).
9. **A large map written whole** (osis `api::values_past_limits_error`, `a_whole_read_loads_at_most_its_bound`): about 0.5 M instructions per entry of a 10-20k-entry map, half the drop's `checked_index` (`rows_exact_on` streams the part again), half the paged join (`join_part` per page: `set_state_touched`, `rewrite_set`, `Killed::note`). Count per page at n and 10n entries before changing it.
10. Allocation (`Value` trees for epochs and schema reads, fragment clones where a join could consume its side, `kdf_key` formatting its purpose per call); redb serializing its allocator state at every open and close (about 15% of an osis-cli `cli::*` test on a directory store).
11. **Each CLI call opens the store**: an open judges every held body again (`Read::settle`, about 40% of osis-cli `cli::named_keys_with_schema_plan_cli_1`) and its close runs the debug whole checks (about 25%), so a test of k calls on a growing store is O(k^2).

Rejected: `opt-level` 2 for the workspace (3-10%); fake or memoized crypto in tests (debug and release differ, every forgery test must opt out).

## Budget
- The gate: 10 minutes wall without its lock wait (notes/time-limits.md, Limits). Ostrich spends about 1.6x the CPU-s per u that fastbox-0 does, so its u limits are tight by that factor until u is timed on real work. `gate.sim` and `gate.properties` shares were moved to their work by a coordinator (Windlass); Tess may undo it.
- The default tests run their binaries in turn, each ending on its slowest tests (about 55 s above CPU/16 on a quiet box); running binaries side by side would close it on a quiet box.

### Levers that need Tess
- The drop's index check sampled (10-15% of every engine property).
- held-model judged after a sample of a clocked order's ingests instead of every one (a quarter to a third of the two order properties).
- Smaller gate sizes; u timed on real work.
- Default tests of only the crates a branch's paths select (the properties' rule, notes/gate.md, The selection): an engine change would skip the crates below it, a sync- or osis-only change also the engine's binaries. It changes CLAUDE.md's gate, and a test drawing fresh seeds per run would run only when its crate is selected.

## Properties and builds
- **The engine compiles twice**: every engine edit compiles osis-engine as a library and again with its 600-odd lib tests, the build's critical path (notes/time-limits.md, Patterns, An engine change). Moving them into `it` saves the lib tests' CPU and at most about 15 s of wall per edit, but is not mechanical: they reach about 1,500 `pub(crate)` items through `super::`/`crate::`, and a second feature set for tests is not allowed (notes/build.md). Tried on osis-crdt (blanket `pub`): no wall saved (crdt's lib tests build off the critical path), and blocked by tests building records field by field, `seq::LIN_MIN` as `cfg!(test)`, and `cfg(test)` checks in the library; each needs its own design. Count what the engine's tests reach before deciding.
- **Builds after a rebase**: main moving under a low crate rebuilds every dependent's test binaries (5-17x the `build` share). `gate.gui-tests` compiles kit, app and masonry test binaries inside its stage; prebuilding them in `build` would put the cost where its share counts it.

## Patterns
- **Per-whole work redone per member**: a commit's reading built again for each part (`part_valid` in a loop instead of one `Judge`), a search from a root over every thing it minted per thing asked: linear at small n, 10-40x at a requirement's 2,000.
- **A harness loop that cannot tell progress from a repeat**: a pending commit handed again comes back `Pending` every round, so a hand-until-quiet loop runs its whole bound.
- **Per-receiver work that is per-sender**: build once per sender state, trim per receiver.
- **A flip-prone input read before the answer needs it**: read it last; a small map read whole where one key is asked: index it.
- **Derived values whose inputs move far more often than their answers**: `Cutoff` rows or narrower reads (n readers of an aggregate over n inputs record O(n²) reads per change).
- **A restart for a new session**: each restart is an end of history, checked whole; a test of what an operation loads cold uses `Engine::forget_cached` and restarts once at the end.
- **The forensic attack** per test: a test of what one node must not open runs it on an engine-level world (`flows::a_section_of_a_thing_not_held_leaves_nothing_on_disk`) and checks the sync world by what the node holds.
- **Worlds built from nothing per case**: copy them (notes/test-harnesses.md, Copied worlds).
- **Width**: a covering set by default, full width through `testenv::large_n` and `_large` twins.
- **Real time waited out** in osis real-runtime tests (`runtime.rs`, `port.rs` timeouts).
- **Large single tests**: split rather than slimmed when their work is spread evenly (the judgment vectors: one test per file; the named order checks).

## Method
Per test or module: `tools/pertest.py` (`top`, `compare`; `run --modules` for what a gate pays). Whole binaries: `tools/icount <bin> -q`, under `tools/heavy`. Profile: `tools/cpuprof OUT <bin> -q`, or callgrind. Why a judgement re-ran: `osis_base::costs::take()` around the step, reading the `"<effects> <- <cause>"` counts (notes/engine.md, Why a key went due). CPU seconds move 20-40% between identical runs: compare instructions.
