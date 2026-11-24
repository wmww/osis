# Test harnesses
> Summary: How to run and replay seeded tests (env vars through `osis_base::testenv`, seed runners, coverage floors), copied worlds, the debug checks every test runs, why-kept and row dumps, loop guards, `LocalPeer` delivery by sync ID and sealed delivery, the store-contents differential, measuring (icount, cpuprof, callgrind, pertest), the default-test cost, mutation probes, and harness footguns.

## Env vars and seeds
- Harness env vars (`OSIS_*_START`/`_SEEDS`, `OSIS_PERM_SEED`, ...) are read through `osis_base::testenv`, which panics on an unparsable value, zero seeds, or any set `OSIS_*` variable not in core/base/testenv-known.txt (add a new one at its end; read at run time, so adding one rebuilds nothing). Probe variables: notes/build.md, Footguns.
- A set variable and an overridden range are echoed past libtest's capture: check that line on a passing run, not only `1 passed`. Per-seed output needs `-- --nocapture`. Sizes: notes/testing.md, Sizes.
- **Every property and its variable**: `python3 tools/test_select.py --all`. Each harness prints its own replay line for a failing seed: use it as printed.
- **`_plain` and `_large`**: a seed runner's `_plain` runs the gate-sized sample: a fixed covering set chosen by planted faults (reading no environment), or a seed range the gate offsets; its `_large` reads the range at full size. The replay line names the `_large` where it checks a seed as the `_plain` does, else the `_plain`.
- Engine lib harnesses: `cargo test -p osis-engine --lib <path> -- --ignored --exact`; a copied binary from `tools/bin-at REV OUT --lib osis-engine` runs from `core/engine`.

Crate-wide seeds:
- **osis-crdt**: every `testutil::rng(seed)` samples other runs with `OSIS_CRDT_SEED=<n>`; a panicking test prints the effective seed. Properties take `OSIS_CRDT_START`/`_SEEDS` and draw from `testutil::fixed`, so the printed replay line is the whole replay. `OSIS_SHRINK=<seed> cargo test -p osis-crdt --lib -- --ignored shrink_script` shrinks a failing `fuzz_seq::tests::random_scripts_replay_plain_spec_5_7` script; `OSIS_CRDT_SHRINK=1` on a `crdt_equals_model` replay line shrinks its deltas (keeping to the failure's kind, as the sync harness's shrink).
- **osis-perm**: `differential`, `queries`, `incremental` sample other histories with `OSIS_PERM_SEED=<n>`; each run is 16 shards seeded `seed ^ i << 40` (the panic names the shard's seed).
- **order harness** (`held_set_decides`): `OSIS_ORDER_START`, `_SEEDS`, `_SEED` (one seed), `_LEN`, `_CLOCK`.
  - `OSIS_ORDER_SHRINK=1` shrinks each failure (`order::shrink`) and prints the history as Rust a scripted test compiles (`rust_of`). A candidate counts only when it fails as the original did (`failure_class`); `OSIS_SHRINK_MATCH=<text>` keeps to failures containing the text, `OSIS_SHRINK_ANY=1` to any.
  - `OSIS_ORDER_STATS=1` prints each history and the tallies; `OSIS_ORDER_DUMP=1` explains a failing node (order.rs docs). For a node-holds-or-drops difference, a dump of the shrunk history usually names the cause; probe the drop decision rather than shrinking further.
- **sim**: notes/test-sim.md, Running and replaying.

## Seed runners
- `osis_base::testenv`'s `run_seeds` (and `Seeds::run`, which announces an env range) runs a seed per thread per core (`OSIS_SEED_THREADS` overrides); `run_jobs` is the general runner. A multi-seed run goes through them, not a serial loop.
- **Hung seeds**: `OSIS_SEED_TIMEOUT_SECS` (default 600) is CPU time, not wall. A lower value names a hung seed early in quick runs. A hung thread prints its backtrace at its next `testenv::checkpoint()`.
- `Cpu::now()`/`secs_since` reads the CPU spent on a thread's work, including threads `par_map` and `run_jobs` ran for it. `pooled_map` is `par_map` holding a `Permit` per call, so concurrent tests and seeds share the cores.
- **Coverage floors**: a property over a seed range checks what its seeds reached with `testenv::reach_floor` at every size and offset.
  - The rate is at most what any one seed reaches and, where seeds vary, about a quarter of the mean or less; set it from runs at offsets, never from the default seeds alone.
  - A case a seed draws on purpose (a seed class: `seed % 8 < 2` large values) is asserted per seed instead.
  - A `_plain` running a fixed covering set asserts its set reaches each case exactly; its `_large` twin carries the rates (rotation `tests_property::SHAPES`).
  - A case too rare for a rate at the gate's size gets more default seeds or a draw on purpose, never a floor of 0. The order harness's floors are per emphasis (`Seen::floors`).
- **Converting a fixed-seed loop to a range**: the seed may index nothing but an RNG or a modulus. A value sized by the raw seed (once 44 TB at the gate's offset) aborts the whole property binary; a loop index turned seed keeps everything it fed. A thread-local setting (`PageParams::set_test`) is set inside the per-seed closure, or `Seeds::run`'s threads run at defaults and pass for the wrong reason. Run the converted property once at an offset below 10^12 before committing.

## Copied worlds
A setup many tests share is built once per test process and each test gets an exact in-memory copy of the live world: it goes on as the original would (same next commit IDs, rng draws, connections, queues, memo hits). Reopening stores is not a copy (every node restarts and syncs again).
- **Adding a cached setup**: `LocalPeer::cached(key, || (peer, extra))`, `LocalPeer::cached_world` for a world holding peers beside state that is not `Clone`, or `osis_base::copying::cached` (its module doc) for another world type. Not cached: a setup that closes and reopens a node, real-runtime tests; no osis-level harness shares a setup.
- **Hooks** (test-only, `#[doc(hidden)]`; policy.py keeps them out of product sources, since two live copies are one node twice and reuse nonces, counters and commit IDs): `Engine::test_copy(clock)`, `Store::test_copy` (memory backends only), `NodeRng::test_copy`; harness copies `Peer::copy`, `LocalPeer::copy`. Types owning identity, rng or a live store copy only through these. Event receivers are subscribed again with the unread events (`Engine::test_subscribe_with`); commit listeners are not copied. Differentials: osis-engine it `copies`.
- **A test that passes built fresh and fails on a cached setup** has found a copy that is not its original: rerun it fresh with `lp.copy()` before suspecting the edit. Each cached builder has its own key, and a thread-local filled beside the setup is stored with the cache and set again on every copy.
- **A copy's gap** may be a state a production path reaches too (a copy leaving the path wait unset matches what a rollback leaves): ask which product path reaches the same state before fixing only the copy.

## Debug checks
Every debug-build test runs these, so every test is also an incremental-equals-from-scratch test. None samples. A whole check (O(everything held)) runs once at the end of the history, never per transaction; per transaction runs only what costs about what the transaction did. All are invisible to scale counts (`costs::paused`, `osis_perm::uncounted`).
- **Rebuild check** (`apply::atomic::check_rebuilt`): a touched aspect's state must equal `rebuilt` (spec/crdt.md §4.6), compared encoded with its derived caches. A deferred aspect (`Core::unchecked_states`) a later rebuild rewrites is never seen wrong. A test hook writing a state no body gives sets `Core::unchecked_tx`.
- **Index check** (`Engine::check_index`): on a clock stopped at the last transaction, after the node closure is walked afresh (`check_closure`), compared by `Core::same_index`. It asserts that an open decodes no commit header: judging from headers at load (`LazyHeader::arc()` decodes at once; clone the `LazyHeader` and deref only where the record is held) fails it, often only in properties or the sim. The fresh cores borrow the node's decoded records (`Core::decoded`).
- **Verdict checks** (`Engine::checked_verdicts`, at the end of history and inside the index check): every held commit's flags are what judging it now gives (`validity::misjudged`), and every re-grant bound a role timeline memoizes is what a search finds. Per re-judge only the touched part (`misjudged_on`).
- **Row check** (`retention::leaving::rows_exact`, in the index check; notes/engine-retention-dating.md Rows): each row written in a pass is checked against the state (`leaving::check_row`); at the end the kept held writes are compared with those built from the held bodies (`bounds::index_exact`), shared per process by what they are built of (`bounds::BUILT`). `Core::unchecked_rows` records what is decided independently of the dating. Rejected: every row of each aspect per pass (n squared over a history).
- **The end of history** is the engine's drop (`impl Drop for Engine`): the verdict checks, then the index check if anything durable changed or rolled back since it last ran, else the states left unchecked. A reload runs a due index check first (`check_before_reload`). Skipped under `OSIS_NO_END_CHECKS=1`, while a panic unwinds, a load is half done (`Engine::loading`), a write's outcome is unknown, or the store fails. A copy starts checked. An engine lib test editing an index in memory sets `Engine::index_poked`. `Engine::check_every_tx` (by hand) runs the index check after every changing transaction, to find the one that diverged.
- **Cost**: the rebuild is about 15% of the engine lib default tests (issues/index-check-rebuild-cost.md). Rejected: sampling by transaction counts (no small test then saw a fault that grows); checking per transaction only the index rows it wrote (blind to a row it should have written).
- **Planted faults** no default test catches (`tools/mutate.py`): a forgotten addendum's thing not judged again; a dropped part missing again not judged again; a rebuilt aspect not dated whole (`bounds::mark_bounded`); a replay's raise ignoring the holder's own level. Not covered: a `node/perm` row left stale when a destruction rewrites a role commit's record.

## Why kept and row dumps
Debug builds only, for a count, retention, role or read test that fails; each reads the rule's own code (docs in `engine/explain.rs`). osis-sync's `World` has each per node.
- `Engine::why_kept(t)`: rooted (with its path of strongs), or the chain of needs to the first rooted thing, or that it goes at the next pass end.
- `Engine::rows(prefix, tid)` (osis-sync `World::rows` adds the sync store's rows): each row's family, decoded key, the tids it names and bytes. `Engine::describe_rows` describes another store's rows.
- `Engine::why_role(t)`: roles, paths, secrets and `lost_due`'s clauses (`rotation::lost::explain_due`); its `kept copy` line is the retain decision (`retention::forget`). Dump the unshrunk history too: a shrink drops words and grants that matter.
- `Engine::describe_commit(c)` names a trace's `C..`. `World::sync_ids_of(t)` (any build): how each node syncs `t`.
- Printed on failure: S1 (`growth::releasing_own_things_*`) prints the rows a fresh world's node lacks and `why_kept` of each thing they name (`growth::leaked`); the sync differential's role and read clauses (`history::closure_clauses`) print `why_role`.
- **Replaying without the end checks**: `OSIS_NO_END_CHECKS=1` (by hand only) also skips `World::run`'s quiet checks, so `differential::holds` and scenarios calling `check` return their world for inspection. Never set it while shrinking: a candidate whose failure is the check then passes.

## Loop guards
A fixpoint loop a bug could keep going forever panics in a debug build instead of hanging: `osis_base::loop_guard::LoopGuard` panics past a bound derived from the loop's size, naming the loop and its last 4 rounds. Guarded: `Node::settle`, `LocalPeer::wake`, `Engine::run`'s end loops. The sync `World`'s delivery cap (`World::cap`: `RULE_CAP`, `STORM_CAP`) bounds its loops and `ROUND_CAP` each step's settle rounds. `LocalPeer::sync_all` stops at n rounds; `deliver_sealed` ends when a round opens nothing.
- The bound is a closure so a release build never computes it: compute the size inside it.
- A loop deciding "something entered" from a cloned `Feed` checks the key is still present: `Feed::added` keeps keys a failed step's rollback removed, and such a loop spins to its guard.

## Delivery by sync ID over `LocalPeer`
A node takes content only of things in its node closure (spec/commits.md §4 Outside the node closure). So `LocalPeer::sync`/`sync_all` send what the sync IDs the receiver syncs carry, decided at the sender by the product's rule (`packages_under` over `Engine::carried_under`, `sync_bodies`).
- A sender's packages are built once per engine state (`SyncMemo::whole`) and trimmed per set of sync IDs (`sent_parts`). Certificate parts (`Engine::certificate_parts`) go to every node, standing for routes the harness does not play (cards, links, pairing); fires go apart (`LocalPeer::pass_fires`).
- No repeat work: `sync_all` stops after a round of duplicates; `sync` re-offers a package the receiver dropped only once `retention::needed::needs` moved, and repeats no delivery that came back a duplicate, nor one the receiver holds whole (`Engine::holds_whole`).
- **Hand deliveries** pick the same (each documented where defined): `common::packages_for` (`package_for` for one commit), `LocalPeer::packages_to`/`packages_to_peer` (on a copy), `common::packages_for_peer`, `common::packages_reading`, `common::give_carried`, `flows::send_carried`. In a per-seed or per-order loop use the copy-free forms.
- An observer is an account granted read and holding the thing (`common::reader`, `LocalPeer::fresh_reader`, `fresh_net`, `share`); a role-less node keeps none of a thing's content, so comparing what it reads compares nothing. A fresh reader's seed must not be a net peer's (`net(n, s)` seeds `s*1000+i`): the same seed is the same account.
- A test's receive of forged or partial input goes through `common::unless_refused`, never `let _ =`.
- `Engine::package` hand deliveries are still whole: what they bring outside the closure waits for good (issues/engine-harness-whole-packages.md).

## Confidentiality over `LocalPeer`
`Package`/`deliver`/`sync` hand over plaintext commits, so a peer that lost access still reads what it is sent. "Who can read" claims use the sealed mode (`LocalPeer::sealed`, `deliver_sealed`; flows.rs `sealed_write`, `spread_sealed`). Plaintext is right for setup and for what an engine does with what arrives.

## Store-contents differential
For a refactor that must not change stored bytes or write order. Seeded `LocalPeer`/`MemoryBackend` stores are byte-deterministic once the persisted index tag is pinned (`index.rs` `VERSION` folds in `OSIS_INDEX_RULES`, a hash of the sources). Throwaway patch, on main and the branch alike: in `MemoryBackend::commit` fold each batch's ops into a running hash, and in a `Drop for Data` append `thread-name trace-hash final-hash batches rows` to a file named by an `OSIS_PROBE_*` variable; set `VERSION` to a constant; run the default tests plus the order properties on each, sort, diff. Tests that differ run to run on one build (crash, store, runtime, driver, cli, some sync and encodings tests) differ between builds too: rerun those on one build to rule them out. A store dropped on another thread moves its line to that thread's name: compare without names too.

## Measuring
Compare old and new code by instruction counts, never wall time; no timing runs inside a task. Usage is in each tool's header.
- `tools/icount CMD...` prints `INSTR <n>` (needs `kernel.perf_event_paranoid` <= 2). Counts repeat to under 0.1%; CPU-s vary 20-40%. It prints the count, not whether the tests passed: run the filter first. Old binary: `tools/bin-at`.
- After a rebase, compare against a binary built from the rebased main, never the pre-rebase baseline.
- A multi-threaded property's count moves with thread timing: compare at `OSIS_SEED_THREADS=1`.
- An `--exact` run counts its fixture too (most of a 4-node world test): compare in-process module counts (`tools/icount BIN -q <module>::`; `--exact $(tools/test_names.py BIN ^content::)` for one module alone); judge a shared-fixture change by the whole binary, which a gate pays once.
- `tools/cpuprof` (its header): use `CPUPROF_INSTR=N` (samples every N user-space instructions, so shares compare across runs; its SIGPROF mode skews with load and kills the perm `it`, crypto lib and transport binaries). It keeps 120,000 samples (then reports TRUNCATED): pick N above the run's instructions / 100,000. Over a whole binary it may write a second `OUT.<pid>`: the larger is the test binary's. Its stacks mislead for spawned threads and deep frames: confirm a suspect with `tools/icount` on an env-gated variant before changing code.
- Exact call counts by caller (valgrind is on fastbox-0, not ostrich): `valgrind --tool=callgrind` on one test (`--test-threads=1`), `callgrind_annotate --tree=caller`; a recursive function's inclusive cost (`name'2`) counts each level again.
- Per-test wall times: `RUSTC_BOOTSTRAP=1 <binary> -Z unstable-options --report-time` from its package dir (on the binary: through cargo it builds a second artifact set).
- **Every default test, or every module, alone**: `tools/pertest.py` (its header). `--modules` shows what a gate pays and where to cut; per test, which test moved. A compare against the last profile also catches a storm that landed passing (a test 20x its old count).

## Default-test cost
Each binary's budget is its line in tools/test_cost.txt (notes/gate.md, The summary); where the time goes and the levers left: issues/test-time.md. Only less work shortens the default tests.
- Profiles are under `/home/ai/osis-profiles/` (`pertest-<rev>`, binaries in `.bins/`): start a test-speed job from the newest with `tools/pertest.py compare` instead of profiling again.
- Measured not to help: the order harness's oracle starting from a kept copy (1.4%), every binary at once, harness inner threads at 1, opt-level 2 for workspace crates (edits build 15-20% slower), selecting default-test crates by the diff.
- Patterns that keep a new test cheap:
  - Shared setups copied per case (Copied worlds; `local_peer::Peer::fork`, `apply_order::each_order`, `order::after_setup`, osis-store `FileDevice::copy`).
  - A size bound checked at its real constant with a fixture the bound counts cheaply (a text string counts one item per byte: osis-crdt `page_items_cap_spec_8`), or reached by records instead of commits (`hostile_moves_join_bounded_spec_6`), checked at its count and one past it.
  - A rare case drawn on purpose, then histories run until a coverage tally is met (osis-crdt `snapshot_then_edit`); tally the path the test's name claims.
  - Debug checks that compare, never recompute (`Checks`, `memo::check_effects`, `engine/decoded.rs`).
  - Smaller data where the property is relative; independent pieces as separate tests or on the process's permits (`order::check`).

## Mutation probes
`tools/mutate.py` (usage in its doc) plants a fault, builds once, runs the given tests and prints which failed; a plant no test fails is a test gap: add a focused test, or an issue. For many plants: `MUTATE_HEAVY=1 MUTATE_PER_HOLD=2`. Reference-graph rules, where caught at all, are caught by focused tests, never by a differential or sim alone. Open gaps: Debug checks (Planted faults); issues/strip-rule-gaps.md.

## Harness footguns
**Engine and `LocalPeer`**
- `Engine::local_census` keys keep the family's trailing `/` (`"pc/"`): a lookup by the bare prefix reads no rows and an "is zero" assert passes vacuously. Probe every row-count assert with its mechanism off.
- `Engine::fires_owed` is in `FireId` order: `.last()` is the highest id, not the newest fire.
- `Hlc::peek` jumps to every received `ts`: a wait "until R's `ts`" ends the moment R arrives. A rule "as of its wall clock" reads `Hlc::wall`; a wait on wall time sets a wake.
- `local_peer::Peer::receive` wakes and re-examines after every ingest, so a wake a shortcut skips is invisible there: probe through `Engine::ingest`.
- `local_peer::Peer::pulled_anew` fills only at `receive`/`reexamine`. The order harness's `fetch_missing` never delivers what a node pulls anew: a node relying on one fails `held_set_decides` with no hint.
- `LocalPeer::sync` carries no ephemeral commit: hand one over with `memory_blob` and `ingest_memory`.
- A role commit past `grant`'s refusal needs `m.unchecked` plus `skip_writer_rules`.
- A mutation that changes nothing writes no delta, and a commit with no delta is not made (`commit_tx` returns `None`).
- `Engine::run` rolled back keeps what a trial cached in some `Core` maps: derive secrets from the store record, never from a cache filled inside a trial.
- `Meta::missing_parts` counts parts whose body is absent, not parts the node cannot open: test readability by value (`engine.get`).
- `Engine::seal_package` writes a `dw/` row at the maker: seal after taking a census.
- A test on what a store holds keeps history on the aspects it probes: a store otherwise compacts by its own judgment.
- A thing re-entering the node closure usually rejoins by its own sync ID, so a re-entry test passes with `refetch` broken: only a dependent thing in a unit whose sync ID never left exercises it.
- A drop path that marks commits stale needs a test where the drop happens in the end-of-transaction tail: only the debug assert "stale validity left unjudged" catches a marker set after the last re-judge.
- A late-order test says which copy it delivers: a node's copy of a commit it purged is header-only.
- Hand a grant's packages to a node only after it holds the thing (a strong): what lies outside its node closure is lost.
- A kept copy syncs nothing: a test of a recorded holder leaving uses an ended way whose holder the node still syncs.
- A hand-again-until-quiet loop must not count every non-`Duplicate` result as progress (a pending commit comes back `Pending` every round): stop once a round applies nothing and leaves `Engine::pending` as it was.
- A world built under `PageParams::set_test` must not go into `LocalPeer::cached`.
- `Core::timer_floor = 0` does not wake a sync daemon: node-sync wakes at `next_timer` (`Node::next_wake`).

**Sync `World`**
- `run` moves the world clock by its dial ticks (about an hour on `contacts`), so an `until` a minute ahead has passed before the grantee reads; an engine's `now()` lags the world clock until that node steps; `advance` over a long wait takes minutes of dial ticks: `skew` one node's clock instead. `RULE_CAP` is per world: a hand-built world sets `w.cap = n * RULE_CAP`.
- `power_off` restarts the node's monotonic clock from 0 (`NodeClock::boot`) while wall clocks run on: a monotonic date that outlives a restart reads as far in the future.
- A storm panic in a hand world with partitions is often dial ticks toward the cut-off peers: raise `w.cap` before reading it as a loop. A world waiting out `PASS_WAIT_MS` with a node away costs 7-10 GB, mostly such ticks.
- No World lever splits a rotation from its step or one fetch over two sources: deliver such a race by hand inside the `w.write` closure, before `Input::Wrote` lets the node settle.
- `step_or_wake` keeps returning true while any node dials a partitioned peer: bound such a loop by world time. Check what a peer was served after each delivery, not after `run()`.
- The quiet checks (`unlogged_must_holds`, `unreached_must_holds`, `wanted_blobs_in_reach`) run at the end of every `World::run`, a partitioned mid-script one included: read which step's run panicked first. A test that wants a pass still under way after `run` steps by hand (`step_or_wake`).
- Streams harness: a body opened as `Opening::Taken` leaves no store entry though the pull worked: check `knows`. A late message harms only a member already at the stream, so a late-reply probe on a first join passes with its rule disabled.
- A world test of a change made while a peer is away passes with the in-place judgement removed (the first reconnect judges every member): mutation-check it with the peer away and back once first, mutating to the old behaviour, not a bare return.
- A count test built on `history::world_of` turns the memo debug comparisons off before counting (`idle::exact`).

**Counting**
- `costs::take` counts per thread: in a `LocalPeer` test it mixes every peer's work; scope the window to one peer's applies.
- `testenv::Cpu` counts only threads `testenv` ran: count other threads' work with `tools/icount`.
- A count taken inside a `measured` closure (`osis_base::costs::take`) zeroes what the closure is measured by: every n/10n check then passes at 0.
- A new `osis_base::costs` count shows in every test comparing all spans (osis `making::`, engine `closure::`): a counter one scale test reads goes outside the shared table (as `osis_store::bytes_handed`).
- A memo's `try_settle` returns `None` for an unchanged answer: count `Some` returns against total runs. A memo read before its key is inserted computes again at the next look: look once before counting.
- An n/10n count through a real world needs an event that moves inputs alone (most also bring new keys).
- A cost test varying only what the node closure holds cannot see a pass judging every held thing when the filter is uncounted: count what is due before filtering.
- `read: judged` counts twice per judgement. An env-gated dump inside a `Cutoff` derivation also prints the debug comparison runs: read growth from `costs` counts.
- A count test with a tolerance passes with a whole term dropped: mutate each term, and make the check exact where every term can be written down.

**Models and generators**
- roles-model `family_run(stride)`: a stride sharing a factor with a dimension's size fixes that dimension; strides of mixed-radix families are coprime with every radix.
- roles-model: probe a failing world by printing it and its reference, never by shrinking it first. Two readings of one world go in one process with a thread-local switch (an env var cannot switch per call across `on_every_core` threads).
- roles-model `paths::World::lowers` counts every edge write below admin, a fresh grant of write included: it is not "a removal".
- held-model `gen::shuffle` does not reorder `Held::dots`, and `Dots::commit` takes the first range holding a dot: an order test over overlapping ranges shuffles `dots` itself.
- A generator may build states no encoder writes: before fixing a rule for one, check it decodes from bytes; a decoder test of such bytes hand-patches an encoding. `DeltaBuilder` `Add v` of a live value writes nothing.
- A loop over consecutive seeds with `rng(seed | 1)` makes seeds 2k and 2k+1 the same history.

**Oracles and isolation**
- A test meant to isolate one mechanism fails with that mechanism alone disabled: a test passing by either of two mechanisms isolates neither.
- An oracle choosing its subjects by an internal flag breaks across a refactor of that index: choose by a stable fact.
- A differential's exclusion is counted over every world it covers and printed beside the failures (applied to failing worlds only, one once excused 38% of worlds unseen).
- A differential mapping model flags to wire shapes never emits a shape its mapping lacks: a shape rule needs a test that builds the wire input directly.
- A test whose comment claims a state asserts or tallies it. The forensic `recoverable` sees nothing of a pending copy outside the node closure: assert the value recoverable before the step that should remove it.
- A count from a process-wide counter (`memo::writes`) moves with other tests' threads: count per thread.
- Each failure kind of a property panics with its own text, so a known_failures pattern for one does not hide the other.
- A shrunk script (`OSIS_SYNC_SHRINK=1`) of a debug-check failure may shrink to another panic: compare the panic first.
- A `rejects` case asserting only the error class passes on any earlier rejection: print the error once when writing one.

**Other**
- A redb store's clean close commits its allocator state; `std::mem::forget` of a store as a power cut fails the reopen (the file lock stays held).
- osis-perm's `paths/hand*.rs` mirror roles-model's hand worlds by name: grep `core/` before renaming a model test. A helper swapped for a "superset" one can pass the default tests and fail a `_plain` property: run the crate's `_plain` properties after a helper change.
- Ephemeral bodies do not survive a restart: a restart case of an ephemeral rule needs a durable aspect. A scale test's small size must page as its large size does.
