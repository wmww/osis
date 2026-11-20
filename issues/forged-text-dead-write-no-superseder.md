# A forged text or list history fails a tick: "a dead write no held body supersedes"
> Summary: osis-engine's `retention::tests_forged::forged_copies_fail_no_node_large` fails on some seeds (hostile single-record text and list writes, `crdt_model::gen::hostile`, forged as snapshots by writer 1): peer 0's tick returns `Corrupt("a dead write no held body supersedes")` from `bounds::judge_replaced_at`, a local error from a writer's bytes (spec/commits.md §4). Fails on main's binary; cause not read.
> Priority: normal
> Tags: security, retention, crdt

**Seen**: a merge gate (first-superseding), seed 513663451504 of 30, also on main's binary (51d7e2b63). Replay: `OSIS_FORGED_START=513663451504 OSIS_FORGED_SEEDS=1 cargo test -p osis-engine --lib -- --ignored --exact retention::tests_forged::forged_copies_fail_no_node_large`.

**Matters because** a peer whose tick fails on a forged snapshot stops dating its aspect (and any tick work after it): any writer of a thing can wedge a reader's retention with bytes the decoders accept. The judge finds a write of the part dead (`deaths`: wins in the part, not once joined into the state) that no held write supersedes (`HeldWrites::holds`, `first_superseding`): either `deaths` reads a death the held writes do not hold (a sequence position, flag or creation case `Fragment::held_writes` leaves out), or the state holds what no held body does. Read it against spec/crdt.md §4.8 (Which write, When) first; then a seed-free hand test.
