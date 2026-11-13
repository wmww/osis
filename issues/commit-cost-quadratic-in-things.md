# Writing and applying a commit costs quadratic in its things
> Summary: A commit of one change on each of n things costs about n² to write and to apply (test profile, load 20: 500 things 0.17 s, 1 000 0.66 s, 2 000 2.4-2.8 s, each side), so the requirements floor test takes about 8 s.
> Priority: normal
> Tags: engine, performance

Repro: `commits::two_thousand_changes_on_as_many_things_spec_requirements_decentralization` (osis), its `N` lowered; the `Write::commit` and the receiver's `ingest` each grow fourfold per doubling. The commit's blob is 188 KB at 2 000 things: the cost is per-thing work that walks the whole commit, not bytes.

A perf sample of the whole test (`it` test profile) puts most time in `BTreeMap<Tid, Role>` iteration, insert and drop (a roles map built or walked per thing), `Core::index_own` with a `(Tid, Ak, Tid) -> {(Ts, CommitId)}` journal set, `perm::Timeline::first_held`, `retention::history::of` and `undo::touch::Touches::note`. Not traced to a caller yet. Fix by design (count the work at n and 10n in the test, notes/coordination.md Check scaling), then shrink the floor test's runtime with it.
