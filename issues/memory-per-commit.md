# Memory per held commit is unmeasured and looks large
> Summary: A two-node sync world's resident set grows about 120 KB per small commit (both nodes, steady over 4 rounds of 100) while both nodes' disks grow 3 KB: memory 40 times what is stored, linear in commits held. Not attributed: the test backend, memos, debug checks or the engine's per-commit `Meta`, header bytes and views. Count it before slimming memory (notes/slim-design.md, Memory).
> Priority: normal
> Tags: engine, sync, performance

Seen by a throwaway probe (the sync-harness world of notes/thing-cost.md Survey): `/proc/self/statm` around 100 one-value commits on one dependent of A by node 0, node 1 its account's second node, each `run` and one second apart, in the test profile: 144, 116, 131, 103 KB per commit in four rounds (66 MB to 100 MB), disks (`disk_use`, rows and blobs) about 3.05 KB per commit. 3,000 dependents made in 300-thing commits grew it about 290 KB per thing (high-water of a big commit's apply, or retained: not told apart).

What is known to stay per held commit (notes/engine-store.md Headers): a `Meta` with its `View` (about 120 B an aspect) and its decoded header, entries in `by_aspect`, `ranges`, `by_thing`, `by_actor`, `commit_blobs`, `blob_parts`; per thing `Held::created` and `mint_admin_of`. None of that reaches 60 KB a commit, so something else grows: the memory backend (`osis_store::memory`, its live and durable copies), the memo system's stamps or caches, the harness (`Net`, history), or a debug check's state.

Method: a counting global allocator in a by-hand test binary (live bytes after each commit at n and 10n commits, by node), or dhat; then each live set by owner. A per-commit cost above the stored bytes is a defect (notes/thing-cost.md principle); spec/requirements.md Scale asks for millions of things a node holds.
