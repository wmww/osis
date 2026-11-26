# Memory per held commit is 33 times what is stored, most of it memos following every commit
> Summary: A two-node sync world keeps 93 KB of live heap per small commit (both nodes) while both disks gain 2.85 KB, linear in commits held: about 55 KB the memos following every held commit for its life (dependency lists, memo entries repeating them, index entries, values), 18.5 KB caches bounded at 16 MB each, 12 KB engine per-commit structures. Attribution and the changes: notes/slim-design.md H.
> Priority: normal
> Tags: engine, sync, performance

Measured with `tools/memprof` over sync `memory::memory_per_commit_probe` at `MEM_N=50` and `500`, `--report A B --per 450`. Left to build, by bytes (slim-design H, Change):
- `Engine::sync_bodies` (a `Memo`) and the per-body metas memo as cutoffs, so the sync `Read`'s `Effects` over them reads one stamped row per key, not the ~45 reads each derivation makes, recorded again: about 20 KB a commit.
- `memo::Dep` is 56 B (`Option<u64>` key and part); every dependency list pays it per read: about 7 KB a commit at 40 B.
- perm's delta facts per content write (`content::set`) live in the engine's `Timeline`, which is over `MemStore`, though content.rs says the engine backs the store with its index: 4.1 KB a commit, in memory for the engine's life.
- The memos keep a reactive record (key, list, index entries) of every held commit, settled or not: a structure following coarser keys would make a settled commit cost its value alone. Design question, model first.

spec/requirements.md Scale asks for millions of things a node holds; at 46 KB a commit a node, a million commits is 46 GB.
