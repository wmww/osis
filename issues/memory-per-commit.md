# Memory per held commit is 20 times what is stored, most of it followers and caches of every held commit
> Summary: A two-node sync world keeps 60.2 KB of live heap per small commit (both nodes) while both disks gain 2.85 KB, linear in commits held: about 19.3 KB the followers of every held commit for its life (keys, about 46 reads a commit a node, rows), 18.5 KB caches bounded at 16 MB each, 12 KB engine per-commit structures. Attribution and the changes: notes/slim-design.md H.
> Priority: normal
> Tags: engine, sync, performance

Measured with `tools/memprof` over sync `memory::memory_per_commit_probe` at `MEM_N=50` and `500`, `--report A B --per 450`; the reads held per commit are counted by `memory::a_held_commit_keeps_the_reads_of_its_own_facts` (46 a node; 120 when each per-thing derivation's reads are copied into every commit's rows). Left (slim-design H, Change):
- The followers keep a reactive record of every held commit, settled or not: about 8 followed keys a commit a node (sync read's `bodies`, `judged`, `local`, blob lists; the engine's `sync_bodies`, `sync_body_rows`, `read_facts`, `held_fates`), each with its slot, key and value (about 5.5 KB a commit, both nodes), its reads (`Dep` and index entry, about 100 B a read: 9.4 KB) and its row (2.5 KB). The reads are the commit's own facts, so what is left is the per-key record itself: memory in what is live or changing, not in what is held, needs settled commits followed by coarser keys. Design question, model first.
- perm's delta facts per content write (`MemStore`, 4.1 KB): out of memory only through a store-read `paths::Store`, the engine's first index read on demand (notes/perm-paths.md, The delta-facts seam).

spec/requirements.md Scale asks for millions of things a node holds; at 30 KB a commit a node, a million commits is 30 GB.
