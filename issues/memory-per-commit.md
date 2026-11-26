# Memory per held commit is 25 times what is stored, most of it memos following every commit
> Summary: A two-node sync world keeps 70.4 KB of live heap per small commit (both nodes) while both disks gain 2.85 KB, linear in commits held: about 30 KB the memos following every held commit for its life (dependency lists, index entries, values), 18.5 KB caches bounded at 16 MB each, 12 KB engine per-commit structures. Attribution and the changes: notes/slim-design.md H.
> Priority: normal
> Tags: engine, sync, performance

Measured with `tools/memprof` over sync `memory::memory_per_commit_probe` at `MEM_N=50` and `500`, `--report A B --per 450`. Left (slim-design H, Change):
- The memos keep a reactive record (key, list, index entries) of every held commit, settled or not: the `sync_bodies` and `read_facts` cutoffs alone are derivations of about 45 reads each, kept per commit (14 KB). A structure following coarser keys would make a settled commit cost its value alone. Design question, model first.
- perm's delta facts per content write (`MemStore`, 4.1 KB): out of memory only through a store-read `paths::Store`, the engine's first index read on demand (notes/perm-paths.md, The delta-facts seam).

spec/requirements.md Scale asks for millions of things a node holds; at 35 KB a commit a node, a million commits is 35 GB.
