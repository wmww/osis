# prose-sync-spec
- Tests cite spec rules as `§N (anchor)` with free-text anchors; spec_map checks only the RULES table, so nothing says which bullet a citation means. 122 of the cited sync/wire anchors match no text in their section, so moving or merging a bullet can silently orphan citations. A check that each cited anchor names a bold label in its section would make spec moves safe.
- Section numbers are load-bearing for those citations, so a prose pass cannot renumber or move rules across sections without touching code on another branch.
