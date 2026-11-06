# A node removing its actor's admin edge writes a self-removal perm voids
> Summary: engine `validity::self_removal` calls lowering holder M's edge a self-removal when the author's admin on the target comes only through M's edge; perm's `walk::judge` (and spec/permissions.md §2 "through X included") counts that authority, so it judges the write explicit, finds no frontier, treats it as a finalize of an unended edge and applies nothing.
> Tags: perm, engine, permissions

Repro (any build): account A (node n) holds an admin edge on T; n demotes A's edge on T (`Engine::demote`, holder A). The commit is written with no frontier and no rotation; `judged_valid` is false at n and A stays in T's roster everywhere. Same for a first admin's record edge removed by one of the first admin's nodes.

Pick one rule and use it in both places: either authority through the lowered edge counts (engine stops calling it a self-removal: an explicit demotion with frontier and rotation), or it does not (perm patches the edge out as the engine does, and the spec drops "through X included"). Found while building issues/owner-to-first-admin.md Stage A; its refused-case test uses a node as first admin (holder = author, a true self-removal) to avoid this.
