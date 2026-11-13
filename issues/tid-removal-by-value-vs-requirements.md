# Removing a tid from a set drops adds the remover never saw
> Summary: spec/crdt.md §5.5 removes a tid from a set by value: the removal hides every add of it stamped before, received by the remover or not. spec/requirements.md (Data model) says "Removing from a collection drops only what the remover had seen", and notes/crdt.md records the observed-dot rule as Tess's. Needs her call, or a rule that keeps the requirement.
> Priority: normal
> Tags: crdt, engine, tess-call

Why it exists: a `delete` (or an undone creation) must unlist the thing alike whoever deletes, also where the deleting node holds a group's `group.0` add of it as a header only. Removal by value does that, and applies to every `set<tid>`, app aspects included: an add made concurrently on a node whose clock lags the remover's is lost.

A rule that keeps the requirement: the remover has seen the header of the part it lacks, and the header gives that part's source and counter range `[lo, hi)` per aspect (spec/commits.md). A removal of value `v` scoped to those dots (hides the elements of `v` whose dot is in the range) drops only adds the remover saw, by header or body; held adds keep their observed-dot tombstones. It keeps the "hidden, not pruned" state shape that makes joins lawful under forged copies. A part not seen at all stays concurrent, as the requirement says.

Question for Tess: keep the requirement (scoped removal above), or relax it for tids (one sentence: removing a tid from a set drops every add of it made before the removal)?
