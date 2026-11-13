# The group index holds and recomputes whole groups in memory
> Summary: `groups.0`'s index (`engine/groups.rs` `Groups`) keeps every group's whole definition in memory, and each membership change costs O(the group and the groups above it) in CPU: `Groups::apply` clones and diffs the definition, unlists and relists each closure above it (`reach`, a new `Arc` closure), and `groups::refresh` clones the definition. Page loads are O(change) (`scale::group_change_is_flat`); this is the in-memory side. spec/requirements.md Scale (millions of items per group, a change costs O(change), no whole value needed in memory) is not met for huge groups.
> Priority: low
> Tags: engine, performance

- At open every group's definition is read whole (`set_def`, then one derive): O(all memberships) memory and startup.
- Per change: one add to a million-item group copies and diffs a million tids, and rebuilds the closure of it and every group above it; `of` updates are O(closure) too.
- Fix direction: keep definitions in the store (the paged state already has a value index) and closures as derived incremental sets (add/remove one member updates `of` for the groups above, ref-counted through subgroups), so a change touches O(change × groups above). Count it in a scale test at n and 10n (CPU work counted, e.g. tids visited).
