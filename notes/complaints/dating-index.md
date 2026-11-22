# dating-index
> Summary: Workflow notes from following bodies that leave the held-writes index.

- The brief's "hand the amend its old value" was not enough for an in-place edit: the held writes sat in a `Memo` and a `Cutoff` row and its `Effects`, three copies of one `Arc`; the amend had to move into `Cutoff` before any edit could skip the copy.
- A facet read both inside and outside `memo::accounted` counts as unaccounted, silently: the amend was rejected on every drop until a probe printed the rejected dep's table (`Table::cause`). A debug message naming the rejected read would have saved a round.
- A cost counter for a copy (`costs::count`) broke `copies::a_copied_world_goes_on_as_the_original`: a world copy shares the original's `Arc`s, so only the original copies. Counters that differ by sharing belong on `Core` (`held_writes_copied`), not in `costs`.
