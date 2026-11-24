# dating-index
> Summary: Workflow notes from following bodies that leave the held-writes index.

- A facet read both inside and outside `memo::accounted` counts as unaccounted, silently: the amend was rejected on every drop until a probe printed the rejected dep's table (`Table::cause`). A debug message naming the rejected read would have saved a round.
