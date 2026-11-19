# Complaints: gimbal-sync-unit-design
> Summary: What slowed a design study that had to count sync costs: no kept n-and-10n test over real sync for many shared sync IDs, trace lines cut before the field that grew, and no per-direction message census.

- No kept test counts an idle reconnect, a commit or a first sync over real worlds at n and 10n shared sync IDs (`opens::a_reconnect_costs_the_same_at_n_and_10n` varies the sync IDs not shared), so the growth in notes/sync-unit-design.md §8 was found only by a throwaway test.
- `OSIS_SYNC_TRACE` cuts a line at about 430 characters: the Pull whose `joins` list was the growth showed the same length at both sizes, and only `net.between` told them apart.
- `net.between` gives bytes per direction but no count per message kind; a census of frames by kind and size per pair would have named the join list at once.
- `osis_base::costs` counts are per thread, not per node: in a three-node world a count cannot be attributed to the maker, the reader or the store.
