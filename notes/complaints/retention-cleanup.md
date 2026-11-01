# retention-cleanup
> Summary: Footguns met in the retention/apply simplification pass.

- The store-contents differential's throwaway patch touches osis-store and the index tag, so every switch between patched and unpatched builds rebuilds most of the tree: at nice 19 on a box at load 60 each tier-1 run took about 20 min. Batch all edits, then one patched run per side.
- Reordering store writes inside one transaction (even same keys, same values) may change the write trace: the pager lays B-tree pages out by insertion order. A refactor that dedups or sorts a list of `put_local`s (e.g. `mark_lost_due` over rosters) is not byte-preserving; keep the order.
- Tier 1 under `OSIS_DUMP_FILE` gave about 12,400 store lines here, not the 57,000 notes/testing.md says (tier 1 shrank since).
