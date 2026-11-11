# roles-growth
> Summary: Footguns met while making edge writes reset only the holder's current entry.

- The issue said a grant resets every past entry; the code reset only state-live entries on a grant (`remove_edge`) and every seen entry only on removals (`removal`). Reading the code before the issue saved a wrong fix.
- The `roles.0` CRDT state is written and kept but nothing reads it (the roster is the timeline's). Easy to assume resets matter for reads; only a removal's resets matter (the waiting rule).
- Engine map fields (`Entry::reset`) are crate-private; counting resets in a node test needs `Map::entries()` via `Fragment::slot`, found by reading `validity::entries`.
