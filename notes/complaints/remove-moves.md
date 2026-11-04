# remove-moves
> Summary: Footguns met removing moves (imports, resolution, move_thing).

- Renumbering a spec section (permissions §8/§9 to §7/§8) touches 250 citations in 75 files, many as bare `§N` resolved by the comment block or the file's `//!` header (spec_map's rule). A throwaway script following that rule did it; it found three pre-existing mis-cites (bare `§7`/`§8` meaning crdt.md under a permissions header) that would have been renumbered wrongly. tools/spec_map.py's RULES section numbers need the same edit by hand (`--gaps` says so).
- Port method numbers are hardcoded in raw-protocol tests (`Raw::call(tok, 62, ..)`, `const WRITE: u64 = 11`): renumbering the method table broke them; grep for literal numbers after any table change.
- Deleting test functions by script leaves double blank lines and orphan helpers; the test build's dead-code and unused-import warnings find the helpers, a diff scan for blank-removed-blank hunks the blank lines.
- Removing a resolve-style wrapper (`self.resolved(t)` -> `t`) leaves `let t = tid;` aliases and `tid: tid` fields; clippy finds the second, not the first.
- Review: a single order seed that fails runs its shrink for about 8 minutes inside the oracle (purge_large 9160006): a 60-seed run went from 70 s to 980 s with no hint until it ended. Pinning the shrunk history as a `check(..)` probe test and `tools/bin-at REV --patch` answered "on main too?" in 2 s per side.
