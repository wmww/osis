# Tests set up access with a bare edge write
> Summary: Many tests grant access with `set_edge` (an edge write with no secrets of its own for the thing), which runs the own-secrets repair path on every node (the race sync-pass bounded with a settle wait) instead of a proper grant (`Engine::grant`, secrets in the same step). Tests that mean to set up access should grant; only tests of the repair path keep `set_edge`. About 323 calls in 30 test files.
> Priority: low
> Tags: tests, node

Found by sync-pass (Fathom's measurement: a bare edge write cost ~95 passes per node before the fix, 6-8 after; a grant costs 6). Sizing: `grep -rn "set_edge(" core/*/tests core/test`. Per caller: is the repair path what it tests? If not, switch to a grant helper.
