# A read grant's first death costs 24 KB of held-writes rows: over the thing_cost budget
> Summary: an aspect keeps held-writes rows from its first death (notes/engine-retention-dating.md Rows). A read grant to another account supersedes writes of the thing's `secrets.0`, so both sides build its held writes: 11 pages, 24,067 B. `thing_cost::what_a_reader_costs` reads 55,435 B at the reader against a budget of 31,500 (31,368 with no held-writes rows: 132 B of headroom). No encoding of the rows fits that headroom; the budget or the rule has to move.
> Priority: normal
> Tags: engine, performance, tess-call

Traced (the rows of `secrets.0` at its build in that test, before paging): 50 writes held by 2 bodies.

| rows | count | key bytes | value bytes |
|---|---|---|---|
| a write (`W`) | 50 | 6,682 | 2,932 |
| a position's top (`T`) | 63 | 5,230 | 3,150 |
| a step under a position (`S`) | 62 | 8,312 | 870 |
| a body's own writes (`L`) | 2 | 84 | 6,280 |
| a body (`N`), its deaths (`D`) | 3 | 110 | 12 |

33.7 KB of rows, 24.1 KB in pages with shared key prefixes left out: about 480 B a write. A key is a 16-byte hash per step of the path (so path order holds and a key's length is bounded per step), a stamp is up to 58 B (a 31-byte session source), a body's own writes repeat each path.

What could shrink it, none built: sources and commit IDs as numbers from a table per page (stamps to about 12 B, holders to 3 B); a body's own writes as its rows' keys; tops kept only for positions with positions below them. Perhaps 80-100 B a write, 4-5 KB here: still far over 132 B.

So the choice is between:
- the reader budget taking the rows of an aspect whose write died (and the granter's: 42.4 KB of rows there, no budget asserted);
- held writes for role aspects read from the bodies instead of kept (a second rule by aspect class or by size: the small bound this replaced);
- a rule under which a role aspect's superseded writes need no dating.

Not at issue any more: `scale::roster_removal_is_linear` is green (one more `secrets.0` entry writes 23.1 KB at 20 holders, 29.7 KB at 200) and a thing's creation costs no row (14,904 B, as before).
