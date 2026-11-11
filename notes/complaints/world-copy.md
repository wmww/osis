# world-copy
- osis-node's `Net` is not `Send` only because `Tamper` closures capture `Rc<Cell>`s in 28 tests: the world cache keeps a `Parts` twin without them. Making `Tamper: Send` would drop the twin but means editing those tests.
- A single `--exact` icount of a cached-setup test cannot show the gain (it builds the world and pays one copy): compare a module or the whole binary.
- `Net::new()` with the same literal prelude was repeated about 250 times across 39 files; a converter script was quicker than hand edits (scratch, not committed).
