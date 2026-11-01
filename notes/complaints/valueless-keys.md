# valueless-keys complaints
> Summary: Footguns met fixing the order-27039 key-erased copies.

- `--ignored --exact dbg_x` without the `order::` module prefix ran 0 tests and passed; always check `1 passed`.
- The issue guessed the expected state (key-erased record alone) from the spec's loose "held value-less"; the expiring put was not in the held set at all, so the real fault was an invalid snapshot's leftover copies. Dumping the state after each ingest (setup + chosen packs) found it in minutes; check which commits a shrunk repro actually holds before reasoning from the issue text.
- Review: a throwaway from-held probe (`rebuilt` without the current state, compared with the state for every aspect with no drop other than as covered, after every order of the order oracle) caught the pre-fix 27039 bug at once and held over 33k orders after it; worth keeping in mind as a cheap differential for "state = join of held" changes.
