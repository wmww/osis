# own-demotion
- The property's oracle and a neighbour's both read an internal flag (`HeldKeyset::demotes`) to pick "the removal's keysets"; a hand test wanting to run on the code before and after a fix had to pick them by `since.commit` instead. Oracles picking by a stable fact (which commit wrote the keyset) survive refactors of the index.
- `rotation::tests_carried` builds take ~2-3 min per edit cycle in a warm worktree; most of it is linking the engine lib test binary.
