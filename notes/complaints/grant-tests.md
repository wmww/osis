# grant-tests
> Summary: mishaps met while moving node tests from bare edge writes to grants.

- `tools/icount` printed `INSTR unavailable` (no perf counters for this user here), so the before/after evidence is CPU-s from `/usr/bin/time`, which load skews.
- The issue's count (about 320 calls) mixed two helpers: about 250 are `LocalPeer` engine tests (`common::set_edge`), where no sync pass runs and the repair path the issue measured does not exist. Only the ~70 `Net` calls were in scope.
