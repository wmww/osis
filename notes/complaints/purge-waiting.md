# purge-waiting
- The issue's case 2 named two tests deleted in an earlier commit (expiry-6); issues citing tests by name go stale silently. Grep the test name before trusting an issue's account of what guards what.
- `reopen_undropped`'s refetch of missing slots at start is also how a destroyed actor's record comes back: filtering out slots whose record is away broke two destruction tests (now commented there).
