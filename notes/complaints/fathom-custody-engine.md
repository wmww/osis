# fathom-custody-engine
- `Engine::run` rolled back (an ingest trial) restores the store but not every in-memory map (`Core::accounts` kept a seed taken in the trial): custody keys off the store record to stay right. A trap for anything caching secrets in `Core`.
- Pairing becoming a rotation shifted every account test's base epoch (FIRST_EPOCH assumptions in tests_signing, tests_forks, flows): a `setup_head` helper and a seed hand-over test helper (`keep_seeds`) absorb it.
- osis-sync sibling tests depend on joiner-target (plain rotations revoking at outsiders); couldn't land green alone.
- Rebasing the 4 branch commits onto joiner-target conflicted per commit; squashing them on their old base first (`merge --squash`) made it one conflict pass.
- osis-sync failures after a design change are slow to diagnose: no per-node "why did it dial / refuse / re-seal" log; I added throwaway eprintlns each time (dial `Why`, store refusal reason, reseal candidates). A traced reason per act in `OSIS_SYNC_TRACE` would save hours.
