# keel-own-release
- An engine-only storage count shows covered own bodies never dropping: durable covered bodies drop in sync's driver (`Engine::compactions` writes the snapshot, node-sync drops), so a storage count test belongs in sync's harness. Cost a detour.
- `flows::thing_of` under an account holds the thing from D (`hold_where_it_lives`), so `unhold(Strong(t))` from the node root was a no-op and the old `a_dependent_keeps_a_destroyed_things_record` passed its middle checks without releasing anything. Check `closure_holds` after a release in tests.
- Started a test run with a trailing `&` instead of `run_in_background`: no task ID to wait on. Use the tool flag.
