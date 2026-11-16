# keel-refgraph-tests1
- The making rule broke about 700 engine, 150 osis and 17 doctest setups, not "far fewer": `new_thing`, `create_with_admin` and osis `create()` all made unheld things. One helper change (`Engine::new_thing` holds where it lives) fixed most engine ones; osis needed `internals::Held`.
- osis `tracking::dispatch_counts_matched_listeners_at_n_and_10n` ran for over 9 minutes once its 440 things were held (a write costs O(held sync IDs), issues/reference-graph.md Status): a hang looks like a slow test; `has been running for over 60 seconds` was the only sign.
- Telling new failures from main's needed a second worktree on origin/main (osis-sync, osis-cli and osis-chat each have failures on main not in tools/known_failures.txt).
