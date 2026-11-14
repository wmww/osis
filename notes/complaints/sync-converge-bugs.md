# sync-converge-bugs
> Summary: footguns met fixing the differential's leftovers and the walk-reopen sim.

- No trace facility in the sync harness: finding both causes took ad-hoc `eprintln!` in pull, opens and the harness's `deliver` (node per input). A `World::trace`-gated per-node event log of opens (open/close/test) and pulls (fetched, opened, not opened) would have cut this to minutes.
- The scripted opens tests built their own `store()` credentials, which had the step the product's `node_creds` lacked: the rule tests passed on a model, not the product. Fakes should be built by the product's constructor wherever one exists.
- osis-engine's `order::kill_and_purge_in_one_commit_keeps_leftover_spec_commits_5` and `scale::purge_rejudge_is_linear_in_requests_spec_permissions_6` fail on the sync-rebuild tip (1094cf3d1); this branch does not touch the engine.
- The accept-later reproducer showed a kept-unread S with no head answering "not in the sync set" to opens (`node_creds` returned None): absence of credentials and absence of S looked the same, so its `changed_at` never moved. Prefer `Some(empty)` over `None` when the thing is held with nothing to show.
