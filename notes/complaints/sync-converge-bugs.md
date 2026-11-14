# sync-converge-bugs
> Summary: footguns met fixing the differential's leftovers and the walk-reopen sim.

- No trace facility in the sync harness: finding both causes took ad-hoc `eprintln!` in pull, opens and the harness's `deliver` (node per input). A `World::trace`-gated per-node event log of opens (open/close/test) and pulls (fetched, opened, not opened) would have cut this to minutes.
- The scripted opens tests built their own `store()` credentials, which had the step the product's `node_creds` lacked: the rule tests passed on a model, not the product. Fakes should be built by the product's constructor wherever one exists.
- osis-engine's `order::kill_and_purge_in_one_commit_keeps_leftover_spec_commits_5` and `scale::purge_rejudge_is_linear_in_requests_spec_permissions_6` fail on the sync-rebuild tips 1094cf3d1 and 795b73e82; this branch does not touch the engine.
- The accept-later reproducer showed a kept-unread S with no head answering "not in the sync set" to opens (`node_creds` returned None): absence of credentials and absence of S looked the same, so its `changed_at` never moved. Prefer `Some(empty)` over `None` when the thing is held with nothing to show.
- The unopened-entries bug was fixed twice in parallel (here in streams, in the dial review in the store); this branch dropped its own at rebase. A coordinator note when a second agent starts on a known issue would have saved the duplicate.
- Histories do not replay from their seed: replays of a failing full-size seed fail 2 of 8 or 5 of 6 times (HashMap/HashSet iteration in streams, store memory and opens is a likely source), so shrinking such a seed is unreliable.
- (review) The replay nondeterminism was one `HashMap` in read's settle (its acts, so its seals' rng draws, ran in hash order). The harness had a replay test, but `Seen` recorded only byte lengths, so it could not see a re-encrypted body; digesting the bytes found it in one run. The trace should carry content wherever a check compares it.
- (review) A `git checkout <file>` to undo a probe line also undid a real edit in that file: probe in a scratch copy, or revert by hand.
- (review) netopen at one worker went from about 3 to about 5 minutes (load 16) with the walk in the model; run.sh's "each module under 3 min" no longer holds for it.
