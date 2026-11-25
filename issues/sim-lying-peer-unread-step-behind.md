# A lying store peer keeps a thing unread a step behind its readers
> Summary: `sims::a_peer_refusing_role_entries_plain` fails on some seeds: node 2 (the lying peer, Forget or Withhold) keeps thing 0 unread at a 1-deep step while its readers' head is 2 deep.
> Priority: normal
> Tags: sync, tests

Replay: `OSIS_SYNC_START=749306945350 OSIS_SYNC_SEEDS=1 cargo test -p osis-sync --test it -- --ignored --exact sims::a_peer_refusing_role_entries_plain` (also 749306945351; seeds move with commit bytes). Panics at the history check that a node keeping a thing unread stands at its readers' recorded head (`core/sync/tests/it/harness/history.rs`, "keeps thing 0 unread at step ... (1 deep), its readers' head is 2 deep"): after `Remove(0, 0, 1), Rotate(0, 0), Run, Grant(0, 0, 1, Writes)`, the step for the rotation never reaches node 2's store, or the check reads a peer whose lie (forgetting or withholding its log) is excused elsewhere. Unexamined which.
