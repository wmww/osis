# link-leave
> Summary: Workflow mishaps on the link-leave branch.

- The sim `World` exposes no host entry listing and `osis` hides the engine's commit index, so the first repro had to be rewritten at the node level (`Net`) to see which blobs reached the host: a `World` probe of host entries would have saved an hour.
- `Net.hide_blobs` left a `Push` with no events, which the node rejects as malformed (a push carries at least one); fixed in the harness (an emptied push is dropped). A push dropped this way is never re-announced, so a hidden blob must reach the node another way (`package`/`ingest`) for the test's recovery half.
- Depth0MC.tla already had `vActs`/`vMem`/... instance names; a new instance's names clashed twice before I read the whole file.
- `cargo test -p osis-node --test it` rebuilds in 1.5-3.5 min at load 30-50 after a one-line edit in osis-node's lib; probing by `eprintln!` cost about ten such rebuilds.
- Review: the worker's diff replaced an unrelated test (`rotation_wrapped_under_epoch_learned_later_is_read_spec_sync_5`, still cited from core/test/sim) in place, unmentioned; git showed it as an edit of that test. Restored.
- Review: `run.sh small D0_` took 29 min at one worker (D0_rm_possess0 15 min, D0_fork_out 7 min), not the "under ~2 min each" the script header says.
