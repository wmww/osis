# crdt-valid-order
- The first osis-engine + osis-node test build took 11 min at load 28 (other agents' builds); nothing to fix here, but a worker should expect it and start it in the background early.
- `seq_unmerge_spec_4_6`'s random seeds change per run, so an in-place un-merge gap (a creation that had pushed another's position write out of the top-2) showed only on the third clean run. Run osis-crdt a few times after touching `remove_dots` or `dots_in`.
- Review: the first gate run failed on `osis-chat thin::own_serving_node_takes_a_chat_spec_data_model_9` at load 20+ (issues/chat-own-serving-flaky.md); it passed three reruns alone. A known flake costing a full gate rerun.
