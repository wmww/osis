# undo-followups

- `tools/policy.py` is not executable (`Permission denied`); run it as `python3 tools/policy.py`.
- Review: the gate's NEW `port_clients::remove_client_revokes` was a listener race (`try_recv` after `drop(sub)`), flaky at load 26, unrelated to the branch; fixed in the test.
