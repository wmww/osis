# chain-projection
- The issue's 18 failures exist only on net-6b (main's osis harness never calls `accept_inbox`; flows seal with no chain), so reproducing meant building net-6b in the task worktree and bisecting chain classes with env-gated prints. A one-line note in the issue ("reproduce on net-6b") would have saved the first hour.
- Most of the time went to tracing which node-sync path a keeper's extra `keys.0` changed: there is no per-node event log in World runs; diagnostics are drained by `trace`.
- I ran `git stash` once by reflex in a probe one-liner; popped my own entry at once by explicit ref. The rule is easy to break inside a chained command.
