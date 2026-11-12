# strip-cost
- Reverting a temporary probe edit with `git checkout <file>` also reverted the uncommitted fix in that file; make a wip commit before probing a file you changed.
- Review gate: `port_clients::remove_client_revokes` timed out (60 s `recv_timeout` on the removal's write event) at load 25, passes alone in 1.2 s; the listener race noted in undo-followups is not fully gone.
