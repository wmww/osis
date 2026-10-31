# Upload and Delete under a stale key still get the head
> Summary: a Status with code 9 carries the head (spec/wire.md §11.2), so an ex-writer or ex-admin whose key is among the head's 8 newest earlier keys learns the head ID and each new rotation by re-sending an old stamped entry or delete, until 8 distinct keys pass. Code 9 vs 1 also tells any holder of an older deposit, write or delete key whether fewer than 8 rotations have happened. Register and Deposit no longer leak this way. Low.
> Tags: security, proto, server

- `server.rs` Upload and Delete arms: `head` when any code is 9. The node uses it (`entry_status`, `delete_status` → `new_head`) only as a shortcut; an open connection learns heads by push.
- Fix direction: drop `head` from Status and let code 9 mean only "stale key", as Deposit now does; check the node still converges for uploads on a connection without the label opened. Whether code 9 itself should exist (vs 1) is the open half.
