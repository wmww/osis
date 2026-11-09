# net-connect-lan-base
> Summary: Mishaps on the LAN-in-every-build branch.

- A `cat > file` left at the head of an edit command (no heredoc) waited on stdin until the 120 s tool limit; nothing else in the command ran.
- One tier-1 run had 5 tests on real directory stores fail at `create().unwrap()` (`ephemeral::restart_forgets...`, `port::listen_socket_names...`, `serving::own_runtime_close...`, `serving::stop_serving...`, `runtime::own_runtime_reopen...`); the same tree passed in full right after. /tmp is a 31 GB tmpfs that was 25 GB full. Not traced: a filtered log kept no error text.
