# client-revoke-flake
- The cause took one eprintln of every listener event: the removal's events came as `commit: None` (the write's own sync step had compacted `clients^.0` before the dispatcher read them). Two earlier gate reviews blamed "the listener race" and patched around it without printing the events.
- 16 copies pinned to 2 cores x 10 rounds reproduced it in 2 min (4 of 160); each failure costs the 60 s `recv_timeout`.
