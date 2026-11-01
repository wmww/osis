# rotation-livelock
- The 6-peer `lacking_write` setup costs about 7 s and a settle about 13 s per seed at load 20 (one `sync_all` about 1 s): seed ranges of it are minutes, so tier 1 keeps two seeds.
- A first fix (rotate every forked role) hung tier 1 in `osis` `sync::used_link_with_sharer_offline_spec_permissions_9` with no timeout: libtest only prints "running for over 60 seconds". Running the one test under `timeout 60` with a trace eprintln found the concurrent-merge loop in a minute.
- Tier 1 at load 20: `osis` `runtime::keep_alive_rewrites_until_dropped` failed once ("4 writes": it counts keep-alive rewrites in a 250 ms wall-clock sleep), passed 3 of 3 alone; a wall-time assertion in tier 1.
