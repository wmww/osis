# net-pull
- The node `Net` harness counted only host-link messages (`sent_kinds`); peer-link counts (`peer_kinds`, `peer_sent`) had to be added for counted peer tests.
- `export PATH=...` from the brief does not persist between Bash calls: `claudewait` was "unknown task" until exported again in the same call.
- `net.item(n, g, admin, ..)` with `admin` = the node's own actor makes a thing other readers cannot open: a stream smoke test looked broken for a while (use the group as admin).
- (review) The randomized stream differential never paged (`REPLY_BUDGET` replies, `SCAN_ROWS` rows): join paging was reached by no test until a tamper hook shrank `max_reply` (`stream_differential_paged_spec_sync_10`). A first paged variant writing 120 items per new group took 266 s; register rewrites on one thing page as well in under a second.
