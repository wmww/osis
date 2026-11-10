# net-pull
- The node `Net` harness counted only host-link messages (`sent_kinds`); peer-link counts (`peer_kinds`, `peer_sent`) had to be added for counted peer tests.
- `export PATH=...` from the brief does not persist between Bash calls: `claudewait` was "unknown task" until exported again in the same call.
- `net.item(n, g, admin, ..)` with `admin` = the node's own actor makes a thing other readers cannot open: a stream smoke test looked broken for a while (use the group as admin).
