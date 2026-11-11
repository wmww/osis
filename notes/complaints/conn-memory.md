# conn-memory
- The p2p NAT-model tests (`MemUdp`) carry `MemConn`, not quinn: QUIC flow-control windows cannot be observed in a default test, only by hand on loopback. A first try at a default window test looped without yielding and took 60 GB of RAM before the kill.
- A one-off background `cargo test` that writes to a scratch dir made in a separate, parallel Bash call can start before the dir exists: create the dir in the same command.
