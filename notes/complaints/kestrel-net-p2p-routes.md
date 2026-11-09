# kestrel-net-p2p-routes
- A tokio test over a nat.rs net has two clocks (model steps, wall): `Net::run_on_tokio` compresses model time, so tests under it pick NATs with one stable route (relayed-to-direct switching only under `Sched`).
