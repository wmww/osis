# double-import
- Load hit 150 from other agents' oracles: a one-test incremental build took 14 min (normally 20 s).
- A test passing captures its eprintln: debug output needs `--nocapture`, cost one extra 14-min round trip.
- `LocalPeer::sync_all` after a move ships the imports everywhere; for order tests deliver by hand from the start.
