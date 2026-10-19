# A deposit at a second server is never promoted
> Summary: The sync state keeps one stamp per (label, blob), not per server: once a writer promoted a deposited entry at one server (`pass.rs` `promote` records the stamp), the same blob deposited at another server of the label is filtered out (`e.stamp.is_none()`) and stays deposited there for good, holding the deposit budget (spec/sync.md §5: a writer re-uploads stamped the deposited commits it verified).
> Tags: sync, node, tests

- Seen in the simulator: `osis_sim::replay("reader_relays", 1)` without its waiver (`sim.waivers` in `relays`): "server 1: deposited ... not promoted by writer node 0" (a reader's certificate deposited at both servers; the writer promoted it at s0 only).
- Fix (node-sync): promote per server: an entry present at a server unstamped there (the server's add carried no stamp) is promoted at that server, whatever the local stamp; or track the stamp state per (server, label, blob). The simulator waiver `WAIVE_PROMOTION` goes when this is fixed.
