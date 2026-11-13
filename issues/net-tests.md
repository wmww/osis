# Networking tests that can fail: leftovers
> Summary: the networking test harness is built (notes/test-sim.md, Reachability model and API world sections: sim peer links, in-process `peer://` and LAN over the nat.rs model, checks over peers, each open no-server audit row as an ignored `repro_*` test its job un-ignores). Left: an end-to-end repro of audit row 4, and real-socket tests beyond localhost.
> Priority: low
> Tags: tests, sim, transport

- Row 4 (issues/no-server-audit.md) has no repro end to end.
- Not in the default tests: row 32 (a real port's bind: by hand), Android, real broadcast reach (row 31).
- (design) Real sockets beyond localhost. Proposed: one by-hand setup in unprivileged network namespaces (`unshare -rn`, veth and bridges) for broadcast across a bridge, routed meshes and client isolation; no multi-machine test in any gate; phones by hand.

Every networking job lands with default tests over this harness, never over `InProcess`'s find-anyone-by-key. Harness words (`World::add_host`, `NetHost`) are renamed with issues/net-rename.md.
