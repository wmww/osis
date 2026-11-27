# sheave-r8-vertex
> Summary: probing one node of a differential run is slow: every engine copy shares its tid and session.

A differential failure is checked on one copy of a world, but `holds_on` plays several (orders, references), and every copy of node i shares its tid and `Core::session`, so an `eprintln!` probe cannot tell the checked engine's lines from the others' (heap addresses move as worlds are cloned). Cost: most of an hour on the redeemer case. Would help: a per-engine-copy id (or the world/order index) the harness sets and probes can print.
