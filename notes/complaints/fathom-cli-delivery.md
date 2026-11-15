# fathom-cli-delivery
- Every CLI invocation that opens sync costs about 1 s wall in debug (a lone local `get` on a dir store about 0.9 s), so CLI tests whose commands now wait (grant, link make, card show) add a second each; `links/cards on a store with no peer` was trimmed to its one uncovered command.
- `SyncScope::Deliveries` (and `All`) never ended on a node owing a delivery no other node could take (a grant to an own group no other node holds): found only by un-ignoring the CLI test; no API test granted to an own group.
