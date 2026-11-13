# cleanup-transport
- The pub(crate) probe's "never used" list mostly cascades (a removed caller makes its callees look dead); the useful finds came from grepping each name across the workspace (`Address::scheme`, `MemConn::remote`, `Transport::dial_as` used only by the crate's own tests).
- tools/spec_map.py clause tags still say "host" (`spec/sync.md §10 (host key check)`): a test comment reworded to dialer/listener must keep the old tag or the clause shows as uncited.
- Removing a dead trait method touched one line each in core/node (driver, hub_loop test) despite the brief's "avoid core/node"; no overlap with net-6b's hunks.
