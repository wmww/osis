# order-settled-seeds
- `OSIS_ORDER_SHRINK=1` on seed 38534 ran 5 min and left ~60 steps (the clocked order's split point moves with every dropped step, so most drops stop reproducing): the cause came from `OSIS_ORDER_DUMP`'s index differences plus a per-ingest probe of the one commit, not from the shrink.
- `LocalPeer`'s fetch stand-in (`Peer::wake`) and node-sync's (`reopen_undropped`, `redeliver`) are separate code with no shared test: the harness dropping a woken commit's carrier looked like an engine loss until node-sync's handling was read.
- The `tools/heavy` lock waited ~13 min behind another branch's gate for a 4 s seed replay.
