# sync-audit
- Making two writers place separate encryptions of one body took three tries: writers wait `relay_delay` (up to `SETTLE_MS`) before uploading another's commit, and a reconnect races, so only `held_to` plus an advance past the relay wait gets both encryptions up.
- Review: local main lagged origin/main (devbox's not-admitted was only on origin); rebased onto origin/main. A test that keeps one node from hearing a single entry needed a new harness knob (`Net::hide_blobs`): `hold_blobs` holds whole messages, and the purge commit travels in the same Push as its rewrite.
- Review gate took 1081 s at load 66 (tier 1 alone about 9 min); quiet gates run 2-3 min.
