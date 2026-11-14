# `serve --listen` replaces the dialable listener; a relisten on the same port races
> Summary: `Osis::listen(urls)` replaces every URL listener, the direct-sync `peer://` listener included, while the account's dial list keeps advertising it; and a listen that restarts a listener on the port it held fails `address in use` (the old listener's task is aborted, not yet dropped), which `rotate_peer_address` hits.
> Priority: normal
> Tags: osis, transport, sync

- Seen at the dogfood rehearsal: a paired node dialed the other's published `peer://` address, which `serve --listen quic://...` had closed; only the dial rotation (notes/sync-driver.md Dials) reached the configured address, a dial timeout plus `REDIAL_MS` later.
- `core/osis/src/net.rs` `drive`: a socket-only listen is added beside the listeners up for this reason; a URL or key change still stops all and relistens.
- Fix: keep the dialable listener apart from `listen`'s URLs (main kept it so), and close listeners synchronously (keep their close handles in `TransportLinks`) before a relisten.
