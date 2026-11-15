# Relistening a QUIC listener set ends its connections and may find its port held
> Summary: `TransportLinks::listen` replacing a set drops its QUIC listeners, whose `Drop` calls `Endpoint::close`: every connection accepted there ends, and the UDP socket stays bound while their `QuicConn` handles live, so listening again at the set's own port (a key change, `Osis::listen` with the same URLs) can fail and leave the set closed.
> Priority: normal
> Tags: transport, sync

Found by reading (core/transport/src/quic.rs `QuicListener::drop`, core/sync/src/driver/links.rs `close_listeners`), not run. `a_listener_set_listens_again_at_its_own_port` relistens with no connection up, so it does not reach this. Cost: after a key change with live accepted QUIC connections the node may stop listening on that set (the error goes to the caller; nothing retries). Fix direction: relisten on the bound socket itself (rebind the endpoint's server config, `Endpoint::set_server_config` for a key change), or retry the listen once the old endpoint's connections are gone; either way the set's connections should end only when the key changes.
