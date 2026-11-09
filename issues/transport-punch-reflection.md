# A relayed dial makes the target send about 8 KB to any address
> Summary: `QuicSock::punch` starts a full QUIC handshake at an address the dialer chose, with no address filter, so a dial through a relay reflects retransmitted 1200-byte packets at any host. Replace it with one datagram and filter the address.
> Priority: normal
> Tags: security, transport

Found by reading, not run. core/transport/src/quic.rs `QuicSock::punch`, called from core/transport/src/p2p.rs with the address the dialer put in the exchange (any key may dial through a relay).

- notes/networking.md says "one punch packet". The code runs quinn `connect_with`, which retransmits padded 1200-byte Initials with backoff until `IDLE_TIMEOUT` (60 s): about 6-8 packets per relayed dial (quinn's exact count unchecked), sourced from the target's IP.
- An attacker who knows T's dialable key and relay opens up to 16 DIAL streams per relay connection, bounded only by `MAX_FORWARDED` and `REG_STREAMS`, each naming victim V.
- `exchange` returns the parsed address straight to `punch`: multicast, broadcast, loopback, unspecified and port 0 are not refused. An osis listener at V also does a TLS handshake per punch.

Fix: punch with one raw datagram through `Sock` (its doc already says "sends a packet"), which also removes a 60 s task and a fake pinned key; refuse addresses `lan::is_global` refuses (a LAN candidate needs its own rule) and port 0.
