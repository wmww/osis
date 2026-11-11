# punch-reflect
> Summary: workflow notes from the punch-reflection fix.

- The `punch` test helper put NAT-less hosts at private addresses behind a global relay; nothing marked that as unrealistic until an address filter refused it. Model hosts with no NAT should sit at a global address.
- The by-hand QUIC relay tests (`p2p::quic -- --ignored`) are the only real-socket check of the punch datagram; they cannot see whether it was sent.
