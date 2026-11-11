# punch-reflect
> Summary: workflow notes from the punch-reflection fix.

- The `punch` test helper put NAT-less hosts at private addresses behind a global relay; nothing marked that as unrealistic until an address filter refused it. Model hosts with no NAT should sit at a global address.
- The relay tests' real-socket path never checked the punch datagram itself; `quic_punch_is_one_unanswered_datagram_spec_sync_10` (by hand) does.
