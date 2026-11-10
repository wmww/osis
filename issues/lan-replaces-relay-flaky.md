# driver_lan_replaces_relay_localhost times out at 30 s now and then
> Summary: The tier-2 test `driver::driver_lan_replaces_relay_localhost_spec_sync_10` takes either ~0.15 s or ~30 s (2 of 5 runs on main, one of them past `GUARD` 30 s, failing): the LAN route seems to come up only at the next `LAN_ANNOUNCE` (30 s) repeat, as if the first announcement or its dial was lost (`join_repeats` is 0 there). Not root-caused.
> Priority: low
> Tags: tests, node, transport

The failing run logs `connection 1: closed (slow or gone)` four times before the guard fires (core/node/tests/it/driver.rs, the wait for a single LAN route after `converge_p2p`). Find why the first announcement does not lead to a kept LAN connection (a dial racing the relay connection and losing the one-connection-per-pair choice?), then fix that rather than raising `GUARD` or adding repeats.
