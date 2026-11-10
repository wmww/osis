# beats-out
- The node test harness (`Net::new`) keeps accounts' home labels off the hosts (`home_at_hosts: false`), so any inbox delivery to an account (a stranded notice, a re-seal) silently goes nowhere; a test of an inbox path must set it, and nothing says so when it is missing.
- `osis_node::retention::suspect` flags raised by `flag_suspect` did not touch the engine, so a reader of the flags keyed on the engine generation never saw them: found only by an end-to-end test.
- The proto `round_trip_every_kind` test needs examples in kind order; adding a kind means placing its example, not appending.
- `driver::driver_lan_replaces_relay_localhost_spec_sync_10` failed 2 of 2 runs here (the route never settled to one LAN connection within `GUARD`); said to be flaky on main, not checked against main.
