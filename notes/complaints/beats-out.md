# beats-out
- The node test harness (`Net::new`) keeps accounts' home labels off the hosts (`home_at_hosts: false`), so any inbox delivery to an account (a stranded notice, a re-seal) silently goes nowhere; a test of an inbox path must set it, and nothing says so when it is missing.
- `osis_node::retention::suspect` flags raised by `flag_suspect` did not touch the engine, so a reader of the flags keyed on the engine generation never saw them: found only by an end-to-end test.
- The proto `examples_name_every_kind` test needs examples in kind order; adding a kind means placing its example, not appending.
- `driver::driver_lan_replaces_relay_localhost_spec_sync_10` failed 2 of 2 runs here (the route never settled to one LAN connection within `GUARD`); said to be flaky on main, not checked against main.
- Review: `suspect_report_outside_the_shared_set_is_ignored` used an unknown label, so it passed with the shared-set check removed; `net.group` twice with the same seed gives both groups one label ID (use `group_seeded`).
- Review: `driver_lan_replaces_relay_localhost` failed 1 of 15 on the branch and 1 of 15 on main (plus a 30 s near-miss on main): flaky on both, not made worse here.
