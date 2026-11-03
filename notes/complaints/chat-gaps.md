# chat-gaps (tiller-chat-gaps)
- The tier-2 `own_host_device_localhost` failed on main for a long time: any person who adds a host after `init` could not have a link to it redeemed. No per-branch check runs it; a person with a host from `init` hides it. Now covered in tier 1 (`redeem_link_of_a_person_with_a_late_host`).
- `osis ... -v` in a test helper: the helper adds its own `--timeout`, a second one is a clap error, not an override.
