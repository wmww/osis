# kestrel-net-one-clock
- `redeem_direct_redials_sharer` needs a dial that fails, so it depends on the give-up; under a one-clock net it hangs to its 30 s guard until it sets `Net::set_dial_ms(0)`.
- `Multi` has no `observed()`, so a driver test wanting to wait for a relay registration uses `P2p` directly.
