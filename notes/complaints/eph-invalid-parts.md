# eph-invalid-parts
- Invalid memory parts were held for two reasons, one hidden: `goes_invalid`'s memory exception, and `Engine::run` skipping `drop_invalid` in every memory transaction (a comment said "memory parts stay"). Removing only the first left 3 of 200 flooded commits held: worth a grep for duplicated guards before trusting an issue's one-line plan.
- In the test net, `set_online(n, true)` plus `run()` does not reconnect; it takes `advance(..)`. Cost a debug round.
- `memory_want` knew a wanted entry is absent at the asking peer but left its presence there set, so a dead entry a peer never held could never go.
