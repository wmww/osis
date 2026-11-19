# g-needs
> Summary: Footguns met while making a needed-only thing hold certificates alone.

- Many engine tests read content at a peer that holds a thing by a node-root strong and no role (`new_thing` without `share`, `net2`, `world`'s outsider): plaintext test delivery let such a node read what a real node never opens. Option A strips it, so ~25 setups broke at once; `new_thing`'s doc invites the pattern.
- `order::fresh` and `parts.rs`'s `Peer::new(FRESH)` are the same account (one seed): the "role-less" observer is granted by the base, which is not obvious from either file.
- The order harness had no model of a pull from the start (a sync ID joining, `pulled_anew`): nothing tested that stripped content comes back on entry.
