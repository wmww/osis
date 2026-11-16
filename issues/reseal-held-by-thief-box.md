# A node holding its head's seed only by X's re-seal re-seals it to no one
> Summary: The custody differential finds (about 1 world in 2000) a node of P on X's side (it took X's revocation of A) that holds its head's seed only through X's re-seal to it, where the model re-seals that seed to T (on its roster, holding no box of it) and the engine's `custody::reseal_seeds` makes nothing.
> Priority: normal
> Tags: engine, tests

- Seen: C took X's revocation (boxed to B and X only); X re-sealed that epoch's seed to C; C's pass end makes t's re-key but no re-seal, while T lacks the seed. Find why `reseal_seeds` skips the head (its keys found through `keys_of`, the roster, the counting tags) and build the minimal test from that (never pin the seed).
