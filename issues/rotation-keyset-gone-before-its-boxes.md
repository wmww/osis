# A rotation's keyset body can go before its boxes
> Summary: Authority reads a rotation's proofs from its `keys.0` delta. That body is role-class (kept `ROLE_KEEP` after replaced, then dropped as covered) while the same commit's `secrets.0` delta lives on (history entries are never replaced). A node fetching the commit afterwards holds `secrets.0` alone and reads no proofs: where the author's role ran through a holder actor it judges the part invalid, while nodes that held the keyset judge it valid (`Dropped::shown`). Not reached by a test.
> Priority: normal
> Tags: keys, engine, retention

## Shape
- Rule (spec/crypto.md §4 Authority): a node holding a rotation's `secrets.0` delta without its `keys.0` delta reads the commit as one without that body (spec/commits.md §4, nothing waits for a part). In flight that heals: the `keys.0` part counts missing and is fetched (`tests_authority::rotation_without_its_keyset_shows_nothing_until_it_comes_spec_crypto_4`).
- Once the keyset is replaced and a `keys.0` snapshot covers it, the body is gone everywhere and never comes. A fresh node (a new device of a holder) then judges the rotation's `secrets.0` part invalid for good. Effect seen so far: only superseded epochs (a current keyset is not replaced), whose establishment differs at that node; content still opens (an invalid box still opens; the newest history box carries the older secrets).
- Making the part wait instead does not help: the body never comes, so the part never joins (its history entries never count there), and it is a carve-out of "nothing waits for a part".
- A probe (keys.0 snapshot by the first admin of M, two `ROLE_KEEP`s, `tick`) did not drop the covered keyset body at that node; check what drops covered role-class bodies before building a reproducer.

## Options
- Keep a role commit's `keys.0` body while the same commit's `secrets.0` body on that thing is held (a judgment input kept with what it judges; cost: one keyset per role per rotation, small beside the boxes kept with the history entries).
- Carry the verdict inputs in the `secrets.0` delta too: rejected before (a certificate-only node then judges otherwise, notes/crypto.md Possession).
