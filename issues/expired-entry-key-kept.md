# A map entry an expiring delta created reads differently by arrival order
> Summary: c1 puts map key k with an expiry; another writer that saw c1 overwrites k in c2 with no expiry. What a node then reads for k depends on order and on who holds which body: a snapshot strips the expiring delta's key, so c2's live write travels in it under no key. Not from atomic apply.
> Tags: crdt, engine, tests

Symptoms:
- Past T, both under keep at most 0, whole commits, no snapshot: a node that got c1 then c2 reads k = c2's value, one that got c2 then c1 reads no k. Repro: `waits::expired_entry_key_alike_repro_spec_crdt_4_7` (ignored until fixed). With no keep bound both orders read alike.
- Before T: a holder's snapshot lists c2, and a node holding c2's part only through it (its body dropped as covered) reads no k while the holder reads c2's value. Its states also differ in dead residue under the key.

Spec/crdt.md §4.7 and §8 must say which is right: c2's write has no expiry, but c1 made the entry that holds its key.

Oracles miss it: `order::` never draws an expiring put on a keep-at-most aspect. `waits::gap_snapshot_check` gives expiring puts keys of their own for this reason; lift that with the fix (shared keys failed about 1 seed in 1000).
