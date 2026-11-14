# A reader's history entry at a made-up epoch stops `secrets.0` compaction
> Summary: A history add needs only the role its key names (`apply::validity::secrets_role`), so any reader may put an entry at `(read, e)` for an epoch e with no rotation. The state then keys e, which no held rotation commit or snapshot bases, so `may_compact_secrets` is false at every node for good and `secrets.0` grows with every later rotation, uncompacted.
> Priority: normal
> Tags: keys, security

- Found by code reading while relaxing the gate for withdrawn epochs (it sets names aside but still needs the rotation basis, which a planted entry never has). Not yet reproduced in a test.
- Threat model: "malicious readers can only waste storage", and this is that, but unbounded and by one write; a writer can do the same with a box.
- Direction: the snapshot should not need every keyed epoch vouched. E.g. a snapshot bases only epochs some held valid keyset lists or writes (a planted one is in none), so the gate may compact over planted keys. Model the establishment change before building.
