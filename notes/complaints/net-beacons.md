# net-beacons
- `decode_body`'s field-count table is separate from its arms: a new kind decoded fine in the msg test only after both were edited (a kind missing from the table fails as "unknown kind", on the wire only).
- A `group_at` per helper with the same seed makes one label ID: the gain-mid-connection test passed for the wrong reason until `group_seeded`.
