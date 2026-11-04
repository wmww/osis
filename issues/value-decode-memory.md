# A whole-value decode of a blob costs 770 B per byte
> Summary: `osis_base::decode` of `{0:0}` items costs about 770 B of memory per byte, so `CommitBlob::decode` of one 8 MiB blob peaked at 6.4 GB (measured), before any signature or list check and with no dedup secret needed. Other whole-value decodes of peer bytes pay the same.
> Tags: security, commit, base

Measured: `CommitBlob::decode` of a blob of `MAX_BLOB` bytes holding `{0:0}` items, 3.3 s, 6476 MiB peak (dev profile). `decode_as` decodes everything before it looks at any of it.

Each one-entry map allocates a B-tree leaf of 11 `(Value, Value)` slots, and `Value` is about 104 B because `Link` sits in it unboxed.

Sites seen, not a full list: `CommitBlob::decode_as` (`sync/inbound.rs` calls it on decrypted blobs), `apply::raw_id`, `osis_label::read_value` (`read_large_max`), `osis_crdt` delta decoding. Who can reach each was not traced.

Possible fix, not designed: read the commit blob by shape, as header lists are now (`osis_base::Reader`), holding each delta as bytes. The whole-commits work is changing that format, so do it with or after that. Deltas and values are general, so they need something else: a memory budget in `Decoder` (`Limits`), like `osis_crdt::decoded_bound` by heads, or a smaller `Value` and map.
