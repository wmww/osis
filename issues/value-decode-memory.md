# A whole-value decode of a blob costs 770 B per byte
> Summary: `osis_base::decode` of `{0:0}` items costs about 770 B of memory per byte, so `CommitBlob::decode` of one 8 MiB blob peaked at 6.4 GB (measured), before any signature or list check and with no dedup secret needed. Other whole-value decodes of peer bytes pay the same. A stranger reaches it through an inbox.
> Tags: security, commit, base

Measured: `CommitBlob::decode` of a blob of `MAX_BLOB` bytes holding `{0:0}` items, 3.3 s, 6476 MiB peak (dev profile). `decode_as` decodes everything before it looks at any of it.

Each one-entry map allocates a B-tree leaf of 11 `(Value, Value)` slots, and `Value` is about 104 B because `Link` sits in it unboxed.

Sites seen, not a full list: `CommitBlob::decode_as`, `osis_label::open_inbox_blob`, `apply::raw_id`, `osis_label::read_value` (`read_large_max`), `osis_crdt` delta decoding.

Who reaches a whole-blob decode (from reading, not run end to end), each before any signature check:
- **Inbox sender or the host of an inbox label, no secret needed.** `open_inbox_blob` seals to the KEM key in `keys.0` and decodes the plaintext whole (`OBJECT_LIMITS`) before it looks at the payload; `open_one` then decodes `payload.commit` again with `CommitBlob::decode`. The deposit key comes from the seed in `keys.0`; a host can simply list the entry. The worst case: 8 MiB deposited, 6.4 GB at the recipient, once per blob and before admission.
- **Anyone holding the group's read secret, on any label.** `unwrap_any` needs a wrap that opens under a read secret, then `open_commit` decodes. A writer uploads it; a reader deposits it (a deposit takes any wrap) or hands it to a host. The ephemeral path (`eph_added`) has the same order: its node cap is read after `open_commit`, so it bounds the delta decode, not this one.
- **Not a host alone on another label**: without a read secret its wrap opens nothing, and `open_inbox_as` tries only inbox labels.

Possible fix, not designed: read the commit blob by shape, as header lists are now (`osis_base::Reader`), holding each delta as bytes. The whole-commits work is changing that format, so do it with or after that. Deltas and values are general, so they need something else: a memory budget in `Decoder` (`Limits`), like `osis_crdt::decoded_bound` by heads, or a smaller `Value` and map.
