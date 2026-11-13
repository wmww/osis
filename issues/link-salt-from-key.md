# Derive a link's prefix salt from its blob key
> Summary: a LINK carries its blob's 16-byte prefix salt beside its key; derived from the key as the link blind is (`kdf("prefix salt", blob key)`), it would need no field, 17 B less per link (about 7% of a link with three delete keys). Optional, from the step-1 review of issues/chunk-list-in-tree.md.
> Priority: low
> Tags: crypto, engine

- The salt is in the link so a holder deletes a piece without fetching it (issues/chunk-list-in-tree.md Decisions); derived from the key it stays so: the holder holds the key.
- What it takes: the LINK format and its vectors (spec/data-model.md §5, spec/wire.md §5), `linked_prefix_inputs` and every framing of a linked blob deriving the salt (`BlobWriter::put_blob`, header-list blobs through `ListBlobs`, whose salt the builder draws today), `tree::bears` and `Framing::keeps`, the freed rows (salt stored), the delete signing (`freed_delete_secrets`); about 80 sites read `Link::salt`. A host sees the salt as now: a KDF output of a key it never sees.
- Check before building: nothing else needs the salt chosen apart from the key (spec/crypto.md §7: the salt is per blob, random; a derived one is per key, which is per blob).
