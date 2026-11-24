# Derive a link's prefix salt from its blob key
> Summary: A LINK carries its blob's 16-byte prefix salt beside its key; derived from the key as the link blind is (`kdf("prefix salt", blob key)`), it would need no field: 17 B less per link. Optional.
> Priority: low
> Tags: crypto, engine

- The salt is in the link so a holder deletes a piece without fetching it (notes/chunk-links.md, The link); derived from the key it stays so. A node keeping the blob unread sees it as now: a KDF output of a key it never sees.
- What it takes: the LINK format and its vectors (spec/data-model.md §5, spec/wire.md §5), `linked_prefix_inputs` and every framing of a linked blob deriving the salt instead of drawing it, the freed rows (salt stored), the delete signing (`freed_delete_basis`), and the sites reading a link's salt.
- Check first: nothing needs the salt chosen apart from the key (spec/crypto.md §7: per blob, random; a derived one is per key, which is per blob).
