# A hostile linked header list costs tens of GB to decode
> Summary: `Header::resolve` decodes a linked list whole with only a byte limit, before the signature check: `{0:0}` items cost about 770 B of memory per list byte, so one list at `MAX_LIST_BYTES` (64 MiB) peaks near 52 GB. Resolved headers of applied commits also stay in memory with no bound on how many.
> Tags: security, commit, engine

- **Decode peak.** `osis_base::decode` of a list of one-entry maps: 8 MiB took 6.5 GB and 8 s (measured, dev profile); each map allocates a B-tree node. At 64 MiB that scales to about 52 GB and over a minute (not run: the box has 60 GB). At the old 8 MiB it was already 6.5 GB.
- **Who can.** `apply::examine` resolves before it checks the signature, and `actor` is the header's own claim, so all it takes is a dedup secret the node also holds (of any actor the sender reads, or created) and a way to deliver blobs. Repeated chunk links are legal, so the upload is about 300 KB (one `CHUNK_MAX` chunk and a node).
- **Not multiplied by pending.** `ix.pending` keeps a `Reason` only, and rows hold the unresolved header; one engine examines one commit at a time. A commit waiting pays again at each re-examination.
- **Multiplied by applied commits.** `Meta` keeps a linked header resolved (`LazyHeader::ready`), and `index::load` resolves all of them at open. A frontier of 34 B IDs held about 36 MiB per 8 MiB (measured), so about 290 MiB at the bound, per role commit, with nothing limiting how many; list blobs can be shared, so each costs its author about 1 KB. Needs a signature and a valid header.

Possible fix, not designed: check `visit_items` against a memory budget before `decode` (as `osis_crdt::decoded_bound` does for ephemeral parts), check the signature before resolving where the author is known, and hold linked headers as bytes like unlinked ones (`LazyHeader::stored`).
