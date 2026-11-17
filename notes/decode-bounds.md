# Decode bounds
> Summary: The one rule for memory on decode and read (what a node holds of an input is bounded by the bytes its author delivered for it, or by the reader's own bound, never by what the input names), the mechanism per input (`Limits::max_alloc`, header list keys, coded peer filters), and what is left.

**Rule.** What a node holds of an input is a decoder-set multiple of the bytes the input's author delivered for it (sent, or made the node store), or at most the reader's own bound for what it asked to read; never what the input names, claims or shares with other inputs. The decoder enforces it where it allocates; callers pick no numbers of their own. spec/wire.md §12 Memory states it.

## By input
| input | supplied by | decoded at | bound |
|---|---|---|---|
| a value inside a blob or message | writer, peer | `osis_base::decode` and readers by shape | its bytes (`Limits::max_bytes`; at most about 56 B per byte; messages also 2^20 items) |
| a large value read whole | writer | `osis_blob::read_value` (engine `read_large_max`, osis `read_link`) | the reader's bound: canonical bytes, and as much again decoded (`Limits::max_alloc`) |
| a commit's linked header lists | signer | `Header::resolve` | the bytes of its own lists: a list's tree is keyed to its header (list key) |
| a peer's filter | stranger | `Opens::beacons`, records load | its coding (`osis_proto::filter::Beacons`) |

- **`Limits::max_alloc`** (osis-base `cbor.rs`): the decoder charges each slot (`Value` per promised item), box (enum payload, link, ticket, unknown tag) and string before allocating it, and fails `TooLarge` past the bound; `check` charges alike, so it refuses exactly where `decode` does. Charges are never returned (an unknown tag's content, decoded and dropped, stays charged), so the charge bounds the peak. `decode_charged` returns the charge. Default unbounded: `max_bytes` bounds it. Test: `decode_allocates_within_its_bound_spec_wire_12` (the charge covers what the value holds, every hostile shape).
- **Whole reads.** `read_value` decodes with `max_alloc` = its byte bound, and a decode past it is `TooLarge` (local), not bad input. The osis read budget charges each link the greater of its canonical bytes and its decode, so one `read_limit` bounds a read over many links. One-byte unknown tags decode to about 36 B per byte: `a_value_read_whole_holds_at_most_its_bound_spec_wire_12` (osis-blob).
- **Header lists.** Keyed by `kdf("header list", actor dedup, skeleton)`, the skeleton being the header's bytes with its linked positions `[]` (`Header::list_secret`; the writer computes it before linking, the reader from the decoded header). Two commits differing outside their lists key them apart, so no small commit can name another's 64 MiB list. A resolved list stays in `Meta` at about 5 B per byte (as inline lists do: the engine's commit indexes are in memory by design). Test: `a_linked_list_serves_its_own_commit_only_spec_wire_4` (osis-commit).
- **Filters.** A peer's filter is held as Golomb-Rice runs, as on the wire, with an index point every `STRIDE` (64) entries; a run at least as long as the one before merges into it (at most log2 n + 1 runs, each entry recoded at most log2 n times). An arriving generation builds its run page by page, and its row is the run's bytes. About 1.3 B an entry against 8; per connection at most `MAX_FILTER_ENTRIES` whole plus as many added. Test: `opens::a_peers_filter_is_held_as_sent_spec_wire_11_2` (osis-sync).

## Rejected
- A format item cap on linked values (`MAX_PAGE_ITEMS`): an item count is not memory (a link holds five times an int), and the reader's own bound already caps it.
- Holding linked lists as bytes: saves about 5x and leaves the count of commits sharing one list unbounded.

## Left
- Transient peaks of one examination: a frontier at `MAX_LIST_BYTES` peaks near 1 GB (header clone, typed copy, `Frontier`), once per examination; the author delivered 64 MiB for it.
- Total over connections: per-connection state grows with peers, the requirements' stated limit; the node-wide bound is issues/sync-unbuilt.md (Security).
- A read of an aspect's state loads it whole before the read limit refuses it: issues/durable-decode-bound.md.
