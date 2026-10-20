# Seeking into a large value fetches everything before the offset
> Summary: Tree nodes carry no lengths (spec/wire.md §6), so a range read or `Seek` into a large blob or string must fetch and decrypt every chunk before the offset; notes/api.md wants `stream` to be `Read + Seek` with lazy chunks.
> Tags: performance, data-model, api, storage

Repro: design: osis-label `StringReader::skip` reads every chunk before the offset.

osis-label's `StringReader::skip` reads and discards. Reading the last MiB of a 10 GB blob fetches 10 GB. Memory stays bounded; transfer and time do not.

Options:
1. Local length index (recommended): the node records each chunk's plaintext length when it first reads or writes a tree (a rebuildable cache unit per aspect, notes/local-store.md); a seek walks the cached lengths and fetches only the target chunk. No format change; the first seek on a tree never read locally still costs O(offset).
2. Lengths in tree nodes (`[level, [LINK+], [len+]]` or a length per link): O(log n) seek for any reader. Format change to spec/wire.md §6 and the provisional `chunker/tree.vec`; owner call.
3. Accept O(offset) and document it.
