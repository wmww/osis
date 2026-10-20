# One delta of a struct with many large register fields cannot fit a blob
> Summary: Paging covers only Bag/Set/Map/Seq element arrays, so a Struct or Enum fragment holding more than `MAX_BLOB / CHUNK_THRESHOLD` near-threshold registers makes a delta that no blob can carry; the spec now says the writer refuses such a write. Possible fix: let Struct and Enum field maps page too.
> Tags: crdt, data-model

Repro: design: the writer refuses such a write (spec/commits.md §1).

spec/commits.md §1 requires one delta to fit a blob and makes the writer refuse the write. The shape that fails is rare (dozens of inline blob or string fields each just under `CHUNK_THRESHOLD`, in one struct, outside any collection). spec/wire.md §2 sets `MAX_BLOB / CHUNK_THRESHOLD` = 64 (8 MiB / 128 KiB) to keep it rare.

Options: (a) keep the refusal (current); (b) extend spec/crdt.md §8 so a Struct's or Enum's fragment map may be `[Link*]` to pages that are field maps, split at content-defined boundaries like element arrays. (b) is a grammar extension; decide before vectors freeze or accept (a).
