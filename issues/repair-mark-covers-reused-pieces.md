# A repair's mark also covers the chunks it reused
> Summary: `Meta::repair` exempts every piece of a repair commit from repair, but a repair reuses every chunk it did not re-encrypt; once the repair is the only own linker of such a chunk, a later purger's delete of it is never repaired and readers pulling through stores lose the value.
> Priority: normal
> Tags: sync, engine

spec/sync-ids.md §1 Repair excludes a commit that is itself a repair, because "what a repair encrypts afresh only it links". True for the re-encrypted blobs (`Mutation::fresh`), not for the rest of the value's tree: a repair writes the position whole with `Reuse`, so it links every unchanged chunk too.

Shape: own commit E links chunks {A, X}. A purger missing the reuse deletes A; repair R1 writes A' and reuses X. A second round (another chunk, R2) makes two own replaces of E at a root large value (a root `Op::Put` is a whole replace, spec/commits.md §5 Own replaces), so E drops. Now X is linked by own commits R1, R2 only, both marked. A third purger deleting X: `judge::pieces` skips (`f.own && !f.repair`), nothing repairs X, and a reader reaching only the deleting store cannot read the value.

Fix: the exemption is per blob, not per commit: a piece is not repaired by way of a repair commit only when that repair encrypted it afresh. Keep the fresh set with the mark (bounded by the pieces repaired), or judge a repair commit's pieces as any own commit's but skip those it wrote afresh. Spec wording follows ("the blob not one a repair of the node encrypted afresh").
