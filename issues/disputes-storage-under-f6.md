# notes/disputes.md, Storage under a fork, predates one side per party
> Summary: notes/disputes.md (Storage under a fork) reads a party's writes as valid on both sides of a fork; under F6 a writer's commits list its side's step and apply nowhere on the other (notes/write-path-design.md §1, notes/delete-keys.md). Rewrite that section to match.
> Priority: low
> Tags: notes, engine

The delete-key check is built (notes/delete-keys.md: header keys and page links). What is left of it:
- notes/disputes.md, Storage under a fork, still assumes a party's writes stay valid on both sides (its delete check, branches, members carrying clean bodies). Under F6 a writer's commits list its side's step and apply nowhere on the other; rewrite the section, and the coherence rule's item 3, from that.
- The demoted writer's level-2 residue is its own issue: issues/demoted-writer-deletes-at-stores.md.
