# notes/disputes.md, Storage under a fork, predates one side per party
> Summary: notes/disputes.md (Storage under a fork) reads a party's writes as valid on both sides of a fork; under F6 a writer's commits list its side's step and apply nowhere on the other (notes/write-path-design.md §1, notes/delete-keys.md). Rewrite that section to match.
> Priority: low
> Tags: notes, engine

The section's delete check, branches and members carrying clean bodies all assume a party's writes stay valid on both sides; rewrite them, and the coherence rule's item 3, from F6. The delete-key check itself is built (notes/delete-keys.md); the demoted writer's level-2 residue is issues/demoted-writer-deletes-at-stores.md.
