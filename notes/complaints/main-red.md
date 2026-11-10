# main-red
- A merge rebased with clippy only left 20 red node tests on main; the edits tests were already fixed on a later branch.
- A fill test's pass hung on rank-0 blobs sorting by BlobId: a header format change reshuffled the batches and exposed a cross-batch await. Ordering by id hides such bugs until bytes change.
