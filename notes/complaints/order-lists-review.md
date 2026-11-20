# order-lists-review
- `Debug` of a `Seq` expands range records per element (equality-shaped), so printing a state never shows whether a join split or kept a range: count `elems().len()` / spans instead. Cost a wrong hypothesis.
- Text ranges exist only content-less (`seq_span::uniform`): a delete-only delta or a state holding deletes without their creations; a hand case from `create` then delete never ranges.
