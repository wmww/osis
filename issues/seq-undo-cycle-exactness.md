# Undo of a move on a cycle: is the spec exception wide enough?
> Summary: spec/crdt.md §4.6 Exactness exempts only an element whose `cur` was demoted to break a cycle from "undo restores the read"; the seq fuzz skips the check for any moved element on a broken cycle, because placement records cycle membership, not which element was demoted. Unchecked whether undoing a move of a non-demoted cycle member restores exactly. Low.
> Tags: tests, crdt, spec

Found reviewing test-tooling-13e. Next: record the demoted element in placement (test-only or debug), narrow the fuzz skip to it, and either confirm exactness or widen the spec exception.
