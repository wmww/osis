# a1-spec-rewrite
> Summary: Mishaps met rewriting A1's spec sections (mizzen-a1-spec).

- The brief (owner keys in spec now, key actors as a kind gone) and the notes it pointed at (notes/a1-spec To recut: "stands until A4"; notes/terms.md: never call a key actor a thing with an owner key) disagreed; the spec carries an Interim bullet in spec/permissions.md §1 for the things whose record holds a key.
- Deleting a draft note is a pointer sweep: 65 pointers in 29 files named notes/a1-spec's four draft files, 50 more its README (kept, trimmed).
- A test of a rule the spec drops cannot keep its anchor (`spec_map --gaps`), so "leave the test to the rebuild" still means editing its citation: each now cites a living rule with a gloss.
- The old walk's code comments (`§5.1 step 4`, invite levels) still resolve as pointers and were left.
- Review: a mechanical pointer sweep turned "(draft: notes/a1-spec/permissions.md …)" into "(draft: spec/permissions.md …)" in osis-perm's module docs, which then read as nonsense; a sweep that retargets a pointer whose gloss names the old file's role needs the gloss rewritten too.
