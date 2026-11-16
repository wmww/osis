# keel-prose-split
- Writing the first new note over notes/crypto.md before the others were drafted left the old text only in git (`git show HEAD:notes/crypto.md`); draft splits into new files first, overwrite the old file last.
- `tools/doc_refs.py` catches section pointers but not bare file pointers whose topic moved (`notes/crypto.md (epochs)` still passes); those needed a by-hand grep of every remaining pointer to the split file.
- Some notes cited spec/wire.md §9 "boxes payload" and wire.md §4 field 16 for the own cover; neither matches the spec now (§9 has no boxes payload, the own-cover field is 17). Notes restating byte positions rot; point at the section instead.
