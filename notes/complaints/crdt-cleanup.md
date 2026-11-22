# crdt-cleanup
> Summary: Workflow notes from a line-cutting pass over osis-crdt.

- Hunting dead pub items by `rg -w "name\("` counts nothing: `-w` needs a word boundary after `(`. Use `rg "\bname\("` (or `\bname\b`).
- osis-crdt has essentially no dead code (rustc catches crate-private items; every re-exported fn has a caller outside or inside): line cuts there come only from merging duplicated walks, which needs reading each one.
