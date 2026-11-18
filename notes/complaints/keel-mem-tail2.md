# keel-mem-tail2
> Summary: mishaps met on the bounded-memory tail.

- `Memo` has no `Default`, so a test resetting `Core::tree_roots`/`covers` must name the memo as `Core` does (`Memo::new("tree roots")`, `"covered"`): a wrong name compiles and silently files stamps elsewhere.
- `costs` had only sums; a held peak needed `costs::peak`.
