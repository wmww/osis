# prune-rest
> Summary: Workflow snags met pruning stage P's drop wait and last-admin rule.

- A python slice "from the first test's doc comment to the third test's" deleted four unrelated tests between them (notes/build.md, Scripted edits): count `#[test]` inside every cut before writing it.
- The last-admin rule's removal could not be judged from a grep: its effect on the story showed only in a search (`-- 3000 paths`, about 45 CPU-s), where the honest remover's list had leaned on it. A worker pruning a judging rule from roles-model runs a few thousand story worlds against main's binary (`tools/bin-at`) before touching the other crates.
