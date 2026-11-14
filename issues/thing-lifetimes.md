# Thing lifetimes: what is left
> Summary: Thing lifetimes by reference are built (design notes/lifetimes.md, engine notes/engine-lifetimes.md). Left: the dependents check in held-model `model.rs`, two node tests, the re-walk keyed by the unheard group, and kit, app and chat adoption.
> Priority: normal
> Tags: engine, tests, app

- **Dependents in the model**: held-model `model.rs` (destruction model) with a release request as one more kind of destruction evidence: check that a node holding a dependent never revives the released thing and judges later edge writes on it as one holding the original destruction does.
- **Node tests** (over several nodes): a removed member's node releases nothing; a concurrent re-reference dangles.
- **Re-walk cost**: held things are walked again whenever any group is newly heard out, not only those waiting on it; a thing held for good under a never-connected co-reader's group is re-walked at each such change. Key the waits by the unheard group (`lh/`).
- **Adoption**: kit, app and chat use `retaining` and `release` (app-layer work).
