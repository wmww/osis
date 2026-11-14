# sync-unbuilt-1
- An `Effects::settle` closure records only the stamped reads made inside it: a `Stamped::get` hoisted out of the closure (to build a merged view) silently stops the key from following that value. Cost a debug round on held elsewhere.
- A flag kept on the store's entry row (held elsewhere) stamped the entry, so inbox's judgement of every own entry re-ran when status recorded it; only `keep::a_taken_inbox_blob_is_taken_once` caught it. Status's notes now live in a row of their own.
- `sync_ids(t)` reads like "the sync IDs carrying t" but is the ones t owns: `Node::wait(Thing)` used it, so a wait on an item in a group never ended. `Engine::carrying(t)` is the carrying one.
- Several test worlds needed `w.cap = 200_000` before a 4-node history; the default cap's storm panic names no step.
