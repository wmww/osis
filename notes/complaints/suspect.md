# suspect
- A World test of a writer mid its first sync of S meeting a flagged reader needs the reader to dial the new node, whose address reaches it only through the node it is cut off from: no cheap way to stage it, so the "list waits for the first sync's end" path has no test (a mutation removing it passes).
- `Engine::package(c)` after a purge of c returns the header only: package a paged commit before purging it, else a "paged" check sees one blob.
- A paged map write in a World test needs a schema aspect (`StaticSchema` map type): a raw `Ak` with `Value::Map` is one atomic value.
