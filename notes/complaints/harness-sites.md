# harness-sites
- `packages_to` (a world copy and a sync per call) inside a per-seed or per-order loop costs seconds: a reach test went from about 1 to 14 CPU-s. One reader's list serves every reader of a thing; an observer's own sync set (`common::packages_for_peer`) needs no copy.
- A fresh reader's sync set as it stands can miss its thing: `packages_for` to one silently dropped a commit the test then found missing (`packages_to` is right there).
- `memory::big_map_apply_memory` (by hand) failed on main: its child node was a bare node keeping none of the thing's content. By-hand tests rot unseen; nothing runs them.
