# rotation-tests
> Summary: footguns met consolidating the rotation unit tests.

- Scripted regex rewrites over test files hit the helper they were introducing (a `shape(false); send...` pattern rewrote `shape_at_v`'s own body into self-recursion; a block-to-`w_arrives` replace rewrote `w_arrives`' body). Introduce the helper after the bulk replace, or exclude its definition.
- `--ignored _plain rotation::tests_cut::` is OR: it starts every `_plain` property in the binary (the custody differential among them). Name each with `--exact`.
- A spec_map anchor's `;` pieces are each a name: `(Passing on: x; y)` makes `y` a name, so a merged test citing two glosses of one rule joins them with `,` inside one gloss.
- The rotation tests' cost is mostly hand-built 4-6 peer worlds settled several rounds (`rounds_to_settle`, `settle`); line consolidation moves it little. Caching a setup shared by many tests (`LocalPeer::cached`) is what cuts a module's count (tests_reseal's `shape`: -25%).
