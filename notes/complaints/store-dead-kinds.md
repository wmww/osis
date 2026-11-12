# store-dead-kinds
- Finding dead pub fns took a hand-rolled grep loop: rustc's dead-code lint stops at `pub`, so store row kinds unused since the store was built (wraps, actor secrets, cursors) stayed, kept alive by their own tests. A periodic "pub items with only same-crate test callers" check (tools/) would catch these.
