# tree-refs-delta
- Exact reachability counts cost each node read its links (up to `TREE_FANOUT`, about 256 on average by the node rule); at test sizes (8 and 80 chunks) the whole tree is one node, so "links counted" grows with the value there even though nodes read are flat. Counting work at sizes past one node (thousands of chunks) is too slow for a default test; the flat test counts blobs read instead.
- A redirect into a scratchpad subdirectory that did not exist yet failed a backgrounded cargo run silently (exit 1 only in the task output).
