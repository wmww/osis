# The opener renders its content view twice
> Summary: The opener (libs/kit/src/views/opener.rs) renders its content view once to learn `has_foot`, then the shell renders it again as its own node: each change to that view renders it twice, beside per-node re-render (notes/listener-design.md; kit `graph::one_node_state_write_renders_one_node`).
> Priority: low
> Tags: app, kit

Fix: learn `has_foot` from the one render (the node's own output) instead of a second render in a memo.
