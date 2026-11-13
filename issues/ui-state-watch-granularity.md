# Extra whole-view refreshes per typing pause
> Summary: Two whole-view refreshes beside per-node re-render (notes/listener-design.md; kit `graph::one_node_state_write_renders_one_node`), unchecked: on a store with a peer a draft commit changes `status()` and `on_status_change` posts a whole-tree refresh; the opener renders its content view once to learn `has_foot`, then the shell renders it again as its own node.
> Priority: low
> Tags: app, kit

Check each in osis-app under guibox with a chat open and typing in the composer; fix what still re-renders the chat.
