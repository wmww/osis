# A removal's cost grows with the thing's earlier rotations
> Summary: Unconfirmed, seen probing engine `scale::removing_a_node_spec_permissions_8` at 21 nodes: the remover's state page loads grow with A's earlier rotations (218 with none, 391 after 8, 606 after 20). Work tied to history, not to live state; probe and count before treating it as real.
> Priority: low
> Tags: engine, performance

Seen by the inbox-admin review (9228c6491); no cause found. First step: a counting test at 0, k and 10k earlier rotations with the remover's loads per component, then a cpuprof of the grown case.
