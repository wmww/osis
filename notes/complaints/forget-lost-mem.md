# forget-lost-mem
> Summary: Workflow notes from fixing forget_lost's memory records.

- Losing access is hard to stage in the node Net without a peer relisting the entries first (the relist from the start restores records a peer still lists, masking the bug): needed two hosts, `blocked` plus `drop_link` on one, and a demote through the other.
