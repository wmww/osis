# Own entries placed under a hosted label and never uploaded stay
> Summary: The local pass places a node's own must-hold entries in its store under every synced label, hosts or not, but deletes only under labels with no host. An own entry placed while no host is connected that becomes must-not-hold (covered by a snapshot) before a host pass uploads it is never uploaded, so no host's deletion ever reaches it, and nothing else drops it: a row (and its bytes until the engine drops them) per such write, kept for good. Found by reading (net-pull2 review); not reproduced yet.
> Priority: normal
> Tags: node, sync, growth

## Why
`judge_local` runs `local_deletions` only with `host` (no host in `label.0`). Under a hosted label the host pass deletes only entries present at its host (`deletions`, `present_at`), and a host's `Deleted` drops a local entry only through `absent_at`, which needs the entry to have been at that host. An entry never uploaded meets neither. Offline writing with compaction (a phone away from its host, overwriting a register) makes one per overwrite: a leak by notes/growth.md's rule.

## Direction
`local_deletions` already limits itself to entries no host or peer holds; running it under hosted labels too (deletions only, not steps, heartbeat or promotion) looks like the rule: what this node's store must not hold goes there, whoever else holds it. Check it cannot drop an entry a host holds but this node has not heard of yet (judged must-not-hold anyway, so dropping it locally is retention's own judgment). Test: a node with a host, the host unreachable, a register overwritten and compacted n times, then the host back: the node's entry rows for the label do not grow with n.
