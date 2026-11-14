# An outside reader loses its grant when the granting account removes one of its nodes
> Summary: After account A removes a node, an outsider reading t can judge A's grant unlisted (A's rotation closed its epoch, t's thing list not here yet) and stop syncing t before the list arrives; lists travel and wrap as their rotation, the leave does not yet wait for them.
> Priority: critical
> Tags: engine, sync, security

## Reproducer
- osis-sync `siblings::repro_an_outsider_reads_the_accounts_writes_across_a_node_removal` (ignored): siblings fixture; node 1 (account A) writes t, grants account B (node 0) read, node 0 accepts and reads; node 1 removes its sibling node 2 from A's D (`Engine::demote(D, n2, None)`); node 0's roster of t loses B's read edge (node 1's keeps it) and it reads nothing.
- osis `sync::repro_an_outsider_reads_the_accounts_writes_across_a_node_removal_spec_permissions_3` (ignored): the same through the API (`remove_node`), found by Fathom on main.

## State
- Built: list blobs logged per sync ID (`certificate_lists`, `seal_lists`, `Opened::Lists`, loose until their rotation); lists wrap as their rotation (`list_wrap_secret`, spec/crypto.md §5). osis-sync `siblings::an_outsider_reads_the_accounts_writes_across_a_node_removal_spec_permissions_5_5` passes (the rotation reaches the outsider under t's sync ID alone).
- Left: where the outsider holds A's contact card, A's rotation arrives first under the card's sync ID, t reads Plain, S_t leaves at once and its list never arrives. Fix in progress (branch outsider-fix): a leaving S keeps syncing until a complete pass begun after it left, the engine answering for it meanwhile.
