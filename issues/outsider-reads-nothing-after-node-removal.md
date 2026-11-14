# An outside reader loses its grant when the granting account removes one of its nodes
> Summary: After account A removes one of its nodes, a reader of another account stops reading A's things (before and after the removal): A's account rotation reaches it, A's node-removal history does not, and its engine then counts A's grant to it as fallen.
> Priority: critical
> Tags: engine, sync, security

## Reproducer
- osis-sync `siblings::repro_an_outsider_reads_the_accounts_writes_across_a_node_removal` (ignored): siblings fixture; node 1 (account A) writes t, grants account B (node 0) read, node 0 accepts and reads; node 1 removes its sibling node 2 from A's D (`Engine::demote(D, n2, None)`); node 0's roster of t loses B's read edge (node 1's keeps it) and it reads nothing.
- osis `sync::an_outsider_reads_the_accounts_writes_across_a_node_removal_spec_permissions_3` (ignored): the same through the API (`remove_node`), found by Fathom on main.

## What node 0 holds
It holds every commit it held before (none dropped) and gains one: A's rotation (role commit by A: `keys.0` on A, `account.0` on D). It lacks D's records and D's role commits (the removal edge write on D, D's rotation), which it cannot read. Handing it node 1's commits by hand does not help: they pend on D's record (`UnknownCreated(D)`, `MissingChain(D)`).

## Where to look
Either sync does not log what the keyset needs beside A's rotation (notes: whoever logs a keyset logs its demotions too, as chain certificates), or the engine judges B's grant fallen with A's new keyset held and its demotions not (it should count the keyset not held, depth0 option B, and keep judging by the old one). Engine judgement first (Fathom): node 1 keeps the edge with full history.
