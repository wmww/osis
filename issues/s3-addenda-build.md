# S3: what addenda still owe
> Summary: Addenda (spec/permissions.md §5.2 Addenda) are built in perm and engine (notes/addenda.md). Left: the remover's leaving out, held-model and the order harness playing addenda, addenda vouching for purge requests, and which node's addendum counts as "of its own" once nodes sign as their node things.
> Priority: normal
> Tags: perm, engine, spec, tests

Plan: notes/redesign-plan.md S3.

1. **The remover's leaving out** (notes/account-membership-design.md §4, The list; notes/write-path-design.md §1, The list is its writer's): a list naming X's lowering of the remover voids the removal, so the remover leaves out what its removal would not apply with. Not in spec/permissions.md §5.1 Frontier. With today's writer rule it changes nothing reachable (the engine writes R only where its author holds the authority in its own walk, where every listed write already stands); one corner: X's writes on a thing reached where X's class does not fall are seeds but not listed, and a remover's authority resting on one would apply R with no list. Build it with a test that reaches it.
2. **held-model and the order harness**: the gaps rule in held-model's role judgment, and an emphasis whose nodes write addenda (`order::under_test`, `local_peer_off` turn them off), so `held_set_decides` compares them; until then it checks nothing of them.
3. **An addendum vouches for a purge request as for content** (Tess: nothing argues for treating a purge specially, notes/principles.md, Deleting has no safe side; modelled: notes/purge-model.md, roles-model `purge_addenda`). Owed: spec/permissions.md §6 ("An addendum vouches for no purge request" goes), `purge_addenda` on in `Rules::fixed`, the walk and the engine's writing rule taking requests, the tests citing the old sentence.
4. **"Of its own"** (§5.2 Writing: a node writes an addendum where none of its own vouches): settle whose addendum counts once each node signs as its own node thing (accounts pieces 1 to 3): every node writing one, or one per account.
