# S3 build: what addenda still owe
> Summary: What is left of S3's addenda (spec/permissions.md §5.2 Addenda) once osis-perm's addenda gaps and the engine writing addenda by the state rule are built: the remover's leaving out (A1), held-model and the order harness playing addenda, the §5.5 reading of admin-only content, and the questions a builder would otherwise guess.
> Priority: normal
> Tags: perm, engine

Spec: spec/permissions.md §5.2 Addenda (Writing, admin-only), §5.1 Frontier. Oracle: roles-model `addenda::GAPS` (core/test/roles-model/README.md, Addenda gaps). Plan: notes/redesign-plan.md S3.

## Built
- **Addenda, the window, the gaps, the triggers**: notes/addenda.md (Rules), notes/engine-roles.md (Write: what makes a removal due again, and why nothing is missed). Tests `apply::tests_addenda` (window, granted after R, admin-only kept by an admin witness and not by a writer's, an edit applying late), `disputes::a_fights_leaving_out_costs_a_write_the_same_at_k_and_10k_candidates`; perm `differential::addenda_model_agrees` on `addenda::GAPS`.

## Left, in order
1. **The remover's leaving out** (notes/account-membership-design.md §4, The list): not in spec/permissions.md §5.1 Frontier; for stage A1, where the list becomes a leaf per thing. With today's writer rule it would change nothing reachable: the engine writes R only where its author holds the authority at R's key in its own walk, in which every received write it lists already stands, and a listed write is neither audited by R nor one of R's seeds; trusting R adds only R's seeds, unlisted writes, which leaving out cannot help (one corner: X's writes on a thing T reaches where X's class does not fall are seeds but not listed; if the remover's authority rests on one, R trusted applies with no list at all, and the per-entry rule would leave out everything). Build it in A1 with a test that reaches it.
2. **held-model and the order harness**: the gaps rule in held-model's role judgment, and an emphasis whose nodes write addenda (`order::under_test`, `local_peer_off`, `setup` turn them off), so `held_set_decides` compares them. Until then `held_set_decides` checks nothing of them.
3. **Addenda against a rotation and admin-only content** (spec/permissions.md §5.5 reads "plain content (§5.2)"; §5.2 lets addenda list admin-only content for a witness holding admin): the engine's epoch-rule addenda (`validity::plain_part`, `signing::answer_rotation`) still leave admin-only content out. Decide the reading and make §5.5 say it.

## Questions a builder would otherwise guess
- **"Of its own"**: a node acts as its account; read "no addendum of its own vouching" as authored by its account, so sibling nodes do not each write one once one vouches. The node that wrote R is excluded, its siblings are not (the model has one node per account).
- **The candidate list** per (R, N) (X's content in R's window, not in R's frontier) is fixed once R is held (a commit applying after makes R due again, `note_applied`): receipt times are recorded per commit. Kept while R is held; growth is per removal per witness, as the addenda themselves.
