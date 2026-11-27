# Card staleness by signer roles: fork ping-pong and a demoted admin's inbox
> Summary: `flows::cards::stale` counts a card commit not held valid only for fields its signer "ever held" the role for (`validity::signer_role_ever`), but that reads grants the walk applied here, which differ across a fork: the two sides can rewrite each other's card every round. Separately, a demoted admin may write a card whose commits steer a stranger to an inbox it picks now. Also O(whole timeline) per call.
> Priority: normal
> Tags: engine, security, cards

## Fork ping-pong (confirmed by reading)
`roles_ever` and `key_role_ever` (core/perm/src/timeline.rs) walk the grants the walk applied. In an admin dispute, side Y's admin grants writer W, which W then uses to write a `keys.0` commit stamped after everything. At X, the grant is void, so W has no role and its commit counts for nothing. X's admin commit is newer than Y's admin commits, so the card is stale and X rewrites it with X's commits. At Y, all of X's commits count, and W's commit (it needs write) is newer than all of them, so Y rewrites. This repeats every round. Before 7931a8b40, the commits not held valid counted by their max `ts`, so this could not happen. The doc on `stale` ("the sides of a fork leave a card the other wrote newer") is untrue as built.

Fix direction: "ever held" must read the same on both sides of a fork. Compute it over every held edge write, applied or not (the option the removed review item assumed: "both sides of a fork hold both histories"), or drop the role filter and stop a writer's far-ahead commit from freezing admin fields some other way. Test: a two-sided fork with W granted on one side, then `refresh_cards` quiet over two rounds on both.

## A demoted admin's card (suspicion)
An admin of A demoted to writer may still write a card on a path through A. The card can carry A's honest commits, the `roles.0` commit that once made it admin, and a `keys.0` commit it signs now, stamped slightly ahead, that sets the inbox. Honest nodes count that commit for admin fields (its signer ever held admin), so they never find the card stale. A stranger taking only the card's commits (`take_holder_keys`, core/engine/src/sync/stranded.rs) learns the grant but not necessarily the demotion, so it may judge the inbox commit valid and fire at the attacker's inbox. To settle: check whether a card's holder keys force the removal onto the stranger's chain; if not, the bound "an inbox an admin once validly chose" fails.

## Cost
`signer_role_ever` is O(every edge the timeline holds) per call (`roles_ever` iterates every `into` edge). `stale` calls it per card commit not held valid, and `take_holder_keys` per `keys.0` part per retry round. Walk only the signer-to-thing paths instead.

## Also
- A commit `take_holder_keys` leaves out (its signer's role not held yet) is not pended. It is taken only when the card is taken again, so what is taken depends on arrival order.
- A writer's far-ahead commit freezes the writer fields (its keysets, box records) until its `ts` (notes/public-and-cards-brief.md, Left).
