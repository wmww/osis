# Epochs differential: the thief's own view of its self-re-add
> Summary: osis-perm `epochs_model_agrees_large` (OSIS_FULL=1) fails at shard seed 0x5005eed0e01 sample 86: observer X at tick 6, taken: model [11, 25, 26], perm [11, 25]. Chain (layer 1) only; at X's own view.
> Priority: low
> Tags: perm, tests

The world (roles-model custody, Random, removal #5 by A of X): X's rotation #25 (at the first epoch, removes B, takes C's removal of T #11) and #26 (at {1, 2}, X's own, removes B, re-adds X, takes #25). At X's own view at tick 6 the model takes #26 as a revocation, perm does not. Only the observer X differs, so no honest node's judgment is in question; one of the model and `osis_perm::Chain` reads a removed node's own re-add of itself (its addition in a rotation its removal hits) otherwise at that node.

Reached once layer 2 of `epochs` drew one more random number per world (covers), so other custody worlds reach the differential; not a regression of anything layer 2 does. Decide which side the spec (§5.4 Following, at a node of P: a removal hits a rotation minted by y unless ... it descends from a re-add of y) says, fix that side, and add the world as a hand test.
