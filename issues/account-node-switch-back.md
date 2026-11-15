# A node of the account that sided with the thief cannot come back
> Summary: A node of P that took a removed device's revocation first (spec/permissions.md §5.4, first-seen) holds no seed of the honest line, so it opens no inner signature there, reads every honest rotation as minted by no node, and a user's choice of the honest line cannot take; one whose own removal it took leaves the account for good. The model (roles-model `forks`) lets such a node switch back; the engine does not.
> Priority: critical
> Tags: security, perm, engine, tess-call

Design: notes/account-forks-design.md (Custody: seeds boxed to device keys, opened whatever counts; a node removed on the line it follows keeps custody while another held line keeps it). Root cause: judgment gates custody.

## What happens (engine)
- A node of P reads who minted each rotation from its inner signature, which opens only with the seed of the epoch it is signed at (§5.4, Following at a node of P). Seeds come from D's `account.0`, whose deltas count only where their rotation counts. A node following X's line never counts the honest rotations, so never takes their seeds, so never opens their inner signatures: to it the honest line is minted by no node and never stands, whatever its user chooses (`Engine::choose_line` holds, but the chosen line is disregarded).
- A node that took X's revocation of itself: where X's removal commit counts on D (its epoch open there) the node leaves the account (`signing::leave_if_removed`) and drops its seeds; where it does not, it stays on D's roster but its chain removes it (its signing pass now signs nothing, `rotations_due`). Either way its user's switch to A's line cannot bring it back.
- Bodies of rotations that do not count are dropped as invalid, so the seed is not even held to be read later.

## What the model does
`forks::signer_at` opens a node's inner signatures by the seeds its rotation's maker boxed to it, counting or not, and `settle` has the user of a node on X's side switch to A's removal, after which the node follows A's line, merges, lists its writes made on X's side. The engine differential (`rotation::tests_forks`) runs the settle without those switches; with them (`engine_agrees_with_forks_model_switching_back_spec_permissions_5_4`, ignored) it fails.

## Options
- Open inner signatures with any seed the node was boxed, counting or not: the node keeps (or refetches) the `account.0` deltas of held rotations it does not count and takes seeds from them for reading signatures only (never signing). Reading who signed leaks nothing the node was not boxed.
- Or a node on the other side is re-paired by an honest device after its user switches (a requirements question: the user sees "re-pair this device").
The first keeps the model's property (a user's switch holds at every node); it needs a design pass on seed custody (spec/crypto.md §9) and on what drops a non-counting rotation's body.
