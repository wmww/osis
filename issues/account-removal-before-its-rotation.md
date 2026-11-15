# A removal acts on D before its rotation is held
> Summary: At a node of P that has not taken A's removal of X, X's removal of an honest node counts on D's timeline by the epoch rule even while the rotation carrying it is not held (it takes a rotation X withholds), so the node drops that node from D's roster, re-keys D without it and boxes its later rotations away from it; the chain does not count the revocation. The model reads D's roster from taken revocations only.
> Priority: critical
> Tags: security, perm, engine

## What happens
- X revokes A with a rotation taking a rotation it never sends: by spec/permissions.md §5.4 the rotation is held nowhere, so no one follows or answers it. Its removal commit on D still counts at an unaware sibling B (X is a node there, the epoch open): `key_holders(D)` loses A, B's next rotation re-keys D boxing everyone but A (X included, the unaware-sibling limit), and A cannot merge B's heads until B merges A's; another node of P that took A's removal cannot take up B's seed (B's D epoch rests on X's removal, cut there).
- Not always transient: a node that took A's removal cannot take up the seed of a rotation B made so (its D epoch rests on X's removal, cut there), so it reads B's later rotations as minted by no node, disregards and answers each, while B merges each answer: the two rotate against each other for good (`OSIS_FORKS_START=916629000175 OSIS_FORKS_SEEDS=1` on `rotation::tests_forks::engine_agrees_with_forks_model_large_spec_permissions_5_4`, listed in tools/known_failures.txt; the model, fed the seeds the engines took up, does the same).
- Otherwise transient: once B holds A's removal it takes it, X's commits on D are cut, A is back on B's roster. No seed reaches X that the unaware-sibling limit does not already give it.
- Making a removal of another node count only as part of a taken revocation (D's roster equal to the chain's view) was tried: a node's own removal must count before its rotation exists (the rotation's seed goes under D's re-key, which reads the removal), and other nodes' judging then needs the D re-key and the chain taken in one fixpoint; ten engine tests stalled. Needs a design pass with the sibling-removal wrap (spec/crypto.md §4).

## Where it shows
`rotation::tests_forks` excuses the honest-node half of D's roster check and skips the act comparison and the seed check where the node holds such a removal (`Run::bare_x_removal`).
