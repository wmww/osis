# A rotator holding an epoch by snapshot alone lists a forged claim of it alone
> Summary: A rotation's keyset lists, per superseded epoch s, the valid settled rotation commits of s its rotator applied (spec/crypto.md §4). A rotator that holds s only by a `secrets.0` compaction snapshot holds none of s's pre-compaction claims, so if a writer's forged valid claim F of s reached it after compaction, its list for s is {F}: a node withheld R_s (and holding no snapshot) then settles e through F and re-seals e to the reader R_s removed.
> Tags: security, keys

Shape: as `valid_forged_claim_withheld_rotation_spec_crypto_4` (notes/crypto.md, osis-keys Chain), but e's rotator A joined from a compaction snapshot keying s, taken after R_s. Writer W signs F (keyset of s copied, listing nothing) after that snapshot; A applies F (valid, settled), removes W, rotating to e: list s: {F}. Node X, not compacted, holds everything but R_s: F is held and settled, so e is settled at X.

Not reproduced; needs a compacted rotator and a non-compacted node X fed by the attacker. Possible fix: the compaction snapshot carries, per epoch it keys, the valid settled claim IDs its writer held (an admin-signed record), and a joiner records them as listed claims of s without holding the commits, so its lists stay complete.
