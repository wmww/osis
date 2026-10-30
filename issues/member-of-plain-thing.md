# A valid member of a thing left plain by an invalid keyset reads nothing new
> Summary: when the only keyset write on T turns invalid (removed admin A's rotation), a valid grant B made meanwhile under A's epochs leaves T plain with a non-owner member Z; nothing gives T secrets of its own again until someone grants on it, so Z cannot read T's new content.
> Tags: engine, permissions

Case: test `valid_grant_under_invalid_keyset_leaves_thing_plain_spec_crypto_3` (apply/keys.rs). T is plain at every node (encrypted under its owner's derived epochs, safe: only owner-chain readers), but Z holds only B's boxes at A's (reading-only) epochs. `own_secrets`/`give_own_secrets` run only on grants and moves. A fix likely has an admin node rotate T from derived epochs (spec/crypto.md §3) when it sees a current non-owner member of a thing with no valid keyset part, boxing every current member; it must be order-independent (several admins may do it concurrently: concurrent rotations are fine).
