# A writer's junk read keyset swallows outside fires
> Summary: A writer may write the read keyset in `keys.0` (it rotates read), and no node but a holder of the epoch's secret can tell its KEM key is junk; a sealed fire or grant offer from outside is sealed to that key, taken as a Deposit (the sender sees it delivered) and opened by nobody.
> Priority: normal
> Tags: security, sync, keys

- Who: any writer of T (a demoted or removed one only until its write turns invalid). Observed by an outsider: nothing; its fire reads as delivered and never applies.
- `apply::keys::tests::bogus_keyset_drops_no_secret_spec_crypto_4` covers the holders' side (no secret lost); nothing covers the outsider's.
- Directions: holders of the epoch's secret derive the keyset (spec/crypto.md §4: `keys.0` vouches for no secret), so a reader can tell; a rule where a keyset whose KEM key does not derive from its epoch's secret counts for nothing must not hang on who holds the secret (verdicts held-independent). Or the sender seals to a key a held step commits to (steps are admin-signed), which an outsider holding `keys.0` only cannot check today.
