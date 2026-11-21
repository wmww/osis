# review-own-demotion
- Undoing a fix by `git checkout origin/main -- <product files>` rebuilt the whole engine lib test binary (~4 min); a mutation flipping one `if` costs the same. No way around it, but plan probes to batch several in one build.
- Unsafe-direction mutation (keysets ignoring `demotes`) was caught only by a structural assert inside an ignored property; no default test observed it. Added `own_demotion_keyset_held_only_with_its_own_edge_writes_spec_crypto_4`.
