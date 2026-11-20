# split-form review
- The brief expected two keys opening one AEAD entry to be infeasible; Poly1305 is linear, so it takes a test helper of ~100 lines (`validity::entry_under_two_keys`) and a `Keystream::poly_key` accessor. Worth knowing for every "a key that opens it" rule.
- `LocalPeer` plaintext packages carry every path key; `LocalPeer::sealed`/`deliver_sealed` is the way to test what a reader's own encryptions give it (notes/test-harnesses.md names it only for "who can read" claims).
