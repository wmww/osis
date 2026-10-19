# Crypto vectors
> Summary: Known-answer vectors from osis-crypto (provisional format until the test-infra runner fixes one). Generated and checked by crates/osis-crypto/tests/vectors.rs.

Each file is one JSON object: `spec` (sections checked), `comment` (conventions for the file), `cases` (array). A case is an object with `name` and named fields:
- byte strings are lowercase hex; numbers are JSON numbers; other strings are descriptions (e.g. `form`, `payload` written as CBOR diagnostic with `xx*n` meaning n bytes of xx);
- a case with `"expect": "error"` must be rejected; `error_class` is the class (BadInput, Parked);
- randomness a computation consumes is listed as fields (`ephemeral_x25519_private`, then `mlkem_encaps_randomness`; a blob's `blob_key`), in the order it is drawn.

Regenerate: `OSIS_WRITE_VECTORS=1 cargo test -p osis-crypto --test vectors`. Without the variable the test fails if a file differs, so a change to any vector is a visible diff.
