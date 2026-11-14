# Rename the "person" leftovers to "account"
> Summary: the account actor is "account" everywhere public and in the engine's API; "person" for it remains in test helpers (engine `it` `validity.rs` and `finalize.rs` `persons`, keys `it` `common::person`), osis `share.rs` `person_links` and a few engine comments (`labeling/blobs.rs`, `retention/purge.rs`, `rotation/lost.rs`). Rename them; nothing ties an account 1:1 to a human (Tess).
> Priority: low
> Tags: naming, tests

The app's **Person** kind (an address-book contact) is another sense and stays (issues/deprecated-terms.md).
