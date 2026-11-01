# Unit ciphertext lengths reveal the length of dropped content
> Summary: Store rows are `nonce || AEAD(plaintext)` with no padding, and row names (`u slot ver`) are plaintext, so an attacker reading freed backend pages (redb free pages are inside the db file) sees every version of a unit with its exact length and can line versions of one slot up in order. The length difference between the versions before and after a shredded drop is the encoded length of what was dropped: enough to confirm a low-entropy guess of purged content ("yes" vs "no thanks"), against spec/requirements.md Deletion ("No fingerprint ... however low-entropy"; forward secure). Holds on every root tier.
> Tags: security, store

## Where
`core/store/src/pager.rs` `seal` (no padding); `unit_row` names. Pages (`btree`) are at most `page_max` but vary with content; overflow values (above `page_max/4`) get a unit of exactly their length.

## Scenario
A register holding "yes" inline in a catalog page; purge it (Shred::Yes). The page slot's old version (ciphertext under an erased key) stays in a redb free page beside the new version; both lengths are readable, and the names give slot and order. Difference = encoded "yes" entry length. A large value's overflow unit shows the value's exact length outright.

## Suggested fix
Pad unit plaintext before sealing: table pages to exactly `page_max` (pages are bounded by it; costs up to ~2x page storage), other units (overflow values, catalog-sized records) to a size bucket (e.g. next power of two or a fixed-ratio ladder; bucket choice per notes/arbitrary-values.md). Padding inside the AEAD, length recorded in the plaintext. Optionally pad memory-irrelevant tree nodes too (their length reveals unit counts only). Then a forensic test: lengths of all historic rows of a slot are equal before and after a shred.
