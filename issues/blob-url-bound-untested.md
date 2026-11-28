# Blob link URL bound untested at the bound
> Summary: The `MAX_URL_BYTES` checks in core/blob/src/link.rs (a URL's decode, the dialable filter, `peer_url`'s length) are tested only past the bound (257 bytes): no test has a URL of exactly `MAX_URL_BYTES`, so `<=` to `<` survives.
> Priority: low
> Tags: tests, blob

Add a case at exactly the bound (accepted, and dialable) and one byte past it (refused) for each check.
