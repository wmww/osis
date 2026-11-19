# Blob link URL bound untested at the bound
> Summary: Both `MAX_URL_BYTES` checks in core/blob/src/link.rs survive `<=` to `<` (osis-blob's tests): no test has a URL of exactly `MAX_URL_BYTES`.
> Priority: low
> Tags: tests, blob

Add a case at exactly the bound (accepted, and dialable) and one byte past it (refused) for both the decode and the dialable filter.
