# forget-unknown review
- A restart test of a forgotten released thing found it coming back: `name_after_crash` re-ingests held entries of commits forgotten whole or with marked parts. Tests that forget and never restart miss this class; a restart step belongs in every forgetting test.
- `local_rows_naming` over a never-held thing found PURGES/VALUELESS rows left by a request that went; checking only the forgotten thing's own tid missed it.
