# eph-paging
- A failing `assert_eq!` on multi-MiB strings printed 15 MB of test output: compare large values by (key, length, hash), as `ephemeral::shape` does.
- `cargo test -p X --test it a b c` refuses several filters: they go after `--`.
- Memory weighing has no blob size accessor (`CipherTx` reads whole blobs only): `page_bytes` reads each page to count its length.
- (review) A probe of a fix in a test binary: `BLOB.ak()` needs `osis_schema::RawKey` in scope; the compiler hint names the import, but a whole `it` rebuild per try costs about 80 s.
- (rebase onto 3h1) The coordinator said "main" moved, but the commit was on origin/main only; local `main` lagged: `git fetch` and rebase onto `origin/main`.
