# eph-paging
- A failing `assert_eq!` on multi-MiB strings printed 15 MB of test output: compare large values by (key, length, hash), as `ephemeral::shape` does.
- `cargo test -p X --test it a b c` refuses several filters: they go after `--`.
- Memory weighing has no blob size accessor (`CipherTx` reads whole blobs only): `page_bytes` reads each page to count its length.
