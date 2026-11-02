# chainless-parts
- Five tests made a commit "pending for good" with a part on a thing nobody has the record of. That was the very behaviour being fixed, so they all fell over at once, and no real wait could replace it (issues/pending-grant-unreachable.md). A device that names the wait it relies on would have shown this sooner.
- Review: `--include-ignored` with a filter matching `judgment_vectors` runs `judgment_vectors_write`, which silently rewrites the vectors from whatever is built. Under a test mutation that pinned the mutant, and `git add -A` committed it; cost an hour of false alarm. A write test should need an env var too.
- Review: `cargo test` timings of pending work mean nothing in debug: `check_unchanged` examines everything left out, so a 550x regression showed as 1.5x until `--release`.
- `grep` for `repro_` tests prints the whole judged dump on failure: cut the output.
