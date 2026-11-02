# chainless-parts
- Five tests made a commit "pending for good" with a part on a thing nobody has the record of. That was the very behaviour being fixed, so they all fell over at once, and no real wait could replace it (issues/pending-grant-unreachable.md). A device that names the wait it relies on would have shown this sooner.
- `grep` for `repro_` tests prints the whole judged dump on failure: cut the output.
