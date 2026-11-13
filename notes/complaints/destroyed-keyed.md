# destroyed-keyed
- Checking that a new test fails without the fix by reverting one function gave a false pass: the fix spans `keyed` and the taint helper, which read one rule. Reverse-apply the whole non-test diff (`git diff -- <src files> | git apply -R`) instead.
- Depth0's `MaxBlind` bounds boxes past the model's true key access (`TExp`), so a negative control for a key-access rule needs `MaxBlind >= 1` or the old rule's box is never made and the control passes silently.
- Review: editing sources while a background `cargo test` is still compiling leaves unclear which version the run tested; finish edits first, then start the run.
