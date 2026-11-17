# keel-whole-commits
- read acts only on what a judgement adds (`now.acts.difference(&before)`): a Log already in the previous judgement's acts is silently not run again, so "drop the stale entry and Log" lost the body with no error. Cost an hour of print debugging; the strip is one `Act::Rewrite` for that reason.
- The harness's quiet checks (`unlogged_must_holds`, `unreached_must_holds`) say which (node, S, commit) failed but nothing about its blobs or parts; I added throwaway prints each time.
- A `--test-threads` default run interleaves `eprintln` probes of tests sharing a fixture: label them or run with `--test-threads=1`.
