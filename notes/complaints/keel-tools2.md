# keel-tools2
> Summary: Mishaps building policy.py --baseline and tools/deprecated_probe.py.

- `git checkout-index -a` under a scratch `GIT_INDEX_FILE`/`GIT_WORK_TREE` fails (128) unless run from inside that work tree; the error is silent with captured output.
- rustc names deprecated uses by visible path (`osis_blob::BlobWriter::<'a>::new`, enum variants and tuple fields as their own items), so matching by the declaring module misses re-exports; a `#[cfg(test)]` line is often a `mod tests;` declaration at a file's top, not the start of a test region.
- The gate runs plain `tools/policy.py`, so while main is red every gate fails at policy; it was left as is (`--baseline` there would let a branch land red silently).
