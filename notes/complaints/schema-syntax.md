# schema-syntax
- Inline schemas in Rust tests come in many shapes (one-line strings with `\n`, `\n\` continuations, `concat!` pieces, `format!` fragments, `(from, to)` replacement pairs in evolution tests): no single grep finds them all, and a regex rewrite catches most but also rewrites deliberate negative tests. A failing `parse` in tests is the only reliable finder; review the diff of every test file touched by a scripted rewrite.
- `\n` inside a Rust string defeats `(?<!\w)` lookbehinds in rewrite regexes (the `n` is a word char): swap escapes for a placeholder first.
