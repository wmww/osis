# kestrel-docs-cleanup
- A check for dead symbols in notes needs prefix matching: tests are cited without their `_spec_...` suffix, so exact grep reports dozens of false dead names.
- Code comments cite issue step numbers (issues/durable-decode-bound.md step 3, retention-modes step 0), which keeps finished plan text alive in issues; a Markdown-only pass can only keep a step legend.
