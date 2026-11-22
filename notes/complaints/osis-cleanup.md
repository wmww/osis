# osis-cleanup
> Summary: footguns met while trimming the osis crate.

- `tools/loc.py` counts no doc comments, so the crate's largest repetition (compile_fail doc tests, nine setup lines each) is invisible to the line count; a fixture moving it into `internals` raises the count.
- `tools/dup_windows.py` finds almost nothing in core/osis: the duplication left is structural (same shape, different names), found only by reading.
