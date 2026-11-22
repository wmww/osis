# osis-cleanup-2
> Summary: footguns met while trimming the osis crate (second pass).

- `tools/loc.py` moves little for a dedup that names a concept (`ReadAs` cost 10 lines to replace a dozen hand-built readers): the line count undersells merges of knowledge, as it oversells deletions of doc comments.
