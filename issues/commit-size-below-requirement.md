# A commit holds far fewer changes than the requirements line says
> Summary: spec/requirements.md says a commit holds "up to about a million changes, of values of any size" (Tess). Values of any size hold (nothing lists a value's blobs), and the aspect list allows about 950 000 deltas, but the whole commit is one blob within `MAX_BLOB` (8 MiB): about 190 000 changes on one thing, about 6 500 things. Raise the bound by design, or reword the line.
> Priority: normal
> Tags: tess-call, spec, commit

Measured at the chunk-tree-4 branch (osis-commit builder, register deltas of a few bytes):
- One thing, n aspects: the writer's bound (`blob_bound`) is about 38-41 B per change; 150 000 fit (6.3 MB), 200 000 do not.
- n things, one aspect each: about 1280 B per thing (a section per thing, its chain bounded at `MAX_CHAIN_DEPTH`, its wrap and AEAD); 6 500 fit (8.38 MB), 7 500 do not. Existing test: `many_writes_per_thing_fit_one_blob` (2500 things of three writes).
- The rules: spec/wire.md §4 ("The whole commit stays within `MAX_BLOB`": a writer pages its deltas and refuses a commit that still does not fit). Paging bounds each delta's root, not their number, and every part and section sits in the one commit blob.

What a fix would be (not designed): parts or sections of a commit in blobs of their own (a section per blob, or the commit blob linking its sections as a header list does), keeping "one commit, applied whole or not at all"; or a larger `MAX_BLOB`; or the requirements line stating the bound as it is ("up to about a hundred thousand changes"). Tess's call: which.
