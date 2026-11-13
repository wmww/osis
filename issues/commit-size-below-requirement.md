# How large may one commit be?
> Summary: Tess asked for "up to about a million changes" per commit; the build fits one commit in one 8 MiB blob, about 150 000 changes on one thing or about 6 500 things. spec/requirements.md states the build's numbers. Question for Tess: raise the limit by design, or keep the line as it is.
> Priority: normal
> Tags: tess-call, spec, commit

**Question for Tess.** A commit is one blob of at most 8 MiB. That holds about 150 000 small changes on one thing, or about 6 500 things changed at once (each thing costs about 1.3 KB of keys and framing). Values of any size are fine: large values live in their own blobs. Your line asked for about a million changes. Should we:
1. **Raise the limit by design**: split a commit's parts across several blobs that the commit blob links (as a long header list already is), still applied whole or not at all. Moderate work in the commit format, sync and apply; the limit then comes from the list bound, not the blob size.
2. **Keep the reworded line** (spec/requirements.md says "about 150 000 changes on one thing, or about 6 500 things").

Measured (osis-commit builder, small register deltas): one thing, n aspects, about 38-41 B per change (150 000 fit, 200 000 do not); n things, one aspect each, about 1 280 B per thing (6 500 fit, 7 500 do not). Rule: spec/wire.md §4 ("the whole commit stays within `MAX_BLOB`"). Existing test: `many_writes_per_thing_fit_one_blob`.
