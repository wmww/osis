# A commit holds at most about 6 500 things
> Summary: spec/requirements.md Decentralization: a commit may touch any number of things, with values of any size. The build keeps a whole commit in one blob of at most `MAX_BLOB` (spec/wire.md §4): about 150 000 small changes on one thing, or about 6 500 things; a larger write is refused.
> Priority: low
> Tags: commits, wire, spec

notes/whole-commits.md (Strip, Sizes) has the figures. Either the one-blob rule gives (a commit's parts spread over blobs while staying atomic at each reader), or the requirement is stated as the bound that is acceptable; the second needs Tess. A write that is refused for size must say so in the app's terms (a write is one commit or is refused, spec/requirements.md API).
