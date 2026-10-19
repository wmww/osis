# Header-list chunks cannot carry every token commitment of a large commit
> Summary: spec/crypto.md §7 gave header-list chunks one commitment per token secret of the commit, which is unbounded for a commit touching many things; spec/wire.md §5 caps prefixes at 16 and gives such chunks only the author-chain tokens when the commit has more than 16 (provisional). Owner accepted (a) for the MVP; the 16 cutoff is arbitrary, find a better design post-MVP (with issues/token-admin-secret.md).
> Tags: sync, crypto, post-mvp

A header list goes by link only when it exceeds `CHUNK_THRESHOLD`, i.e. commits touching thousands of aspects; their token secrets (an admin and a write secret per thing) number in the thousands, while every wire object needs a fixed maximum size.

Options:
- (a, provisional) all commitments when the commit has at most 16 tokens, else only its level-2 (author-chain) tokens: the author deletes its own header lists at servers; thing admins who are not label admins cannot, and the label delete key or convergence by an admin cleans up.
- (b) no commitments on header-list chunks above 16 tokens: only label delete keys delete them.
- (c) re-encrypt header-list chunks per projection, each with that projection's tokens (at most 3): bounded and complete, but header-list chunks multiply by the projection count and stop being shared by the commit's projections.

Recommended: (a). Header lists hold hashes and tids only, readable to anyone holding a projection anyway.
