# Who can delete a huge commit's index chunks at a server
> Summary: A commit that touches thousands of things stores its header index as extra chunks at servers. Today the author and the sharing group's admins can delete those chunks there; an admin of one touched thing who is not a group admin cannot, and waits for a group admin's cleanup. Closing that gap costs either more bytes per large commit or chunks nobody but the group can delete. Owner accepted the current rule for the MVP; a better design is post-MVP.
> Tags: sync, crypto, post-mvp

## The decision (user terms)
Only commits touching more than 16 things are affected (an ordinary write never is). For those, the question is who can wipe the commit's index chunks from an untrusted server:
- **Keep today's rule** (accepted for MVP): the author and the group's admins can; a thing admin who is not a group admin has to ask a group admin. The chunks hold hashes and ids only, readable by anyone who can read the commit anyway, so nothing leaks while they wait.
- **Per-reader copies of the index**: every thing admin can delete, but the index chunks are stored once per readable subset of the commit (two to three times more index bytes for big commits) and are no longer shared between those subsets.
- **No thing-level deletion of index chunks**: simplest rule; only the group's delete key removes them.

Recommended: keep today's rule unless a deployment shows thing admins routinely needing to clean servers they are not group admins of.

## Technical details
spec/crypto.md §7 gave header-list chunks one commitment per token secret of the commit, which is unbounded for a commit touching many things; spec/wire.md §5 caps prefixes at 16 and gives such chunks only the author-chain tokens when the commit has more than 16 (provisional). A header list goes by link only when it exceeds `CHUNK_THRESHOLD`, i.e. commits touching thousands of aspects; their token secrets (an admin and a write secret per thing) number in the thousands, while every wire object needs a fixed maximum size. The linked-list case is `vectors/commit/headers.vec`.

Options as specified: (a, current) all commitments when the commit has at most 16 tokens, else only its level-2 (author-chain) tokens; (b) no commitments on header-list chunks above 16 tokens; (c) re-encrypt header-list chunks per projection, each with that projection's tokens (at most 3). The 16 cutoff is arbitrary. Related: issues/token-admin-secret.md.
