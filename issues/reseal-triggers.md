# Re-seal: members no automatic trigger reaches when their deposits are refused
> Summary: After two rounds of model-checking fixes (a removal travels in its rotation; established epochs make re-seal decisions order independent; rotation commits are uploaded before the step; stranded heartbeats also on a refused claim; deposit-seed refresh is a MAY) one residue remains for the owner: a member whose deposits are refused (seed refreshed, or budget full) or that cannot deposit at all has no automatic re-seal trigger and depends on a human. Within spec/requirements.md's accepted limits for re-seal ("triggered, never guaranteed"). Owner to pick: accept for the MVP (recommended) or add a mechanism.
> Tags: owner-call, permissions, sync

## Background
TLC (models/tla/rotation, R2; `MC_drop_refresh.cfg`) found: a member whose next step's claim set the server dropped can neither walk to the head nor, when the deposit seed was refreshed since it last read `/keys`, place its stranded heartbeat, so nobody re-seals it. The wrongful re-seal residues of the first round (a fork-merging or later rotation read out of order, `MC_reorder.cfg`, `MC_fork_reorder.cfg`; a secret handed out by re-seal before its commit, `MC_hist.cfg`) were closed in the second round without a wire change: spec/crypto.md §4 established epochs (a rotation counts only with the rotation commits of everything it supersedes, or a `/secrets` snapshot for a compacted chain; history boxes and re-seals carry established secrets only), spec/permissions.md §3 (re-seal at chain-established epochs at the end of a complete pass), spec/sync.md §5 (the rotation chain is uploaded before the step). Rationale: notes/permissions.md (re-seal), notes/crypto.md (history boxes, opening), notes/sync.md (rotation commits before the step; Limits for the accepted post-compaction residue).

## Residue: refused stranded heartbeat
A member that reaches a refused claim places a stranded heartbeat by deposit. The deposit is refused when the admins refreshed the deposit seed since the member last read `/keys` (a MAY), or when the label's budget is full. Then no automatic trigger exists: the member is boxed at every epoch it is listed at (no "missing box") and heartbeats nothing. It is reached only when a human asks a co-member to re-seal (the client offers it), or through a direct connection to a co-member that may rotate.

Options:
- (a) Accept: within spec/requirements.md "re-sealing is triggered, never guaranteed"; the recommended default is not to refresh the seed except against abuse, and clients offer "re-share with M" by hand.
- (b) Claim events in the label log: the server logs a verified claim (step ID, slot) and admins map the slot to the member through the claim set they hold in `/label`, re-sealing claimants whose next rotation is compacted. Reliable and deposit-free; cost: a new log event kind (wire); the server learns nothing new (it already sees which slots claim).
- (c) Servers keep claim sets for the whole path (32 B per padded reader per step, never dropped): the walk always reaches the head, where the member can at least open and download; the heartbeat problem stays.

Recommendation: (a) now; (b) is the right mechanism if stranded members turn out common.

## Conservative reading meanwhile
Implement the spec as edited. Clients: offer "re-share with M" by hand to any member that may rotate; do not refresh the deposit seed on rotation by default. notes/sync.md Limits records it.
