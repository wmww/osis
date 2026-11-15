# A sibling's thing rotation and the listing that makes it count wait on each other
> Summary: Two nodes of P remove different nodes while apart; P's thing t has a holder outside P. Node 1's rotation of t (at its own P epoch Q1) counts at node 0 after the merge closes Q1 only by node 1's listing, which is on t and wrapped under t's newest epoch at node 1, which node 0 holds only once that rotation counts: node 1's writes on t are never read at node 0.
> Priority: critical
> Tags: engine, security

Shape: `rotation::tests_signing::sibling_removals_apart_both_hold_spec_permissions_3` with `world(5, 4)` (peer 4 an outsider granted write on t) in place of `world(4, 4)`, carried as labels do (`carry_sealed`), acting in turn.

What node 0 holds once settled (first 0; first 1 is symmetric):
- Node 1's rotation of t to n2, made when node 1 wrote after its removal (the knowing re-key), signed at Q1 and boxing P at Q1: held, not established (`est false`, no secret). The merge M closes Q1; node 0 cannot list it (Q0, made before it arrived, ends Q1 for the cutoff: Q1 is boxed to the node node 0 removed), so it counts only by node 1's listing answering M.
- Node 1's listing (a role commit on t, `listing.0`) and node 1's later re-key of t (wrapped under the n2 it supersedes): wraps shut at node 0. The listing goes under t's newest epoch at node 1, which descends from n2.
- w1 (node 1's write on t at Q1): shut at node 0.

The same class as the account rotation wrap (spec/crypto.md §5, an account's rotation): what makes an epoch count at a reader must open without that epoch. Candidate rule: a commit whose word (thing list, listing) names a rotation commit of a read role of the actor of the sync ID is wrapped, and its sections sealed, under the epoch that rotation supersedes; a listing's payload is commit IDs. Not built: it reaches past the account rotation (sections too, every listing), and the box to P at Q1 not opening at node 0 once Q1's seed is held may be a second cause.
