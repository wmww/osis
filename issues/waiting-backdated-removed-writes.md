# Waiting counts a removed node's writes backdated to an older epoch
> Summary: Waiting (spec/permissions.md §5.5) counts P's commits on D at any closed epoch none of whose closers decides on D at the node; a node removed at epoch e_k can sign on D at an older epoch e_j it held, and at a sibling holding e_j's closer without its D list (a new or catching-up sibling, the rotation from a Prove's rotations or a header-only copy) the write counts until the list arrives. Unchecked whether that transient count can make the sibling act lastingly (box or re-seal to the removed node).
> Priority: normal
> Tags: engine, security

- Without Waiting the same window reads every commit at e_j unlisted (the sibling leaves); with it, every commit at e_j counts, the removed node's backdated ones too. The removal's own rotation decides at once (field 15), so only epochs before it are open to this.
- To settle (Fathom: engine judgement): can a commit at e_j order after the removal on D's timeline (parents, key order), and does anything a node does while a commit counts outlive it (re-seal, seed boxes, a grant it signs on that roster)? If either is no, close this with that reason in notes/engine-validity-epochs.md.
- Shape to test: nodes 0, 1, 2 of P; rotations r1 (plain) then r2 (node 0 removes node 1); node 1 signs a grant of itself on D at r1's closed epoch; node 2 holds r1 without its D list (and r2 whole): does the grant count, and does node 2 box anything to node 1?
- Custody's rule (e) (issues/sibling-removal-rotation-before-list.md) does not close it: it changes leaving, not what counts.
