# Account forks: custody, roster, canonical merges
> Summary: Design closing the account-fork problems (a node that sided with the thief cannot switch back, a bare removal acting on D, a thing listing wrapped under the epoch it decides, the merge storm): custody of a secret follows the boxes held and never a judgment; D's roster, keys and removals are P's chain; a merge's epoch is a pure function of the tips it joins. Not built; modelled in roles-model `custody` (every property holds, every negative control fails).

Tess's rule this serves (spec/permissions.md §5.4): every node, the account's and outside readers, follows the first device revocation it sees; a counter-revocation raises "account forked"; the user may switch sides and a switch sticks; nothing switches back by itself; D's roster is never an input of the side.

## The wrinkle
Two decisions make all four problems.

1. **Judgment gates custody.** A secret a judgment needs to read its evidence opens only after that judgment counts:
   - P's seeds sit in D's `account.0` under D read epochs, which D's timeline establishes, which the epoch rule judges, which reads P's chain, whose side reads inner signatures, which open with seeds. Every engine fixpoint on this path (`rotations_due` taking seeds up as each opens the next D epoch, the account-rotation wrap exception, "counts once its inner signature opens") is this cycle. A node on the thief's side never counts the honest line, so never opens its seeds, so reads it as minted by no node: the switch cannot take (issue account-node-switch-back).
   - A thing epoch is read only once its rotation counts (boxes at a closed account epoch are stale, a secret from a commit not counting is not established), while the listing that makes it count is wrapped under an epoch descending from it (issue sibling-thing-epoch-listing-cycle).
2. **D is a second source of the roster.** D has its own role timeline and key schedule, judged by the epoch rule, beside the chain's taken revocations. A removal is a D role commit apart from the P rotation carrying it, so it can act on D's roster and re-key D while its rotation is not held, and the two sources disagree (issue account-removal-before-its-rotation). Fixing the roster to the chain alone stalled only because the seed sits under D's re-key, which reads the removal: decision 1 again.

The merge storm is a third, separate decision: **a merge carries its maker's choices** (a random seed, its takes and answers, its list), so two nodes merging the same heads mint two epochs, which fork again.

## Principles
- **Custody follows holding.** A node reads with every secret it can open from what it holds (a box to its own key, a seed or secret derivable from ones it holds), whether or not the commit carrying it counts or its epoch is open or stale. Judgment decides only what counts and what the node uses (signs at, encrypts under, boxes to others). So judgment is a function of held commits alone, never of a fixpoint with keys.
- **The chain is the roster.** At a node of P, who is a node on a line is read from P's rotations alone: D has no timeline of its own for membership and no key schedule of its own.
- **A merge is a join, nothing more.** Its epoch is a pure function of the tips it joins; anything else a node has to say goes in a plain rotation.

## Design
### Custody
- A rotation boxes its new seed to the KEM key of each device on its roster, in its D section (sealed under the D read secret of the epoch it is signed at, below). Any node holding a seed may later box it to a roster device lacking it (a seed re-seal, the existing re-seal rule applied to seeds). A device holds a seed iff it holds such a box to itself or derives it (Merges), whoever wrote the box and whether or not its rotation counts.
- An inner signature opens with the seed of the epoch it is signed at or of the epoch the item mints; a merge certificate's with the seed of any epoch it joins. So a node of P reads who minted every rotation boxed to it on any line, and its side is a function of held rotations and its user's choice.
- A node signs at, rotates from or boxes only a seed of an open epoch it follows on which it is a node. Holding a line whole (with what it takes) already holds every removal on it, so "takes up a seed only where it holds every removal its writer held" is structural.
- Every box a node can open is opened for reading: a box to P at a closed or not-open epoch, a box in a commit that does not count (the reading-only rule, spec/crypto.md §4, widened to stale boxes). Stale still means "do not encrypt under, re-seal or rotate"; it never means "unread".
- A node removed on the line it follows keeps its device key, its seeds and D's sync IDs while any held line keeps it a node (the warning stands, its user may switch); it leaves (drops seeds and what it read as P) only when no held line keeps it.

### Roster and D
- D's secrets derive from P's epochs, as a plain thing's from its first admin (spec/crypto.md §3): D read at P epoch e is `kdf("thing read", e's read secret, D's tid)`. D never rotates on its own; a P rotation re-keys D.
- Every change of D's membership is carried by a plain P rotation: its D section holds the removals and additions (a pairing is a rotation adding the device; a rotation's history box gives the new device the seeds its adder holds). No removal or grant exists apart from its rotation, so nothing acts on D before its rotation is held.
- Nodes on a line: the devices the creation record names, plus additions, minus removals, carried by rotations on the line. A removal of y carried by r hits every rotation minted by y that is not on r's line (made before it), unless it descends from a re-add of y on a line descending from r. A taken revocation from another line hits as now (spec/permissions.md §5.4). An addition by a removed node is in a rotation the removal hits, so it adds no one: forged and backdated grants, Z, and a grant at an unaware sibling's epoch need no rule of their own.
- D's roster at a node = the nodes of its preferred head's line under the taken revocations. The epoch rule never reads D for membership.

### Merges
- A **plain rotation** carries removals, additions, `takes`, answers (rotations it supersedes unnamed) and a fresh random seed, and names no fork. A **merge** carries nothing but the join.
- A merge's **tips** are the plain rotations maximal on the union of the lines it joins. Its seed is `kdf("merge seed", tips' seeds in epoch-name order)`, so its keys and epoch name (`[height, signing key]`, spec/crypto.md §3) are a function of the tip set. Structures name epochs by epoch name, not by the minting commit's ID.
- A merge commit is one **certificate** of that epoch: signed at a joined epoch, with each joined epoch's merge signature over the epoch name, the maker's inner signature, and seed boxes to roster devices that cannot derive the seed (a device added on one branch). Several certificates of one epoch are one epoch: not beside each other, closing the same epochs. The epoch counts iff some certificate of it is followed; a certificate minted by a node a taken removal hits stands with nothing.
- Who can derive a merge seed: exactly the holders of every tip's seed, the intersection of the joined lines' custodies. A node aware of a removal merges only heads one of which carries it, so the removed node lacks that tip's seed and the merge's; a node that would have to merge lines lacking a removal it holds makes the plain rotation first.
- Policy, any node of P, at the end of a complete pass of D's sync IDs: if it owes a plain rotation, make one at its preferred head; then, if it follows more than one head and holds every tip's seed, make the merge of all of them; re-seal its heads' tip seeds to roster devices it holds no box to them for. It owes a plain rotation for:
  - a removal or an addition it makes;
  - an answer: a held rotation that does not stand under its taken revocations or stands with one it did not take, on no line a counting rotation answers, that it has not answered (a rotation waiting only on its parent epoch is owed nothing);
  - a taken revocation its preferred head's line does not carry (on it, or taken by a rotation on it), only while it cannot make the merge: a taken revocation counts, so some head carries it, and the merge of all heads carries it.

### Why this ends the storm by structure
- Plain rotations are made only for carried content, each at most once per node per event (removal, addition, taken revocation, answered line). A merge creates no plain rotation. So the plain rotations of a run are finite, and merge epochs are subsets of them.
- Two nodes holding the same plain rotations make the same merge epoch, in lockstep or not; once every node of P holds them all, every node has one head. No timing, no designated merger, no wait on any one device: any node holding the tips' seeds makes it, and a second certificate is harmless.

## Properties
At every node and every prefix of its receipts, on top of roles-model `forks`'s (revocation holds, no flip, no false alarm, seeds stay away from X, settled):
- **Custody is monotone.** The secrets a node can open only grow with what it holds (but for its own leave); no secret's custody waits on a judgment.
- **A switch takes.** After a user's switch to a held line on which the node is a node, the node follows that line, signs at its head, and counts every honest write on it, whatever it followed before (its own removal taken first included).
- **One roster source.** D's roster at a node is a function of the rotations it follows and its taken revocations; no removal changes whom a node boxes unless its rotation is taken there (held, even with its chain, is not enough: a revocation whose line merges a fork its maker signed as a made-up key actor is held but not taken).
- **Bounded rotations.** Under every delivery schedule (lockstep, symmetric, random), honest nodes make at most one plain rotation per node per event and stop rotating once deliveries complete; merges made at once of the same tips are one epoch.
- **What decides opens without it.** On a thing with a holder outside P, a sibling's rotation of the thing at a closed epoch of P and the listing naming it open at the other node: its writes there count (the listing-cycle shape).
- **Merge secrecy.** No merge seed made by a node aware of X's removal is derivable from seeds X holds.
- **Certificates are interchangeable.** Holding any one of an epoch's certificates by nodes of its line instead of all of them changes nothing a node reads.

## Model
roles-model `custody` (core/test/roles-model/README.md, Custody): parties `forks`'s plus C (two removals made apart) and T reading only; thing t held by an outside reader; the thief holds every header and old key, forks, revokes, signs as a made-up key actor, adds, takes what it withholds, answers, certifies merges and re-seals. Random and lockstep schedules, an exhaustive small family. Negative controls, each failing: `custody-judged` (switches and held keys), `roster-bare` (one roster source), `merge-random` (lockstep never settles), `stale-shut` (held keys; the sibling's thing writes never count), `merge-carries` (certificates of one epoch read otherwise). Next: the engine differential (`rotation::tests_forks`) with switches back and the lockstep schedule, and `sibling_removals_apart_both_hold_spec_permissions_3` with `world(5, 4)`.

## What it removes once built
The account-rotation wrap exception (spec/crypto.md §5: a P rotation is wrapped under the epoch it is signed at, the general rule); D's own rotations; the `rotations_due` seed fixpoint; the "Who is a node" grant fixpoint and the D clause of removal frontiers (spec/permissions.md §5.1, Listed); the merge-storm limit (spec/permissions.md §5.5); the `forks-first-grants` and `forks-anyone` controls (moot by construction).

## Costs
- A pairing is a rotation of P (rare; readers outside see one more rotation, not whom it adds).
- A merge seed is held by everyone holding all its tips' seeds; for an unaware sibling's tips boxed to X that includes X, the existing unaware-sibling limit (spec/permissions.md §5.5), no wider.
- Reading stale boxes reads nothing the node was not boxed.
