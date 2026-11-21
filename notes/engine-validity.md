# Engine: validity
> Summary: How the engine keeps every delta's validity, and so every read, a function of the held set (spec/permissions.md §5, spec/crdt.md §4.6): what is re-judged after a held-set change and its cost, un-merge by one rebuild path, snapshot authority and carried writes, covered bodies going missing again, and why validity flips against dropped data converge on delivery (the rule, rejected removal rules, holes left). The spec states the rules; this note keeps reasons, costs and tests.

Elsewhere: the epoch rule (notes/engine-validity-epochs.md), reasons and Tess's decisions (notes/revocation.md Snapshots and history, Revocation, Implementation), invalid bodies dropping (notes/engine-retention.md Invalid bodies), suspect flags (notes/engine-suspects.md).

## Principle
Validity is a function of the held set, never of arrival order: an invalid delta changes no value, and a node that held it reads as one that never did. So every judgment input is held or persisted with its commit, re-judging follows what changed, and every change of what counts goes through one rebuild from the held valid bodies.

## Re-judging
### What is re-judged
- Authors whose role may have moved, on the things it may have moved on (`Core::stale_authors`, `stale_under`: `Held::upstream` and `Held::reach` of what `osis_perm::Changed` reports, via `ix.by_thing`). A thing holding addenda is judged whole: an addendum vouches for others' deltas.
- Commits whose writes apply otherwise whoever signed them (`Changed::commits`: an invite grant overtaken on its grant loses its boxes' exemption with no role of its author moving). Never every commit on a changed edge: a long role history would re-judge all its holder's writes per arrival.
- Every delta on the things a component walked anew or a new record's chain reaches (`Core::stale_things`).
- Commits whose void, required-role or overreach inputs changed (`stale_commits`), and those acting for a thing whose timeline changed (`acts_for`).
- Everything after a rebuild at open (`stale_all`).

No delta's validity depends on its thing's `retention^.0` setting: a setting is judged as an admin-only delta and only moves what history keeps (notes/engine-retention-history.md). A rollback restores validity flags with the journal.

`rejudge_all` repeats while a rebuild left something stale (a part `retention::uncover` made missing); it ends, as `uncover` never turns parts back.

Rejected: re-judging every held delta per role commit (O(held commits) each); a grant re-judges no content commit (`scale::grant_is_flat_in_content_commits`).

### How perm reports moves
`Timelines::update_touched` re-partitions around the things whose held inputs changed (`Held::take_touched`; a commit naming only things of its component continues the walk instead, `Timelines::append`). A component evaluated anew re-judges all its things; one whose walk only went on or gained leaves, only what authority flows to from the touched things (`Held::reach`). So a new thing, or a grant to a holder new to every walk, re-judges that thing's deltas only.

### Cost per commit
- `Judge` takes each commit once, looks record depth and the timeline up once per thing, and answers an author's deltas from where it holds the role (perm `Timeline::valid_from`, once per (thing, author, role)). A voided commit is re-judged alone.

### Addenda by header
An addendum's validity reads its header and the timeline, never its body: `ix.addenda` holds every held commit's `addenda.0` delta from its header (`validity::note_addenda`, also at open for a body not held), with its entries only while the body is held (`forget_addendum_body` on drop or strip, before its `node/addenda` row is rewritten). So the persisted row equals what a rebuild reads (`tests_addenda::a_bodiless_addendum_is_judged_by_its_header_spec_perm_5_2`).

### Checks
- Debug builds assert at each transaction's end that nothing stale is left, after each re-judge that no flag on the things it took changed outside the re-judged set, and at the end of the engine's history the same of every held commit (notes/test-harnesses.md, Verdict checks).
- `Engine::misjudged` (in `Engine::check_index` and the order harness after a reopen) checks each flag is what judging gives. Judgment inputs from a body (rotation role, overreach) are persisted in the commit's `node/metas` row, so this holds with the body dropped.
- perm `incremental::incremental_equals_from_scratch_plain` checks reported moves against every timeline answer (`update_moved`). Arrival order: engine it `apply_order`, perm `incremental` late leaves.

### Possible holders (`Held::ever_admins`, `ever_writers`)
The one helper for "could this author ever have held the role" where the answer must not depend on arrival (purge rights; spec/commits.md §4); a timeline read would. A least set grown from the thing through mint admins and grants signed by members, of any validity, so it only grows. One set over the thing and its members, not one per member thing (a member could name the holder on the thing anyway; per-thing sets took 20 s per call on a chain of 1000 nested holders).

## Un-merge and the one rebuild path
### Un-merge is skipping invalid bodies
- Un-merge is by invalid delta, not by author (spec/crdt.md §4.6). Invalid bodies never travel, so a rule taking more than the delta's own writes would make reads depend on whom a node met first.
- A non-snapshot delta carries no foreign stamps (spec/crdt.md §3.3; overlapping session ranges void both commits), so an invalid body holds only its own writes and a valid one none of an invalid delta's. So `rebuilt` joins every held valid body whole, leftovers included, and nothing of an invalid part.

### One path
- Every validity flip, valid body drop other than as covered, strip and re-arrival rebuilds the aspect (`apply::rebuild` → `rebuilt`; issues/drop-rejoin-robust.md item 1). A drop as covered leaves the state's value as it is (the coverer carries the body's writes; notes/engine-retention-dating.md Invariant), so it only rewrites shredded the rows holding the body (`apply::shred_covered`, notes/engine-paged.md Writes); while the aspect's value-less list changed in the transaction it rebuilds. No in-place un-merge: re-merging needs the bodies (a register's earlier value comes back only from them), and one path keeps every case alike.
- An invalid part changes no state, so its arrival, its drop (`drop_invalid`, unless it uncovers a part) and a valid snapshot joining with copies of invalid writes rebuild nothing.
- Mid-transaction, between an overlap voiding a held commit and the re-judge flipping it, the state still holds that commit's writes; the flip's rebuild takes them before the transaction ends.
- The rebuild writes the state shredded.

### Where a rebuild stops
Newest body first, `rebuilt` stops once the state's root reset or register write is past the next body's `ts` (`Fragment::settled_above`; spec/crdt.md §7 One reset per position): older writes are pruned (spec/crdt.md §4.2). A debug build reads them all anyway and checks the skipped state equal. So a chat kick reads down to the winner only, flat in length.

### Checks
Debug builds check after every transaction that the state equals a rebuild (`apply::check_rebuilt`: every aspect changed other than by a valid join, and a sample of those). osis-crdt `unmerge_spec_4_6` checks un-merge per delta (`Fragment::remove_writes`) on random histories. The engine property `validity::unmerge_paged_matches_fresh_large` compares a node un-merging paged states with a fresh reader holding the thing (a node not holding it keeps no content, so reads nothing) and counts one rebuild per aspect the revoked writer wrote: the receiver gets those writes in the millisecond it gets the removal, outside R's window, so it writes no addendum (an addendum would flip `addenda.0` and re-raise a vouched aspect: two more rebuilds).

### Cost
O(aspect history) per flip (`scale::validity_flip_is_linear_and_invalid_arrival_flat_spec_permissions_5_2`: n + 1 body reads, commits re-judged flat). Accepted as rare (issues/long-aspect-cost.md). An invalid arrival reads no other body (the same test).

## Snapshot authority and carried writes
### Authority
- A snapshot's part is valid iff its author could write the aspect at it (`Judge::part`: `delta_valid` with `required_role(ak)`, never the rotation role).
- An invalid snapshot gives nothing: its copies never join (on apply, late, or in `rebuilt`), it is left out of dating replaced bodies (`retention::bounds::note_body`), and it covers nothing (`covered` → `Some(false)`), so a demoter lists the commits it would have covered.
- Frontiers and `Absorbed` are no receipts (`validity::inflated_snapshot_claims_count_nothing_spec_crdt_8`), so a demotion frontier does not depend on a snapshot's validity (`flipped_snapshot_leaves_frontier_alike_spec_perm_5_2`).
- A commit whose part is away applies without it whatever snapshots are held (`listed_part_alike_in_any_order_*`, `part_listed_by_invalid_snapshot_applies_*`).
- A snapshot dropped other than as covered (`DropFor::Other`: bound or expiry; a purge never drops a snapshot) still settles suspect flags (`Dropped::stands_in`, `ix.dropped_snapshots`); one dropped as covered need not (its coverer is valid and stamped no earlier). It carries nothing: what it alone covered goes missing (Uncovering, below).

### Carried writes
A write's own delta is the one carrying its dot (`copies::any_delta`). A valid snapshot vouches for every write it carries; nothing is judged per claimed author.
- **Copies join like any write** (spec/permissions.md §5.2 Copies): never compared with a held delta's, never stripped, nothing recorded. Differing copies settle by the copy order (`differing_copies_join_by_copy_order_alike_*`). Cost: one join, O(part).
  - Rejected: stripping the delta's writes where a valid snapshot's copy differs. It acted on a writer's claim about others' history and cost a whole-state read per snapshot join and a rebuild per differing copy.
- **Own delta invalid**: its body gives nothing; a held valid snapshot's copies stay. Dropping that snapshot rebuilds the aspect. A cover must carry a valid snapshot's copies too (`covered`), so it never drops a voucher's vouching.
- **Own delta never received**: the write is in the state only through a held valid snapshot (nothing indexes which). When that snapshot falls or drops, the rebuild keeps the write only where another held valid body carries it, alike with a node that got the demotion first (`demoted_compactor_snapshot_by_frontier_*`, `invalidated_copy_of_shared_dot_goes_alike_*`).

Tess's scenario (spec/requirements.md Permissions: edits a remaining writer vouches for having received are kept): a removed holder's unseen write compacted by an honest writer before it learned of the removal stays wherever that snapshot is held (`removed_holder_write_compacted_earlier_stays_alike_*`) until an admin's reset or revert.

## Uncovering
### The test
A body dropped as covered (`Dropped::as_cover`) stays dropped while the test that dropped it (`snapshot::covered`) passes on what is held now; bodies dropped by expiry or purge stay dropped. It passes with:
- **a carrying snapshot**: a coverer held with its body and valid, or itself dropped as covered under covers that carry it (`retention::coverers` walks the chain);
- **or two own replaces**: any two valid held own replaces later than the body (`snapshot::own_covers`), recorded as its covers or not, so the test is a function of what is held. With one, a node deletes at other nodes what a holder judges uncovered and logs again (`one_own_replace_left_covers_nothing_spec_commits_5`); with only those it dropped under, it goes missing where a holder judges it covered (`any_two_held_own_replaces_keep_a_drop_spec_commits_5`).

### When it runs
Whenever a cover on the aspect may stop carrying: it turns invalid, arrives again judged invalid, or drops or goes missing other than as covered (`drop_part_for`, `unstrip`). A part failing the test is set missing, and the aspect rebuilt and flagged suspect (`Why::Uncovered`). It joins as a late part when it arrives again.
- A missing snapshot covers nothing until it arrives (`covered` → `None`): else any older valid snapshot would "cover" it and the compactor drop it for good.
- A missing part dropped later (a purge) is no longer missing (`drop_part`).
- Chains un-drop whole: a delta dropped under S1 and S1 under S2 both go missing when S2 falls; the delta's writes come back from S1's copies once S1 is fetched again.

### The chain of covers
- Only the chain records a cover. With the body gone, nothing else tells a snapshot carrying it from one that does not: tables reach no expiring delta and no delta whose writes died unseen (spec/crdt.md §8), and `covered` on a dropped body is too loose to keep writes by.
- So a forgotten coverer keeps its covers while a held part names it (`retention::handed`, `Indexes::handed`, rows `cv/`): one row, what its parts dropped under; nothing naming it is rewritten. One no held part names is spliced out (each kept covers naming it takes its covers), so rows are bounded by the held parts dropped as covered and a chain under a lasting body stays one row per coverer those parts name (osis-sync `growth::` counts rows at n and 10n). Else a coverer forgotten before a body dropped under it breaks the chain, and every `uncover` fetches, flags and drops the body again (`forgotten_coverer_keeps_its_covers_*`, `forgotten_coverers_keep_the_chain_short_*`). Rejected: rewriting each part naming it to name its covers (a meta and record write per part, so each snapshot of a growing aspect rewrote and re-judged every earlier body).
- `coverers` and `uncover` walk the chain through kept covers; `uncover` judges each commit on it once (`reached`), so chains shared by an aspect's parts cost their length once.
- A part dropped as covered counts covered (`Engine::part_covered`) and its carriers are the held valid snapshots on its chain (`read_facts`): the chain is the record, and `uncover` makes it missing once nothing on it carries. So a new snapshot joins and judges only held bodies, not the ones its predecessors covered.
- The chain is sound only because `covered` judges a held body by the join alone, not the frontier: a snapshot can carry writes past its own frontier (its writer held the body behind a session gap). By the frontier, a holder would call uncovered what a node that dropped the body calls covered, and re-place it every pass for the other to delete (`held_memory_body_past_a_snapshot_frontier_judged_by_the_join_*`).

### Fetching it back
- The body counts missing again (`facts.missing`), so read fetches it where a source shows it (spec/sync-judgement.md §3 Dropped bodies; `Streams::fetch_again` is not built: issues/sync-unbuilt.md). A holder finds the body uncovered, so must-hold, and logs it again (`coverer_demoted_after_cover_drop_alike_*`, `covered_drop_coverer_and_remover_revoked_alike_*`).
- With no copy anywhere the write is gone at every node alike (spec/permissions.md §5.2). Usually only a reader holds it then.
- The order harness drops covered bodies at every sync step (`order.rs` `drop_covered`) and checks a reopen reads alike, so open-equals-rebuild covers un-drops.

## Flips against dropped data
The one class of honest-use read divergence: validity is a non-monotone function of the held set (an explicit demotion arriving late turns applied writes invalid, and un-merge is the join of every held body and residue minus the invalid writes), so a node that dropped a body it would need computes a different join than one that kept it. The class is (a validity flip) x (a non-vouching drop under the flipped write).
- Every flip is an explicit demotion arriving late (a removal, a demotion, a revoke of a snapshot's or cover's author); `until` and self-removals audit nothing and are judged at the write's own `ts`, so they never flip.
- Compaction vouches (a valid snapshot vouches for what it carries), so it does not cause the class. The non-vouching drops are: expiry, purge, a pending part dropped at T, a right-less drop breaking a required retention. In honest use the class needs an aspect with retention bounds (or expiry/purge) written by a holder later demoted with a frontier not covering the write. Each new dropping mechanism re-opens a shape of it, so the fix is a rule, not per-case patches.
- **The rule** (Tess signed off the requirement sentences, spec/requirements.md Decentralization; spec/commits.md §5, spec/sync-judgement.md §3 Dropped bodies; `retention::takes_late`): a body dropped other than as covered counts as never received, and a copy that arrives again joins and is judged again; a body dropped as covered whose cover turns invalid is the same rule (Uncovering, above). Memory parts stay final. So nodes holding the same bodies read alike; a node lacking a body gets it from any holder, a reader included (deposit, then promotion); with none it is gone alike. Expired and purged copies still arrive value-less or stripped. A part pending at its expiry is dropped as never received and the aspect flagged suspect (`retention::pending_drops`, `strip_pending`). The backstop for what no writer holds is repair (notes/engine-suspects.md).
- **Rejected: removal rules.** No removal rule removes the class: convergence is decided by what the node dropped, not by the rule.
  - Giving up retroactive invalidation: by arrival at the judging node breaks Deterministic outright; by arrival at a chosen peer is a sequencer; by the author's claimed `ts` is the rejected timestamp rule and still retroactive. Any rule in which a removal invalidates a write some node already applied is retroactive there, and the removed writer plus any reader would keep write power (deposit, promotion).
  - Binding each write to its key epoch: an epoch's write secret proves only a lower bound on write time; a removed writer backdates into any epoch it held.
  - Bounded reach-back by a first witness (a signed receipt frontier, or a log stamp under an epoch the author never held): deterministic but still retroactive; reduces loss, closes no divergence, adds a receipt frontier to every delta.
  - A reach-back window on `ts` (backdated vandalism is what removal prevents); the demoter compacting first (not needed with the rule).
- **Holes left** (F forged by an authenticated writer, bounded; C clock or arrival, transient; L nodes alike but something lost):
  - Sticky drops in the role timeline (L; notes/role-timeline.md).
  - A valid snapshot's copy differing from a held delta's joins by the copy order wherever held (F, no divergence; notes/revocation.md Snapshots and history). Equivocation by a valid writer whose first commit's writes are all dead: nodes that held the first void both, those that forgot it count the second (F; spec/commits.md §5 Forgetting). A forged snapshot listing a part shows the commit partly until the part arrives (F; Authority, above).
  - A keep-at-least bound or an `until` straddled by two clocks (C, seconds; notes/sync-convergence.md); a value read past its T until the next call or Tick, a relay-only signal twice after a restart (C).
  - Session-sources double removal: a write left out of A's frontier because Y's snapshot covered it, then Y removed by a frontier not covering that snapshot: lost alike (L; a demoter listing every commit avoids it).
  - Writes the revoker had not received: lost alike, a re-grant brings back only what some node still holds (the designed semantics). Every writer dropped what only a reader kept: lasts to the next write (spec/requirements.md Deterministic).
