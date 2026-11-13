# Engine: snapshot authority and carried writes
> Summary: How the engine judges compaction snapshots and the writes they carry (spec/permissions.md §5.2): an invalid snapshot gives nothing, a valid one's copies join like any write. Reasons: notes/permissions.md (Snapshots and history).

## Authority
- A snapshot's part is valid iff its author could write the aspect at it (`Judge::part`: `delta_valid` with `required_role(ak)`, never the rotation role).
- An invalid snapshot gives nothing: its copies never join (on apply, late, or in `rebuilt`), it is left out of dating replaced bodies (`retention::bounds::note_body`), and it covers nothing (`covered` → `Some(false)`), so a demoter lists the commits it would have covered.
- Frontiers and `Absorbed` are no receipts (`validity::inflated_snapshot_claims_count_nothing_spec_crdt_8`), so a demotion frontier does not depend on a snapshot's validity (`flipped_snapshot_leaves_frontier_alike_spec_perm_5_2`).
- A commit whose part is away applies without it whatever snapshots are held (`listed_part_alike_in_any_order_*`, `part_listed_by_invalid_snapshot_applies_*`).
- A snapshot dropped other than as covered (`DropFor::Other`: bound or expiry; a purge never drops a snapshot) still settles suspect flags (`Dropped::stands_in`, `ix.dropped_snapshots`); one dropped as covered need not (its coverer is valid and stamped no earlier). It carries nothing: what it alone covered goes missing (notes/engine-validity-uncover.md).

## Carried writes
A write's own delta is the one carrying its dot (`copies::any_delta`). A valid snapshot vouches for every write it carries; nothing is judged per claimed author.
- **Copies join like any write** (spec/permissions.md §5.2 Copies): never compared with a held delta's, never stripped, nothing recorded. Differing copies settle by the copy order (`differing_copies_join_by_copy_order_alike_*`). Cost: one join, O(part).
  - Rejected (built, removed): stripping the delta's writes where a valid snapshot's copy differs. It acted on a writer's claim about others' history and cost a whole-state read per snapshot join and a rebuild per differing copy.
- **Own delta invalid**: its body gives nothing; a held valid snapshot's copies stay. Dropping that snapshot rebuilds the aspect. A cover must carry a valid snapshot's copies too (`covered`), so it never drops a voucher's vouching.
- **Own delta never received**: the write is in the state only through a held valid snapshot (nothing indexes which; tests use `Engine::carried_dots`). When that snapshot falls or drops, the rebuild keeps the write only where another held valid body carries it, alike with a node that got the demotion first (`demoted_compactor_snapshot_by_frontier_*`, `invalidated_copy_of_shared_dot_goes_alike_*`).

Tess's scenario (spec/requirements.md Permissions, Limit): a removed holder's unseen write compacted by an honest writer before it learned of the removal stays wherever that snapshot is held (`removed_holder_write_compacted_earlier_stays_alike_*`) until an admin's reset or revert.
