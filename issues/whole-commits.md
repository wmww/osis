# Whole commits: steps 4, 5
> Summary: Tracking the rest of notes/whole-commits.md (steps 2a, 2b, 3 built): step 4 (per-part strip, must-hold per blob) and 5 (cleanup, the sealed-sections rule), with the spec text each lands. The spec describes only what is built; each step moves its lines below into spec/ and deletes them here.
> Tags: engine, node-sync, label, host, spec

Built: 2a (one expiry per commit), 2b (one blob per commit, sections per thing), 3 (apply never waits for a part); the spec carries them (spec/wire.md §4, §5, §11.2; spec/commits.md §4-§6; spec/sync.md §1, §3, §5), design in notes/whole-commits.md.

Not built from step 3: "sealed sections of things not synced stay unopened": a receiver cannot tell from the blob whether a section's thing is synced before the commit's own `group.0` membership write applies (a commit creating a thing in a group would leave the thing's record sealed), so it needs held blobs reopened as the sync set grows; node-sync opens every section it holds a secret for.

Left:
- **4, per-part strip** (notes/whole-commits.md Left to build).
  - spec/commits.md §5: a part whose body must go (keep-at-most bound, applied purge request, covering compaction, invalidity under `required.0^`) is stripped: dropped locally as today and, by a right holder, uploaded again as the commit's blob without that part (other sections verbatim), naming the old entry as replaced. One mechanism for keep at most, compaction and purge.
  - spec/sync.md §6: must-hold per blob, judged on the parts the node reads: must-hold if a readable part is must-hold and no other held blob of the commit under the label carries it; must-not-hold if a readable part must not be held; else may-hold. "Strict subset" becomes "fewer parts of the same commit wins while nothing the node reads is missing from it". A node never uploads or deletes on the strength of sections it cannot open.
  - spec/sync.md §5, §7: hosts delete unattended only at the commit's expiry or a timed delete carrying every group's signature (no node sends timed deletes: issues/host-timed-delete-unused.md removes them, so this clause may go); a rewrite stripping a dead part carries the live ones.
- **5, cleanup**: the leftovers listed in notes/whole-commits.md Left to build; decide the sealed-sections rule (above).
