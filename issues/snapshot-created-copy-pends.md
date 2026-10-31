# A snapshot's or a content commit's projection still pends at a syncer of its thing
> Summary: The link-race fix (atomic apply: a plain membership commit held in part applies) leaves out content commits (a thing's `/created` chain copy) and membership snapshots (a roster snapshot's projection carries its reset). A syncer of the thing holding only such a copy waits for the rest; forever if the author's full commit never reaches the thing's label. With the placement order gone the copies may go first.
> Tags: node, sync

Code: `apply::examine` (`projection`), certificates in `labeling/certs.rs` (`parts_of(.., ["/created"])`, roster projection with the reset).

Why left out: applying the `/created` part alone would split every thing creation (its `/created` blob is its own retention class under the thing's label, so atomic apply would weaken for content commits, spec/requirements.md); a roster snapshot's partial apply resets the roster to the projected members until the rest arrives (writes of the others judged invalid meanwhile).

How likely: the author must lose its disk (or the thing's label never take the commit) between sending the copy and placing the commit. Not seen in sims.

Options: mark projections apart from bodies (a projection flag the receiver can trust is extra bytes or state); project roster snapshots without their reset (then the copy does not replace the roster where applied alone); accept.
