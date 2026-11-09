# An ending's verdict still reads what the ending drops
> Summary: The right to end needs the first admin's edge on the thing, and a removal of that edge is authorised by a grant on the thing, which the ending drops. A node that took the ending first keeps it; one that held the removal first keeps the thing; their syncs upload and delete the blobs for ever. Needs a choice from Tess.
> Priority: critical
> Tags: engine, sync, tess-call

An admin by a grant on T removes T's first admin F. Concurrently a holder of F ends T.
- Node C holds the removal first: the request falls, C keeps T and re-uploads what hosts lack.
- Node A takes the ending first: T's grants go with it. The removal arrives (or is thrown as a part on an unknown thing), but its author's authority on T was that grant, so it is invalid here and the ending stands.

A and C differ for good on what they hold, and A's dropped-body deletes meet C's re-uploads with no end (`repro_first_admin_removal_after_ending`). This is honest input, only a race.

Choices:
- **The right reads only the first admin's standing, not its edge on the thing.** Nothing dropped can then change the verdict, and no removal can make an ending fall. A first admin removed from a thing can still end it, so "the first admin is history" (spec/permissions.md §1) gets an exception: ending stays with the creator's side for good. Fits the sentence in spec/requirements.md ("only its creator's side"). Recommended.
- Keep the thing's edges while the request is held. A tombstone per ended thing, for the sake of a rare race.
