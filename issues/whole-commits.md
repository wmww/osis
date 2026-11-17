# Whole commits: the sealed-sections call
> Summary: What is left of notes/whole-commits.md (Left to build): whether a node opens sections only of things it syncs, and one owed engine test for unopened sections a strip left out.
> Priority: normal
> Tags: engine, sync, security, spec

Built: one blob per commit, one expiry, apply never waits for a part; the strip per blob for parts gone for good and for parts dropped as covered by a snapshot reaching them, a part never received counting covered under such a snapshot (spec/sync-judgement.md §2 Per blob, spec/commits.md §5 Covered, notes/whole-commits.md Strip).

## Sealed sections
Whether a node opens sections only of things it syncs: opening sections of things it merely has the secret for lets a purged part be read for good from a sync ID where no request arrives; not judgeable at open time (a commit creating a thing and the strong to it carries the thing's record in a section whose thing the receiver does not sync until that strong applies), so it needs held blobs reopened as the sync set grows.

## Owed test
`Engine::held_sections` keeps an unopened section only where every shared blob of the commit the node opened lists it, its bytes held or not (the held-model `strip` finds two strips of different parts, each by a node opening only its own, never meeting otherwise: 13 of 3000). No engine test reaches it: it needs three things under different secrets in one commit, two purged separately by nodes each reading one, and a third node reading neither.
