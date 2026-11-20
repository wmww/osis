# A3 draft: spec/sync-judgement.md
> Summary: Draft spec text for stage A3 (not in spec, not built): the required set's removal clauses (in for good while its reach is held, and under the openers' sync IDs while held, in place of `ROLE_KEEP`) and leaf blobs as evidence; what the delivery duty logs or deposits under a sync ID it holds for the duty. Map: notes/a3-spec/README.md.

Written over notes/a2-spec/sync-judgement.md. Replaces its **(A3)** sentence in §2 and adds a leaf-blob clause to §1 Certificate blobs and §2. Every other bullet *stands*.

## 1. What goes under a sync ID
- **Certificate blobs**, its lead: certificate copies, header-only copies, leaf blobs (spec/wire.md §4: one lowering's leaf for one thing), list blobs **(until A4)** and record blobs. A leaf blob is one blob wrapped under each sync ID it is logged under, as a certificate copy is.
- A node holding a sync ID for the delivery duty (spec/sync-set.md §2) and not a writer of it deposits what the duty logs there (spec/sync-inbox.md §3); it relays nothing else there.

## 2. Required set and judgement
- S's **evidence**, a clause added: a leaf blob is in it when its (lowering, thing) is in S's evidence (spec/permissions.md §4: read by a body there that its lowering cuts, or, a leaf for a thing other than the lowering's own, with its lowering where that is a body), judged by the leaf's pair in a held root.
- role commits naming an actor (spec/permissions.md §4 Role changes travel): *stands* (S's actor's own, with the target's boxes to it and its `sync.0`; and those naming a holder S's thing's keys open, with the chain's role commits), while held, a removal included: no `ROLE_KEEP` clause for removals. A removal is also in S's required set while it is in S's evidence (its reach held): for good while the unit holds a thing it reaches.
