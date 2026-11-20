# A3 draft: spec/sync-judgement.md
> Summary: Draft spec text for stage A3 (not in spec, not built): the required set's removal clause (in for good while its reach is held, in place of `ROLE_KEEP`) and leaf blobs as evidence; what the delivery duty logs or deposits under a sync ID it holds for the duty. Map: notes/a3-spec/README.md.

Written over notes/a2-spec/sync-judgement.md. Replaces its **(A3)** sentence in §2 and adds a leaf-blob clause to §1 Certificate blobs and §2. Every other bullet *stands*.

## 1. What goes under a sync ID
- **Certificate blobs**, its lead: certificate copies, header-only copies, leaf blobs (spec/wire.md §4: one lowering's leaf for one thing), list blobs **(until A4)** and record blobs. A leaf blob is one blob wrapped under each sync ID it is logged under, as a certificate copy is.
- A node holding a sync ID for the delivery duty (spec/sync-set.md §2) and not a writer of it deposits what the duty logs there (spec/sync-inbox.md §3); it relays nothing else there.

## 2. Required set and judgement
- S's **evidence**, a clause added: a leaf blob is in it when its (lowering, thing) is in S's evidence (spec/permissions.md §4: read by a body there that its lowering cuts, or with its lowering where that is a body), judged by the leaf's pair in a held root.
- role commits naming an actor (spec/permissions.md §4 Role changes travel): a role commit naming S's actor as holder, with the target's boxes to it and its `sync.0`, while held. A removal is in S's required set while it is in S's evidence (its reach held): for good while the unit holds a thing it reaches; no `ROLE_KEEP` clause for removals.
