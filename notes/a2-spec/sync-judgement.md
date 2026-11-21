# A2 draft: spec/sync-judgement.md
> Summary: Draft spec text for stage A2 (not in spec, not built): spec/sync-judgement.md §1 (entitlement, deposits, per-sync-ID copies and certificate blobs as evidence copies) and §2 (the required set as bodies plus evidence, judged by every node from what it holds now; the may-hold clause on an author's other blobs gone), §3 (a delete at a peer resting on a verdict waits for a complete pass). Map: notes/a2-spec/README.md.

Replaces, in spec/sync-judgement.md: in §1 one sentence of Entitlement, the deposit bullet's list, one sentence of Per-sync-ID copies, the Certificate blobs bullet's lead and first sub-bullet; in §2 the first, third and fourth bullets of the required set and one clause of may-hold; in §3 one sentence added to Deletes. Every other bullet *stands*. **(A3)** and **(until A4)** as in notes/a2-spec/permissions.md.

## 1. What goes under a sync ID
- **Entitlement**, its sentence on placing: **(until A4)** Placing thing lists (spec/permissions.md §5.5), an account root reads as its account does, whichever node judges it; for what a node seals, boxes or opens, only its own account's root does. *The rest of the bullet stands.*
- A node that is not a writer of S deposits what it must log there (S's evidence it holds that S lacks, notes/a2-spec/permissions.md §4 Logging evidence; **(until A4)** its account's rotations and thing lists; its invite grant or self-removal, its external fires, its listings and its history adds) and relays or deposits the must-hold bodies it holds (§3).
- **Per-sync-ID copies**, its first sentence: S's body of a commit is the parts of it S's actor may read on things of S's sync unit; it is the shared blob where S's readers can open every section, else one per-sync-ID copy (*the rest stands*, "a part only S's certificates name" read as "a part only S's evidence names").
- **Certificate blobs**: certificate copies (notes/a2-spec/permissions.md §4 Copies: per (commit, thing), a role commit's edge-class parts on one thing outside S's sync unit), header-only copies (things' witnesses and destroying requests; **(until A4)** accounts' rotations), list blobs **(until A4)** and record blobs: copies of parts about one thing, thing lists, or raw creation records (spec/wire.md §3).
  - S's evidence goes as certificate copies exactly where its bodies do not carry it: on a thing outside S's sync unit.
  - *The other sub-bullets stand* (one blob per copy wrapped under each sync ID it is logged under; parts that differ per sync ID are separate blobs; a refused one goes again as a fresh encryption; list and record blobs a fresh encryption per sync ID; linked frontier and header-list chunks under it too).

## 2. Required set and judgement
S's **required set** is its sync unit blobs (§1) plus what is logged there beside them, one rule for every blob whoever logged it, judged by each node from what it holds now (spec/permissions.md §4: a function of the held commits and S's sync unit, never of what was once required):
- S's **evidence** (notes/a2-spec/permissions.md §4 Evidence of a sync ID): a certificate copy is in it when the edge-class part it holds (its identity's) is in S's evidence; judged by the deltas the blob holds, the same at every node; a record blob by its records (those of the members of the paths S's evidence states, and up their record chains); **(until A4)** a list blob by its thing lists and a header-only copy of a rotation while S's evidence names its account; a destroyed thing's certificates by the sync ID's things needing it (spec/commits.md §5 Destruction). A copy holding parts other than one thing's edge-class parts of its commit is no certificate copy.
- cross-published `sync.0` commits (§1). *Stands.*
- role commits naming an actor (spec/permissions.md §4 Role changes travel): *stands*, "as certificate copies where the bodies do not carry it". **(A3)** A removal is in it while held, in place of `ROLE_KEEP` after its `ts` (notes/a3-spec/sync-judgement.md).

- **may-hold**, its list: not loggable, covered, out of history, parked, unfetched pages, dropped here, judged invalid. ("a certificate blob whose author has no other blob under the sync ID" goes: a copy is in S's evidence or not, whoever signed it.)
- *Every other bullet of §2 stands.* Outside the required set stays judged only at the end of a complete pass begun after what decides the commit's place under S last moved: for a certificate copy, the bodies whose evidence held it, the edge writes on their paths and S's sync unit.

## 3. Acting on the judgement
- **Deletes**, one sentence added after its first: a delete resting on a verdict (a body covered by a snapshot judged valid, a body judged must-not-hold by a validity it reads) is sent only once a complete pass of S (spec/sync-status.md §1) begun after that verdict's inputs last moved has ended (notes/a2-spec/commits.md §4 Provisional). OPEN 2 (notes/a2-spec/README.md).
- *Every other bullet of §3 stands.*
