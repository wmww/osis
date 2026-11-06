# Moving a thing (not built)
> Summary: A thing never changes its record and nothing moves it (Tess): a move is grant then remove, with no tid change. What could be built if an app needs one: a plain copy; a copy with imported history was built and removed, kept here as reference with what made it costly.

1. **Grant then remove** (after step 2): grant the new party admin, remove the old one. The tid stays; a large set moves by handing over one shared actor (the share-through-one-actor rule, spec/requirements.md Generality).
2. **Plain copy** (possible today, needs nothing in the protocol): the mover creates M under the new owner and writes T's current values as its own writes; T stays. Loses original authorship, edit history and others' purge rights over the copied values.
3. **Copy with imported history**: rejected. It was built (spec text: `git log -S 'Import commit' -- spec/permissions.md`) and cost 29 merged items, two open issues and an order oracle, while nothing first-party moved: imported writes interact with purge, retention, validity and arrival order.

## The removed import design, in short
- **Copy**: a node with rights on new owner X creates M (owner X, fresh nonce, a `creator` field in the creation record naming that node, the only one whose imports M takes). Roles on M are X's to grant; the mover writes T's `keep` default on M when T's says retain.
- **Links**: `was.0` on M (what M continues), `moved.0` on T (what T continued as), both role-class, admin-written. A tid t held in thing R's value resolves at read time to the held M with `was.0 = t` in which R's owner chain holds rights (exactly one), else t's `moved.0`, at most 8 hops. Stored values are never rewritten.
- **Import commit**: a content commit with an import marker, every delta on M, no own writes, commit form, no `expires`, no `created.0` or `required.0^`; its header carries an origins table `[commit_id, author, actor, ts]`.
- **Re-sourcing**: a write of origin commit C gets dot (`Commit(C)`, k), keeping its `ts`; k is its counter in C for an own-source write, else its rank by (source, counter) among C's dots on that aspect. Referenced dots map the same way, so importing C twice gives the same dots.
- **Origin choice** per write: a valid snapshot covering and carrying it, else its own commit, else the snapshot carrying it. Expiring, purged and invalid writes are not imported; of a sequence, only shown elements and what they anchor at.
- **Validity**: an import is valid iff valid as the importer's content write on M. An import listing an origin with its own delta on M is void.
- **Purge and retention**: each imported delta keeps its origin's retention; for purge rights its author is its first origin's author. A purge of an import takes every write under its origins' dots.
- **What it touched**: header kind and list, creation record, dot ownership, covered-body checks, purge fall and return rules, keep bounds of snapshots, sequence import bounds, arrival-order independence, the undo "complete state" check.
- **Its open problems**: imported dots shared `Commit(C)` with a commit-form C's own dots (the void rule and its rebuilds; a dropped snapshot stayed dropped); multi-origin imports existed only in hostile input yet every purge rule handled them; a hostile creator's two imports of one origin could differ in retention.
- **If rebuilt**: give imported writes a source kind of their own and one origin per import commit; both remove the hardest rules above.
