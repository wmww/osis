# Moving a thing to another owner (not built)
> Summary: A thing never changes owner and nothing moves it (Tess). What could be built if an app needs one, simplest first, with the removed import design as reference.

1. **Plain copy** (recommended if ever needed): the mover creates thing M under the new owner and writes the current values of T as ordinary writes of its own; T stays with its owner. Loses original authorship, edit history and others' purge rights over the copied values; needs nothing new in the protocol (an app can do it today).
2. **Copy with imported history** (built once, then removed; full text in git history of spec/permissions.md §7, `git log -S 'Import commit' -- spec/permissions.md`). Cost: imported writes interact with purge, retention, validity and arrival order; 29 merged items, two open issues and an order oracle were spent on it, while nothing first-party moved.

## The removed design, in short
- **Copy**: a node with rights on new owner X creates M (owner X, fresh nonce, and a `creator` field in the creation record naming that node, the only one whose imports M takes). Roles on M are X's to grant; the mover writes T's `keep` default on M when T's says keep.
- **Links between them**: `was.0` on M (the thing M continues), `moved.0` on T (what T continued as), both role-class, admin-written. Read-time **resolution** of a tid t held in thing R's value: the held M with `was.0 = t` in which R's owner chain holds rights (exactly one), else t's `moved.0`, repeated at most `RESOLUTION_HOPS` (8) times. Stored values never rewritten.
- **Import commit**: a content commit with an import marker, every delta on M, no own writes (empty counter ranges), commit form, no `expires`, no `created.0` or `required.0^`. Its header carries an **origins table** `[commit_id, author, actor, ts]` per origin commit.
- **Re-sourcing**: a write of origin commit C gets dot (`Commit(C)`, k), keeping its `ts`; k is its counter in C for an own-source write, else its rank by (source, counter) among the dots C carried on that aspect. Referenced dots (anchors, reset stamps, sibling keys) map the same way, so importing C twice yields the same dots.
- **Origin choice** per write: a valid snapshot covering and carrying it, else its own commit (held valid, not dropped), else the snapshot carrying it. Expiring, purged and invalid writes are not imported. Of a sequence, only shown elements and (content-less) what they anchor at.
- **Validity**: an import is valid iff valid as the importer's content write on M; its elements are judged by that alone. An import listing an origin with its own delta on M is void. Several imports of one origin by M's creator all count.
- **Purge and retention**: each imported delta keeps its origin delta's retention; for purge rights and delete keys its author is its (first) origin's author; no level-2 delete key. A purge of an import takes every write under its origins' dots, so every import listing that origin drops.
- **What it touched**: header kind and list, creation record, dot ownership (`Commit(C)` resolved to the import on M), covered-body checks, the purge fall/return rules, keep bounds of snapshots (own deltas through imports), sequence import bounds (`MAX_DELTA_BARE`), arrival-order independence, and the undo "complete state" check.
- **Open problems when removed**: imported dots shared `Commit(C)` with a commit-form C's own dots (the void rule and its rebuilds; a dropped snapshot stayed dropped); multi-origin imports existed only in hostile input yet every purge rule handled them; a hostile creator's two imports of one origin could differ in retention.

## If it is rebuilt
Give imported writes a source kind of their own and one origin per import commit; both removed the hardest rules above.
