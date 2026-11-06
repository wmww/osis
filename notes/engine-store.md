# Engine store records and the persisted index
> Summary: What the engine keeps in its encrypted `Store`: local record prefixes, store kinds (aspect units and their three tables), the rebuildable `node/*` index tables, and how an open uses them (the rules tag, `node/edges`, lazy headers, saved role walks), with open costs. Not here: the store itself (units, key tree, shredding: notes/local-store.md), node-sync's `y/` records (notes/sync.md), paging layouts (notes/engine-paged.md). Module map: notes/engine.md.

## Local records
Layouts in `engine/records.rs` (and the module named); all are `*_local` records of the store.

| prefix | holds |
|---|---|
| `seed`, `hlc` | the node seed; the last `ts` issued or seen |
| `c/`+commit | applied commit records: a head (`index::record_head`, version byte 1: received, origin, dropped parts with what each keeps (`Meta::dropped`), stripped parts (`Meta::stripped`), parts whose leftover keeps own values (`Meta::valued`)), then the current blob |
| `t/`+tid | creation records |
| `a/`+aspect | aspects with a state (`aspects.0`) |
| `r/`+aspect | receipt records (notes/permissions.md Revocation) |
| `v/`+aspect | value-less deltas (expired, purged): the join-time strip list |
| `w/`+aspect+commit+ai | leftovers (notes/engine-retention.md) |
| `p/`+aspect, `pn/`+aspect+commit, `z/`+commit+tid | purge requests on a whole aspect or author; requests naming a commit; a request that dropped a permanent delta (`retention::lasting`) |
| `x/`+T+commit+ai | timers (expiry, keep bounds) |
| `s/`+tid | things this node was asked to sync |
| `o/`+commit | commits voided by overlapping session ranges |
| `g/`+tid+commit | `keys.0` parts whose held body wrote a keyset, any validity (`ix.keyset_parts`; kept while the commit is held, whatever becomes of the body); `own_keys` = things with such a part valid (`apply::keys::refresh_own_keys`, on noting, flips, load), so an uncover keeps it and an invalid rotation drops it |
| `k/`+actor | opened epochs of an actor (`established`, `claims`, `snapshot`; never re-inferred). A plain thing's leftover epochs here are reading-only overlays on its derived ones (`Core::own_epochs`/`epochs`) |
| `b/`+commit+tid | pending boxes kept sealed by forgetting (`apply/keys.rs` `SEALED`; notes/engine-lost-access.md) |
| `e/`+aspect | aspects whose deaths wait for a recompute |
| `q/`+aspect | suspect flags: le64 corrected wall ms last raised, then per body its commit, aspect index and `Why` bits (`retention/suspect.rs`) |
| `l/`, `T/`, `K/`, `B/` | the lost-access work list, timed losses, kept copies, bearers (`rotation/lost.rs`) |
| `d/`+AK | the local schema of each app AK (canonical form) |
| `u/`+name | API records (account, home group, settings) |
| `sides` | the sides taken in admin disputes (`sides.rs`): per (edge write, holder) trusted and chosen flags |
| `i/v` | the persisted index's rules tag |
| `y/...` | node-sync's state (notes/sync.md) |

Store kinds besides local records (osis-store's catalog):
- **Aspect units**: the state (snapshot grammar with its pages inline, or for a paged state `[1, skeleton, [[set ID, path, encoding]*]]`: the state with its paged collections reduced to their reset and `W`), the undo buffer (notes/engine-retention.md), pre-reset snapshots.
- **Aspect tables** (`engine/pages.rs`, notes/engine-paged.md): table 0 state pages (row key = set ID ‖ order-preserving bytes of the page's first dot, the first page the set ID alone; value `[first dot, next page's first dot, page]`); table 1 the index of paged maps by key and paged sets by value (set ID ‖ keyed BLAKE3 of the key or value, links by content hash (`pages::ident`, key `Core::key_salt` derived from the node seed) ‖ entry or element dot; a superset, rebuilt with the layout); table 2 a paged sequence's placement (layout: the comment above `Place` in `pages.rs`). Tables 1 and 2 are rebuildable: written with the layout, and the unit tag names their rules.
- Counters (memory overlay rows only, notes/engine-apply.md Counters), death records (per body and aspect: first and last), pending and parked commits, blob ciphertexts (pages, chunks, header-list trees).

## Index tables
Rebuildable store index tables `node/*` (`engine/index.rs`): `node/metas` (per commit a byte per part: valid, the rotation role it needs, a grant's overreach; then the header's `View`; then what its `secrets.0` parts show for possession, `Indexes::shown`: every input of a part's judgment that comes from its body is in the row, so a fast open judges a held part as the running node did), `node/boxes to`, `node/epoch intro`, `node/keysets`, `node/delete hints`, `node/required`, `node/snapshots` (per aspect, with frontiers), `node/carried` (writes snapshots carry whose own delta was never received), `node/edges`, `node/walks`. They are an index, never the truth: a store whose index fails to read is rebuilt from the commit records.

## Open (`apply::load`)
- **Fast open** with an index of these rules (tag `i/v`: package version and the build script's hash of the engine's and its osis dependencies' sources): reads the commit record heads and header bytes (extent found by `osis_base::item_prefix`, nothing decoded; no part decoded, nothing re-judged), the `node/metas` rows, the parts table and the derived index tables, perm's inputs from `node/edges` and `group.0` states. `secrets.0` and `keys.0` states are not read (epochs and own keys persist).
- **Rebuild** once, re-judging every delta and writing the index (`write_all`: index tables dropped shredded first), when the store is tagged with other rules, a forget changed the records below the indexes (`index::invalidate`), or an index row fails to decode or is missing (`Engine::reload` retries as a rebuild). Damaged bytes cannot reach decoding: the store's AEAD makes them an open error (`Error::Store`).
- **`node/edges`**: per role commit (`Kind::is_role`), what perm's adaptation reads of its held `roles.0` parts (`validity::EdgeParts`: each entry's dot, the holder its key names and the grant its value reads, parsed as `edge_of` does). A pure function of the commit record, written by `Tx::put_commit` with the record every time the record is written (first apply, late parts in `join_late`, which reuses the row as its edge writes, `drop_part`, forget; same transaction, same shred flag; `Tx::remove_commit` removes it shredded), all of them by `write_all`. No tag of its own: the index's rules tag covers it. A debug build checks every row against its record at each fast open. Each row duplicates the decoded `roles.0` values of its commit.
- Perm's adaptation (`holder_keys`, unresolved removals) runs at every open over the rows, oldest first as a rebuild does, so the result is what a rebuild gives. Role-class snapshots reach perm on a fast open as on apply. `Core::snapshots` keeps each aspect's held snapshot bodies in (`ts`, ID) order: arrival order would make a fast open and a rebuild list them differently.
- **Lazy headers**: `Meta::header` is a `LazyHeader` (derefs to `Header`), decoded on first use from the record's header bytes (hash checked against the ID then; `Header::from_stored_value` skips what was verified on arrival: delete-key point decompression, inline-list size re-encode). `Meta::view` is what open's indexes read (`index_commit`, `index_validity`, the role filter, `commit_ids`); perm's adaptation reads the view (`validity::add_role_commit`: kind, ts, author, actor, form, per aspect tid and range, the frontier) and the `node/edges` row. An open decodes only headers with a list by link (resolved from blobs); a debug build decodes every header and asserts its view equals the row's.
  - A lazy decode cannot fail (the bytes hash to the ID and were verified on arrival under these rules); if it does, it reads as the view with empty fields and fails every later transaction (`Core::header_fault`, `Error::Corrupt`).
  - Commit records stay scanned at open: header bytes are kept in memory, since readers outside a transaction have no store.
  - `Core::by_chunk` (blob -> commits listing it, from `View::chunks`) serves what would scan every header's chunk list (`chunk_ops`'s reuse, `relink`, forget's kept blobs, sync's `dropped_chunks` and `replaced_leftovers`); `label_bodies_meta` finds a group's commits through `by_thing` and `by_aspect` (debug: equal to the scan of views).
  - Whole-map iterations over `Core::commits` that remain: views only (`commit_ids`, the open's role filter, sync's `acted`), keys only (`index::write` all), after a rebuild, tests, and rare paths commented as decoding every header (`held_commits` without a scope, forget's lost aspects, the debug check after each re-judge, `forget_dropped` in full passes decoding only commits with dropped parts).
- **Saved walks** (`node/walks`; osis-perm `cache.rs`, notes/permissions.md Implementation): perm's timelines come from them (`index::update_timelines_saved`). A component resumes a walk saved under any of its things (root first) whose tag matches these rules and its held inputs, continued as at run time over leaf things and commits added since; otherwise it is evaluated. A unit that does not match or read is evaluated anew, never an error. Walks are written in the transaction that persists the index, after it (`index::write`: `Timelines::to_save`, components of at least `WALK_CACHE_MIN` = 64 commits, rewritten once grown by a quarter), shredded, so none runs ahead of its commits; `Timelines::saved` marks them only once the transaction is durable (`Engine::run`). `write_all` saves every component of the minimum; an open that evaluated a component saves it in one more transaction (failure ignored). A forget or a rules change drops the table with the others.
- Test: walks.rs `open_equals_rebuild_after_*` (a validity flip, an un-merge, a forget, a crash at every write, demotions with inline and linked frontiers: the open equals a rebuild); `open_equals_rebuild_random_histories*`.

## Open costs
`scale::role_change_and_open_cost` (release, least of three opens, 16 cores at load about 11): 10^4 content commits open in 24 ms (a rebuild from every commit record: 126 ms). Plus 10^4 edge writes by the node on its 100 things: 108-111 ms (the index 44 ms: headers 18, metas 26-27; perm's adaptation 29-32, of which `node/edges` rows 8.5; walk restore 30). 10^4 edge writes by 5 admins with demotions every 40, at the owner: 109 ms with the walk restored, 117 ms evaluated anew. Open is still O(commits) (issues/node-core-gaps.md).
