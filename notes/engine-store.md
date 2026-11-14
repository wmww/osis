# Engine store records and the persisted index
> Summary: What the engine keeps in its encrypted `Store`: local record prefixes, store kinds (aspect units and their three tables), the rebuildable `node/*` index tables, and how an open uses them (the rules tag, `node/edges`, lazy headers, saved role walks), with open costs. Not here: the store itself (units, key tree, shredding: notes/local-store.md), sync's `y/` records (notes/sync.md), paging layouts (notes/engine-paged.md). Module map: notes/engine.md.

## Local records
Layouts in `engine/records.rs` (and the module named); all are `*_local` store records.

| prefix | holds |
|---|---|
| `seed`, `hlc` | the node seed; the last `ts` issued or seen |
| `c/`+commit | applied commit records: a head (`index::record_head`, version 1: received, origin, dropped parts with what each keeps (`Hold::Dropped`), stripped parts and whether each leftover keeps own values (`Hold::Leftover`), the canonical bytes of the header's linked lists), then the current blob. A held header is whole in its record (its list blobs go at the commit's expiry, spec/wire.md §5), so no open reads them |
| `t/`+tid | creation records |
| `a/`+aspect | aspects with a state (`aspects.0`) |
| `v/`+aspect | value-less deltas (expired, purged): the join-time strip list |
| `w/`+aspect+commit+ai | leftovers (notes/engine-retention-purge.md) |
| `p/`+aspect, `pn/`+aspect+commit, `z/`+commit+tid | purge requests on a whole aspect or author; requests naming a commit; a request that dropped a permanent delta (`retention::lasting`) |
| `x/`+T+commit+ai | timers (expiry, keep bounds) |
| `s/`+tid | things this node was asked to sync |
| `o/`+commit | commits voided by overlapping session ranges |
| `g/`+tid+commit | `keys.0` parts whose held body wrote a keyset, any validity (`ix.keyset_parts`, kept while the commit is held); `own_keys` = things with such a part valid (`apply::keys::refresh_own_keys`, on noting, flips, load), so an uncover keeps it and an invalid rotation drops it |
| `k/`+actor | opened epochs of an actor (`established`, `claims`, `snapshot`; never re-inferred). A plain thing's leftover epochs here are reading-only overlays on its derived ones (`Core::own_epochs`/`epochs`) |
| `b/`+commit+tid | pending boxes kept sealed by forgetting (`apply/keys.rs` `SEALED`; notes/engine-lost-access.md) |
| `q/`+aspect | suspect flags: le64 wall ms last raised, then per body its commit, aspect index and `Why` bits (`retention/suspect.rs`) |
| `l/`, `T/`, `K/`, `B/` | the lost-access work list, timed losses, kept copies, bearers (`rotation/lost.rs`) |
| `d/`+AK | the local schema of each app AK (canonical form) |
| `u/`+name | API records (account, home group, settings) |
| `sides` | sides taken in admin disputes (`sides.rs`): per (edge write, holder) trusted and chosen flags |
| `i/v` | the persisted index's rules tag |
| `sy/`, `rn/`, `ow/`, `iw/`, `ih/`, `cp/`, `hw/`, `fm/`, `se/`, `bp/` | the tables the engine keeps for sync (notes/sync-facade.md) |

Other store kinds (osis-store's catalog):
- **Aspect units**: the state (snapshot grammar with its pages inline, or for a paged state `[1, skeleton, [[set ID, path, encoding]*]]`: paged collections reduced to their reset and `W`).
- **Aspect tables** (`engine/pages.rs`, notes/engine-paged.md): table 0 state pages (key = set ID ‖ order-preserving bytes of the page's first dot, the first page the set ID alone; value `[first dot, next page's first dot, page]`); table 1 paged maps by key and paged sets by value (set ID ‖ keyed BLAKE3 of the key or value, links by content hash (`pages::ident`, key `Core::key_salt` from the node seed) ‖ entry or element dot; a superset, rebuilt with the layout); table 2 a paged sequence's placement (layout: the comment above `Place` in `pages.rs`). Tables 1 and 2 are rebuildable: written with the layout, the unit tag naming their rules.
- Counters (memory overlay rows only, notes/engine-apply.md Counters), pending and parked commits, blob ciphertexts (pages, chunks, header-list trees).

## Index tables
Rebuildable `node/*` tables (`engine/index.rs`), an index, never the truth: a store whose index fails to read is rebuilt from the commit records.
- `node/metas`: per commit a byte per part (valid, the rotation role it needs, a grant's overreach), and the header's `View`. Every input of a part's judgment that comes from its body is in the row, so a fast open judges a held part as the running node did.
- `node/boxes to`, `node/epoch intro`, `node/keysets`, `node/delete hints`, `node/required`, `node/snapshots` (per aspect, with frontiers), `node/edges`, `node/walks`, `node/refs to` and `node/refs from` (the reference index, notes/engine-refs.md).

## Open (`apply::load`)
- **Fast open** with an index of these rules (tag `i/v`: package version and the build script's hash of the engine's and its osis dependencies' sources, not sync's): reads the commit record heads and header bytes (extent by `osis_base::item_prefix`; no part decoded, nothing re-judged), the `node/metas` rows, the parts table and the derived index tables, perm's inputs from `node/edges`, the `group.0` states a page at a time (`groups::load`) and the `account.0` states. `secrets.0` states are not read (epochs and own keys persist); `keys.0` states are read by neither open (observing one only ends delete hints, which a load reads from the index or not at all).
- **Rebuild** once, re-judging every delta and writing the index (`write_all`, index tables dropped shredded first), when the store is tagged with other rules, a forget changed the records below the indexes (`index::invalidate`), or an index row fails to decode or is missing (`Engine::reload` retries as a rebuild). Damaged bytes never reach decoding: the store's AEAD makes them an open error (`Error::Store`). So a stored commit record decodes decode-only (`CommitBlob::decode_stored`: this node's canonical encoding, each part's delta kept as bytes), as stored states do; a parked row may hold a peer's bytes as received, so reexamining one uses `CommitBlob::decode` (`apply::read_pending`).
- **`node/edges`**: per role commit (`Kind::is_role`), perm's reading of its held `roles.0` parts (`validity::EdgeParts`: each entry's dot, the holder its key names, the grant its value reads, as `edge_of` parses). A pure function of the commit record, written by `Tx::put_commit` whenever the record is written (first apply; late parts in `join_late`, passing `apply::PartsRead::edges` of what they applied: role-class parts join whole, so the record holds exactly those; `drop_part`; forget; same transaction and shred flag; `Tx::remove_commit` removes it shredded), all by `write_all`. Covered by the index's rules tag. The index check compares the rows with a rebuild's reading (`Core::rebuilt_edges`): one row per role commit, none other. Each row duplicates its commit's decoded `roles.0` values.
- Perm's adaptation (`holder_keys`, unresolved removals) runs at every open over the rows, oldest first as a rebuild does. Role-class snapshots reach perm on a fast open as on apply. `Core::snapshots` keeps each aspect's held snapshot bodies in (`ts`, ID) order, so a fast open and a rebuild list them alike.
- **Lazy headers**: `Meta::header` is a `LazyHeader`, decoded on first use from the record's header bytes (hash checked against the ID; `Header::decode_stored` skips what was verified on arrival: delete-key point decompression, inline-list size re-encode). Open's indexes read `Meta::view` (`index_commit`, `index_validity`, the role filter, `commit_ids`); perm's adaptation reads the view (`validity::add_role_commit`) and the `node/edges` row. An open decodes only headers with a list by link; debug builds assert a decoded header's view equals the row's, and the index check's rebuild decodes every header.
  - A lazy decode cannot fail (bytes hash to the ID and were verified on arrival); if it does, it reads as the view with empty fields and fails every later transaction (`Core::header_fault`, `Error::Corrupt`).
  - Header bytes stay in memory: readers outside a transaction have no store.
  - `label_bodies_meta` finds a group's commits through `by_thing` and `by_aspect` (debug: equal to the scan of views).
  - Whole-map iterations over `Core::commits` left: views only (`commit_ids`, the open's role filter, sync's `acted`), keys only (`index::write` all), after a rebuild, tests, and rare paths commented as decoding every header (`held_commits` without a scope, forget's lost aspects, the debug check after each re-judge, `forget_dropped` in full passes, decoding only commits with dropped parts).
- **Saved walks** (`node/walks`; osis-perm `cache.rs`, notes/permissions.md Implementation): perm's timelines come from them (`index::update_timelines_saved`). A component resumes a walk saved under any of its things (root first) whose tag matches these rules and its held inputs, continued over leaf things and commits added since; otherwise, or when a unit does not match or read, it is evaluated anew, never an error. Walks are written after the index in the transaction that persists it (`index::write`: `Timelines::to_save`, components of at least `WALK_CACHE_MIN` (64) commits, rewritten once grown by a quarter), shredded, so none runs ahead of its commits; `Timelines::saved` marks them once the transaction is durable (`Engine::run`). `write_all` saves every component of the minimum; an open that evaluated a component saves it in one more transaction (failure ignored). A forget or a rules change drops the table with the others.
- Test: the debug index check after sampled transactions (`Engine::check_index`, notes/test-harnesses.md Index check: an open and a rebuild equal the running node); damage, crashes and restores in `caches::`.

## Open costs
An open restores the persisted index and the saved walks, rebuilding nothing (`scale::grant_is_flat_in_content_commits`), but is still O(commits): it reads every header (issues/node-core-gaps.md).
