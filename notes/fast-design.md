# Fast by construction: design
> Summary: Design (Fathom, under Tess's direction in notes/api-design.md) for making the ergonomic way the fast way across core, kit and app: a render depends on exactly what it read through a tracking `osis` handle, kit is a dependency graph of memo nodes, lists are windowed by construction, a harness checks every view. Findings, design, build plan.

Counts in section 1 and 2 are from reading the code. Symbols: H things held, P messages on the page, Q the walk to the oldest quote, W rows visible, S live listeners.

## 1. How a view gets data today
- A render reads osis directly through `cx.data.db` or `Data`. Listening is separate and imprecise: `Ui::watch` holds one `on_thing_change` per held thing, each facet has `live()` (chat: `on_fire`), plus `on_status_change`. Every listener posts the same `Msg::Changed`.
- `Msg::Changed` runs `refresh_inner`, which walks and re-renders the whole tree (`sync_node`). `fill_blocks` then compares `Vec<Block>` and rebuilds only slots that differ.
- One message into an open chat, window at least 760 px:
  - **Core:** `targets` scans all S listeners. Per notes/api.md, `listing_moved` also costs O(commits held at that aspect), twice per transaction.
  - **Held things:** `Data::things()` runs 6 times (`opened` 1, bar `is_favorite` 2, rail `favorites` 2, `watch` 1). That is about 12H engine reads whatever changed.
  - **Chat:** `recent` runs twice, because the opener renders its child once just to learn `has_foot`: 2 × (P + Q) commits read.
  - **Chrome:** `reach`, `changed` and `undo_target` re-read.
  - **Widgets:** the stream slot rebuilds all P rows (a `Panel` with up to 4 children each) and lays them all out.
- So cost grows with H, Q and P, and does not depend on window size. A status change or a typing pause pays the same refresh even though the chat's content did not change.

## 2. Where the easy path costs too much, widest effect first
1. Whole-tree refresh is the only update path, so every view inherits it.
2. Listening is declared apart from reading, so it is both too broad (per thing) and too narrow to trust (`live()`).
3. Lists are `Vec<Entry>`. `NEWEST` caps only streams, cards and rows build all, nothing is keyed (`list.rs` is unused), and there is no `VirtualScroll`.
4. Innocent `Data` calls are O(H): `opened`, `favorites`, `is_favorite`, `collections`, `all_tags`. Memo caches live on `Cx`, which is rebuilt per node, so `summary` and `aspects` are not shared.
5. Core dispatch is O(S × changed) per event; `listing_moved` is O(commits held).
6. `on_thing_change` keeps a materialized copy of every aspect (`last`), so the shell holds O(all held bytes) in memory and reads it all at startup.
7. Calendar `entries` calls `overridden` over all things per event: O(events × H) per render. It also runs inside `summary`-driven sorts.
8. The `members` facet's `summarize` runs `items`, which is O(H) and sorts, per collection tile. By reading (not run), two Everything collections sorted by name recurse through each other's summaries without end: a stack overflow.
9. `search` is O(H × facets) per keystroke, again on any background change, and `tags_of` per remaining thing.
10. `tags_of` and `Delete` scan `members(g)` where `groups_of` answers directly.
11. Chat `Timeline`/`find_all` walks history per render (no edit index).
12. `about`: `account_name` scans all things for each unnamed person; `undo_target` runs on every refresh; `pending` re-reads fields.
13. The same work twice: `has_foot` render, `things` per call, `groups()` per `cx.state`.

## 3. The design
**Rule: a render depends on exactly what it read, and has no other way to read.** This completes the existing principle in notes/listener-design.md: every read has one listener at the same address, so a read can subscribe itself. No parallel system.

**Core** (one new noun, no second read API)
- `ReadSet::new(on_change)`, `db.tracking(&set) -> Osis`, a handle variant like `act_as`, and `set.sweep()`.
- On a tracking handle, every read subscribes as it reads, under the lock `subscribe` already takes. So there is no gap between read and listen, on any dispatcher.
- It keeps listeners already in the set; `sweep` drops those not read since the last sweep.
- It uses the existing filters, with no initial call. Reads that have no listener today get an internal one with no new public API: `aspects` (set of names only), `groups_of`, `role_on`, `has_content`, `created`, `changed`.
- `undo_target` listens as `on_write(scope)`.
- Value listeners keep a hash of the last value, not the value.
- Dispatch is indexed by (tid, ak) and tid: O(log S + matched). `listing_moved` judges only the commits a join superseded.
- `role_on` and `holders` have no single address: their reach is the role graph, so they listen on every roster and key change (brute force, on the rare path), compare, and fire on a difference.

**Kit** (a dependency graph, not a framework; built: libs/kit/src/view/graph.rs)
- One node type: a key, a value, a `ReadSet`, a dirty flag. A view render is a node, `cx.memo(key, f)` is a node, and **every address a render's `db` reads is a node** (`view::Db::leaf`), so an address is read once and listened to once however many memos ask. Equal output stops propagation.
- Dirty marks: a fired `ReadSet` queues its node; the queue becomes `Dirty` on the node and `Check` on what depends on it. Asking for a `Check` node validates its dependencies in the order read (each dependency has a seq bumped when its value differs) and runs only if one moved, so equal output stops the run. A node asked for while it runs is a cycle: an error, nothing cached.
- `Cx` holds `Reader` (a tracked `Db`, the read half of `Osis`, plus every `Data` read) and no write methods. Actions get `Act` (`Data`, untracked, writes, effects). A write during render does not compile. `Data` is `Reader` plus writes.
- `things`, `favorites`, `groups`, `summary` and `aspects` are shared memos. The opener asks for the child node's foot, so nothing renders twice.
- Passing state not in osis (scroll range, search query, the minute tick for "5 min ago") is a local cell (`Local`), a node set from outside. `db.now()` stays untracked; `cx.ago` reads the tick.
- The renderer re-runs dirty nodes only, parents first, and reconciles rows by key with `list.rs`.
- **Windowed by construction:** the only list block is `cx.list(page, |cx, key| Entry)`. `page(from, n)` returns keys, and the closure runs only for rows the `VirtualScroll` shows. A set source pages a key index built from per-item memos, so one change costs one item (first build O(H), once). History sources page through `fired`.
- A `Vec<Entry>` block cannot be built.

**App:** facets read `cx.db` as today, and `Facet::live` goes. Chat's read path, `recent`, becomes a `cx.list` page; quote text stays a memo until step 9.

**One message after this:** one matched listener, page memo reads O(W) commits, one node re-renders, one row is built. Things, favorites, rail and chrome are not touched.

Why this passes the notes:
- **notes/api-design.md:** one read API, one new concept, and compile-time rejection of writes in render.
- **notes/app.md:** views stay data-driven, and memo and list are general concepts that name no feature.

## 4. Holding it there
Counters: the existing `osis::costs` spans (extended to count engine reads and dispatched targets) plus graph counters (renders, memo reruns, rows built). A new kit test, `view_costs`, walks `registry.views`, so a new view is covered when it registers. `ViewType` gains a required `sample: fn(&Data) -> Tid`, usually one line through an `Offer`, so a view without one does not compile.

For each view the harness checks:
- **Precision:** a write to an address the node did not read causes 0 renders; a write to one it did causes exactly that node (generic, driven by the recorded `ReadSet`).
- **Scale:** grow what the view read at n and 10n; reads and rows built stay within a fixed ratio.
- **No duplicates:** no address is read twice in one pass.
- **Window:** rows built are at most W.

Hand-written, for what the harness cannot generate:
- One chat message, at n and 10n: 1 render, at most c·W rows read, 1 row built.
- One `ui:week.0` entry write re-renders 1 node (listener step 8).
- Core dispatch counts at 10n unrelated listeners.

All of these count work, never wall time.

## 5. Build plan (one worker plus reviewer each; the app works after each)
Steps 1, 2 and 3 are built (notes/api.md Watching; libs/kit/src/view/graph.rs). Step 3 also deleted `watch`, `subs`, `live`, `Facet::live`, `Notify`, `LiveEnded` and the status subscription: a fired read queues its node, and one queue message drives the whole-tree refresh.
1. Core: indexed dispatch, hashed `last`, `listing_moved` by touched commits; kit adopts `Dispatcher::Pump` (delete `marshal`).
2. Core: `ReadSet` and the tracking handle over every read; notes/api.md and the api-design checklist.
3. Kit: graph, `Cx`/`Act` split, shared memos, whole tree still refreshed. Removed the 12H reads and fixed the summary recursion (a summary counts unsorted: `source::count`).
4. Kit: dirty-only renderer (listener step 8 lands). Delete `Ui::refresh`, `sync`, `sync_node`, `Msg::Changed`.
5. `view_costs` harness: precision, duplicates, `sample` on every view.
6. Keyed reconcile for stream, cards and rows, wiring in `list.rs`.
7. `cx.list` and `VirtualScroll`; delete `NEWEST` and `Window::Newest`; harness adds scale and window.
8. Expensive paths: per-item source index, `overridden` as one memo, `search` as a memo over the query cell and per-item text, `tags_of` by `groups_of`, `reach` memo.
9. Core edit index (issues/signal-edits.md) if Tess agrees; quotes become a lookup.

`on_thing_change` stays for the CLI and port (it has left kit).
