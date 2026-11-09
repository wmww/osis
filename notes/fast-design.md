# Fast by construction: design
> Summary: Design (Fathom, under Tess's direction in notes/api-design.md) for making the ergonomic way the fast way across core, kit and app: a render depends on exactly what it read through a tracking `osis::ReadOnly` handle, kit is a dependency graph of memo nodes, lists are windowed by construction, a harness checks every view. Findings, design, build plan.

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
- `ReadSet::new(on_change)`, `db.tracking(&set) -> ReadOnly`, the read-only handle `Osis` derefs to, and `set.sweep()`.
- On a tracking handle, every read subscribes as it reads, under the lock `subscribe` already takes. So there is no gap between read and listen, on any dispatcher.
- It keeps listeners already in the set; `sweep` drops those not read since the last sweep.
- It uses the existing filters, with no initial call. Reads that have no listener today get an internal one with no new public API: `aspects` (set of names only), `groups_of`, `role_on`, `has_content`, `created`, `changed`.
- `undo_target` listens as `on_write(scope)`.
- Value listeners keep a hash of the last value, not the value.
- Dispatch is indexed by (tid, ak) and tid: O(log S + matched). `listing_moved` judges only the commits a join superseded.
- `role_on` and `holders` have no single address: their reach is the role graph, so they listen on every roster and key change (brute force, on the rare path), compare, and fire on a difference.

**Kit** (a dependency graph, not a framework; built: libs/kit/src/view/graph.rs, view/tree.rs)
- One node type: a key, a value, a `ReadSet`, a dirty flag. A view render is a node and `cx.memo(key, f)` is a node; sharing a read between nodes is a memo, as `things` and `summary` are (a node's `db` holds one listener per address it read). Equal output stops propagation. A memo's function is a plain `fn(&Reader, &K)`: it captures nothing, so it cannot depend on anything but its key and its reads. A failed dependency stays a dependency: a node that handled the error is asked again, never `Clean` over it.
- Dirty marks: a fired `ReadSet` queues its node; the queue becomes `Dirty` on the node and `Check` on what depends on it. Asking for a `Check` node validates its dependencies in the order read (each dependency has a seq bumped when its value differs) and runs only if one moved, so equal output stops the run. A node asked for while it runs is a cycle: an error, nothing cached.
- `Cx` holds `Reader` (`db`: a tracked `osis::ReadOnly`, plus every `Data` read) and no write methods. Actions get `Act` (`Data`, untracked, writes, effects). A write, a listener, a session, the clock and creating the profile do not compile on `ReadOnly` (doc tests in core/osis); `Reader::now`/`now_local` are the only clock and move with the tick. `Data` is `Reader` plus writes. The account's profile is made at open and when a peer arrives (`Data::ensure_profile`), never by a read.
- `things`, `favorites`, `groups`, `summary` and `aspects` are shared memos. The opener asks for the child node's foot, so nothing renders twice.
- Passing state not in osis (scroll range, search query, the minute tick for "5 min ago") is a local cell (`Local`), a node set from outside. `Reader::now` and `now_local` in a render depend on the tick, so whatever shows a time moves with it; `Cx` reaches no other clock.
- The renderer (`Tree`) re-runs marked nodes only, parents first; a parent that came out different reconciles its children (a child whose slot was rebuilt is refilled from its value, unrun). A node that fails stays in the tree and its siblings go on, so the read that recovers marks it; marks walk past nodes already marked, which a failure can have left unqueued. The shell's own reads are a node too; its results and New chips are view types. Rows of a stream, cards or rows block reconcile by key (`view/keyed.rs`, `list.rs`): one changed row rebuilds that row, and the widgets around it stay.
- What a node reads twice is a memo (`members`, `tag`, `collection`, `name`, `window_opt`): one listener per address per node, by construction.
- **Windowed by construction:** the only list block is `cx.list(page, |cx, key| Entry)`. `page(from, n)` returns keys, and the closure runs only for rows the `VirtualScroll` shows. A set source pages a key index built from per-item memos, so one change costs one item (first build O(H), once). History sources page through `fired`.
- A `Vec<Entry>` block cannot be built.

**App:** facets read `cx.db` as today, and `Facet::live` goes. Chat's read path, `recent`, becomes a `cx.list` page; quote text stays a memo until step 9.

**One message after this:** one matched listener, page memo reads O(W) commits, one node re-renders, one row is built. Things, favorites, rail and chrome are not touched.

Why this passes the notes:
- **notes/api-design.md:** one read API, one new concept, and compile-time rejection of writes in render.
- **notes/app.md:** views stay data-driven, and memo and list are general concepts that name no feature.

## 4. Holding it there
Counters: `osis::costs` spans (`read: engine`, `watch: considered`, `watch: dispatched`) plus `Graph::take_costs` (renders, memo runs, rows built). `osis_kit::testing::check_views` walks `registry.views`, so a new view is covered when it registers; kit's `view_costs` test runs it on kit's registry, the app's on the app's. `ViewType` has a required `sample: fn(&Data) -> Tid`, usually one line through an `Offer`, so a view without one does not compile.

For each view the harness checks:
- **Precision (built):** every aspect of the things it read, each moved in turn, and each aspect set and group membership it read: only the nodes that read that address (and what depends on them, and what reads the whole thing: `changed`, its commits) run, each reader exactly once; a write to an unread thing runs nothing.
- **Nothing stale (built):** after every such write the screen equals a fresh render of the current data, which catches a read no listener covers.
- **Reach (built):** a view whose sample shows no block, or none of whose reads could be moved, fails; a sample that shows a thin view (no rows) is not detected.
- **No duplicates (built):** no node reads an address twice. Nodes reading one address separately are not checked (raw's name, body and aspects; the opener's `groups_of` and `ui:raw.0`; a profile in results): one read per node and per address, a constant.
- **Scale and window (step 7):** grow what the view read at n and 10n; reads and rows built stay within a fixed ratio; rows built are at most W. Until then only the hand-written rows tests at n and 5n guard scale.

Hand-written, for what the harness cannot generate:
- One chat message, at n and 10n: 1 render, at most c·W rows read, 1 row built.
- One `ui:week.0` entry write re-renders 1 node (listener step 8).
- Core dispatch counts at 10n unrelated listeners.

All of these count work, never wall time.

## 5. Build plan (one worker plus reviewer each; the app works after each)
Steps 1 to 6 are built (notes/api.md Watching; libs/kit/src/view/graph.rs, view/tree.rs, view/keyed.rs, testing.rs).
1. Core: indexed dispatch, hashed `last`, `listing_moved` by touched commits; kit adopts `Dispatcher::Pump` (delete `marshal`).
2. Core: `ReadSet` and the tracking handle over every read; notes/api.md and the api-design checklist.
3. Kit: graph, `Cx`/`Act` split, shared memos (a summary counts unsorted: `source::count`).
4. Kit: dirty-only renderer; `osis::ReadOnly` as the one read surface.
5. `view_costs` harness: precision, duplicates, `sample` on every view.
6. Keyed reconcile for stream, cards and rows, wiring in `list.rs`.
7. `cx.list` and `VirtualScroll`; delete `NEWEST` and `Window::Newest`; harness adds scale and window.
8. Expensive paths: per-item source index, `overridden` as one memo, `search` as a memo over the query cell and per-item text, `tags_of` by `groups_of`, `reach` memo.
9. Core edit index (issues/signal-edits.md) if Tess agrees; quotes become a lookup.

`on_thing_change` stays for the CLI and port (it has left kit).
