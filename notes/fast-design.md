# Fast by construction: design
> Summary: How the ergonomic way is the fast way across core, kit and app (Tess's rule in notes/api-design.md), as built: a render depends on exactly what it read through a tracking `osis::ReadOnly` handle, kit is a dependency graph of memo nodes, lists are windowed by construction, and a harness checks every view. Why, the design, and how it is held there.

Symbols: H things held, P messages on the page, W rows visible, S live listeners.

## 1. Why
A view system where listening is declared apart from reading, every change re-renders the whole tree and lists build every row makes every view's cost grow with what is held (H) and the page (P), not with what is shown (W): one chat message cost about 12H engine reads plus every row of the page, and a status change or a typing pause paid the same.

## 2. Paths the design keeps closed
1. Whole-tree refresh as the only update path, so every view inherits it.
2. Listening declared apart from reading: too broad (per thing) and too narrow to trust.
3. Unwindowed lists: every row built.
4. Innocent helper calls that are O(H), and caches per node instead of shared.
5. Core dispatch O(S × changed) per event; listing changes O(commits held).
6. Listeners keeping a materialized copy of every value they watch.
7. The same work twice (a parent rendering a child to learn its shape).

## 3. The design
**Rule: a render depends on exactly what it read, and has no other way to read.** This completes the principle in notes/listener-design.md: every read has one listener at the same address, so a read can subscribe itself. No parallel system.

**Core** (one new noun, no second read API)
- `ReadSet::new(on_change)`, `db.tracking(&set) -> ReadOnly`, the read-only handle `Osis` derefs to, and `set.sweep()`.
- On a tracking handle, every read subscribes as it reads, under the lock `subscribe` already takes. So there is no gap between read and listen, on any dispatcher.
- It keeps listeners already in the set; `sweep` drops those not read since the last sweep.
- It uses the existing filters, with no initial call. Reads with no public listener get an internal one: `aspects` (set of names only), `groups_of`, `role_on`, `has_content`, `created`, `changed`.
- `undo_target` listens as `on_write(scope)`.
- Value listeners keep a hash of the last value, not the value.
- Dispatch is indexed by (tid, ak) and tid: O(log S + matched). `listing_moved` judges only the commits a join superseded.
- `on_thing_change` is not used by kit (the CLI and port keep it).
- `role_on` and `holders` have no single address: their reach is the role graph, so they listen on every roster and key change (brute force, on the rare path), compare, and fire on a difference.

**Kit** (a dependency graph, not a framework: libs/kit/src/view/graph.rs, view/tree.rs)
- One node type: a key, a value, a `ReadSet`, a dirty flag. A view render is a node and `cx.memo(key, f)` is a node; sharing a read between nodes is a memo, as `things` and `summary` are (a node's `db` holds one listener per address it read). Equal output stops propagation. A memo's function is a plain `fn(&Reader, &K)`: it captures nothing, so it cannot depend on anything but its key and its reads. A failed dependency stays a dependency: a node that handled the error is asked again, never `Clean` over it.
- Dirty marks: a fired `ReadSet` queues its node; the queue becomes `Dirty` on the node and `Check` on what depends on it. Asking for a `Check` node validates its dependencies in the order read (each dependency has a seq bumped when its value differs) and runs only if one moved, so equal output stops the run. A node asked for while it runs is a cycle: an error, nothing cached.
- `Cx` holds `Reader` (`db`: a tracked `osis::ReadOnly`, plus every `Data` read) and no write methods. Actions get `Act` (`Data`, untracked, writes, effects). A write, a listener, a session, the clock and creating the profile do not compile on `ReadOnly` (doc tests in core/osis); `Reader::now`/`now_local` are the only clock and move with the tick. `Data` is `Reader` plus writes. The account's profile is made at open and when a peer arrives (`Data::ensure_profile`), never by a read.
- `things`, `favorites`, `groups`, `summary` and `aspects` are shared memos. The opener asks for the child node's foot, so nothing renders twice.
- Passing state not in osis (scroll range, search query, the minute tick for "5 min ago") is a local cell (`Local`), a node set from outside. `Reader::now` and `now_local` in a render depend on the tick, so whatever shows a time moves with it; `Cx` reaches no other clock.
- The renderer (`Tree`) re-runs marked nodes only, parents first; a parent that came out different reconciles its children (a child whose slot was rebuilt is refilled from its value, unrun). A node that fails stays in the tree and its siblings go on, so the read that recovers marks it; marks walk past nodes already marked, which a failure can have left unqueued. The shell's own reads are a node too; its results and New chips are view types. Rows of a stream, cards or rows block reconcile by key (`view/keyed.rs`, `list.rs`): one changed row rebuilds that row, and the widgets around it stay.
- What a node reads twice is a memo (`members`, `tag`, `collection`, `name`, `window_opt`): one listener per address per node, by construction.
- **Windowed by construction** (`view/paged.rs`, `widgets/vlist.rs`): the only list block is `cx.list(id, shape, page, row)`. `page(at, n)` returns keys of a window (`At::{Start, End, From(k), Before(k)}`), `row` runs only for those. The window is a keyed local cell (`LIST_WINDOW`, by list path): an anchor key and rows either side. `VirtualList` asks for a new window as the viewport nears an edge; the shell sets the cell, one node re-renders, keyed steps touch only rows that differ. Rows are at most a window (`WINDOW`, `MAX_SIDE`), so a `Vec` insert in the widget and the keyed diff are bounded by the window, not the list.
- A list keeps its place by key: the row at the top stays at the same offset whatever comes or goes around it, so a row inserted above does not jump the view and a re-render leaves the position alone. A list that follows its end (a stream) pins to the bottom while there; scrolling up unpins it.
- A set source pages an index over per-item memos (`source::items`, `item_index`): one item changing reads that item, and the index reruns over memo lookups (no store reads). A stream pages per-thing heads (`arrange::stream_page`) and reads a thing directly past its head, one page from the anchor's sort key (`Facet::stream` takes it: a facet keys rows of one time to sort as it pages them). A chat page is one `fired` page (edits folded by osis), each quote a memo per quoted message over `commit(id)`, which tracks that commit alone: an edit reruns the page read and the edited message's quote, rebuilds its row and the rows quoting it, nothing else.
- `VirtualList` carries the scrolling a page's scroller did: a bar in a gutter (over the whole list where its source knows the length, `Page::total`, by jumping to a row; over the loaded rows otherwise, a stream), PageUp/PageDown/Home/End/arrows, assistive-tech scroll actions, the wheel passed on at the list's edge. A row leaving under the top hands the place to the next row shown; a window names its row, so a list whose anchor key left resumes there. A page holding a list lays out at `MIN_PAGE` at least inside a scroller, so what surrounds it stays reachable in a short window. `Shape::scope` (the query) makes a changed scope a new list at its top.
- A `Vec<Entry>` block cannot be built: `List` has no public constructor; a `Day` is built only by `arrange::days` and holds at most `DAY_ROWS`.
- Masonry's `VirtualScroll` is not used: its dense ids cannot shift when a row is inserted above, and it cannot pin the last row to the viewport's bottom.

**App:** facets read `cx.db`; a chat is a `cx.list` over `fired` pages, its quotes memos per message.

**One message:** one matched listener, page memo reads O(W) commits, one node re-renders, one row is built. Things, favorites, rail and chrome are not touched.

Why this passes the notes:
- **notes/api-design.md:** one read API, one new concept, and compile-time rejection of writes in render.
- **notes/app.md:** views stay data-driven, and memo and list are general concepts that name no feature.

## 4. Holding it there
Counters: `osis_node::costs` spans (`read: engine`, `watch: considered`, `watch: dispatched`) plus `Graph::take_costs` (renders, memo runs, rows built). `osis_kit::testing::check_views` walks `registry.views`, so a new view is covered when it registers; kit's `view_costs` test runs it on kit's registry, the app's on the app's. `ViewType` has a required `sample: fn(&Data) -> Tid`, usually one line through an `Offer`, so a view without one does not compile.

For each view the harness checks:
- **Precision:** every aspect of the things it read, each moved in turn, and each aspect set and group membership it read: only the nodes that read that address (and what depends on them, and what reads the whole thing: `changed`, its commits) run, each reader exactly once; a write to an unread thing runs nothing.
- **Nothing stale:** after every such write the screen equals a fresh render of the current data, which catches a read no listener covers.
- **Reach:** a view whose sample shows no block, or none of whose reads could be moved, fails; a sample that shows a thin view (no rows) is not detected.
- **No duplicates:** no node reads an address twice. Nodes reading one address separately are not checked (raw's name, body and aspects; the opener's `groups_of` and `ui:raw.0`; a profile in results): one read per node and per address, a constant.
- **Scale and window:** a view that lists something growable names how (`ViewType::grow`, required: `None` for a view that lists nothing that grows). The harness shows it at n and 10n: rows built at most a window; adding one more costs (renders, memo runs, addresses those runs read) within a fixed ratio and builds at most two rows. A chat grows by messages each quoting its first.

Hand-written, for what the harness cannot generate:
- One chat message, at n and 10n: 1 render, at most c·W rows read, 1 row built; one edit the same, no other quote run (app `views::an_edit_rebuilds_one_row_flat_in_history`, `a_new_message_reruns_no_quote`); a page deep in the chat reads the same at n and 10n (`chat_pages_read_flat_in_history`).
- One `ui:week.0` entry write re-renders 1 node (listener step 8).
- Core dispatch counts at 10n unrelated listeners.

All of these count work, never wall time.
