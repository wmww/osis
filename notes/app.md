# The first-party app
> Summary: The first-party app over osis and schema/ (decided with Tess). Start here before any change to app/ or libs/kit/: the rule that the app is divided by view and never by feature, with its tests; the model (things, facets, pages, entries, sources, arrangements, views as data); the code shape; the look; state in osis; the kit/app split; Masonry without Xilem; platform work; how to run it; the app as built.

## Direction (Tess)
- Fresh and timeless, not a bundle of generic apps over osis types. Bright colours, flatish but not distinctly flat, its own look rather than the native aesthetic.
- Oriented around data, not functionality: no "tab for notes, tab for calendar". Views show whatever combination of things they can meaningfully place.
- Responsive and lightweight on every device; webview is out. Native first, web later.
- Build first in something light, simple and running everywhere; if the UX suffers, rebuild differently. Platform work (Rust embedding, possibly an iOS shell of our own) is accepted for the sake of the right foundations in text, accessibility and low-level control.
- Convergent design, not a mobile/desktop split: one layout keyed on width and input kind, phone layout designed first, desktop adds columns. Touch on desktop supported.
- Do not copy the mockup closely: it is a test bed for the look and the theme spec. The app leans simpler and less distracting and chooses its own structure and UX. UX is figured out along the way, iterating once there is something to play with.
- Motion: almost none; only unobtrusive fades or motion that adds clarity.

**Fast by construction (Tess).** From core through kit to app, the most ergonomic way to build something also gives it the right performance, so it is hard to build anything slow. There is no typical use, so there is nothing to tune for: everything reacts only to what it should, nothing is done twice, and nothing scales with the wrong thing. Fix slowness by design and by refactoring as far as needed, never by profiling and tweaking hot paths or by hiding the slow thing. (notes/api-design.md)

## The rule: the app is divided by view, never by feature
A feature is something a user notices; it is not a place in the app or a module in the code. There is no notes area, calendar area or chat area, in the UX or the source. osis data is a graph of things carrying any mix of aspects, so an app shaped around one kind of data meets, at once, the same data nested, repeated, mixed with other kinds and carrying aspects it never planned for, and answers by growing a second copy of everything.

Good interfaces are specific; things are not. A calendar entry deserves a form made for it, yet no thing is only a calendar entry. The app resolves this by making *views* specific and *things* kindless: a view says which aspects it is good for, and any thing with those aspects can be seen through it, whatever else the thing carries. Views are built from reusable parts, each knowing how to show what is there. Target property: **once two pieces of functionality each work, they work together, without anyone having thought of the pair.** Something that should compose but needs code naming both pieces is a defect in the structure.

Tests for a change (apply before writing it, and in review):
- **Could this be a thing?** Whatever a user might want to arrange, name, tag, favorite, share or find is a thing shown by the ordinary machinery. Settings, a person's own name and saved views are things and aspects, not panels.
- **No kind.** A thing has no type. A view may be as specific as it likes about the aspects it is for, but nothing classifies a thing into one category: a view's fit is computed from aspects present, and several may fit. `if chat`, `match kind`, or a list of things "of type X" is the smell.
- **No destination.** No screen, tab, section or sidebar exists for one kind of data. Any thing opens the same way (below), and many things are shown by collections.
- **Name the general concept.** Before adding a widget or block, say what it is with the data removed: "a list ordered by time", never "the message list". If the concept is not reusable, the design is not finished. Two configurations of one implementation are still two views: "a list" and "a timeline" are different concepts even if they share code.
- **Facets do not know each other.** A facet file names only its own aspect family; shared behaviour goes through the facet contract. Only the registry lists facets. A second facet needing a first's data is a missing contract method.
- **Mix must work.** Every view accepts things it did not expect: no aspects it knows, several kinds of content at once, a thing appearing twice, a cycle, things unreadable or deleted. A view shows what it can place and leaves out, without error, what it cannot.

## Terms
Used exactly, in code and notes.
- **Thing**, **aspect**: as in spec/requirements.md. A thing has no kind.
- **Facet**: the app's knowledge of one aspect family: reading, writing, summary, search text, entries, offers. Draws nothing on its own terms: it supplies parts a view places.
- **View**: a node of the view tree: a *view type* (code), a *subject* and a *config*. Its output is `Block`s, some of which are child views.
- **View spec**: the data naming a view: type, subject, config. Plain, comparable, storable.
- **Config**: a view type's display properties (e.g. compact, read-only, what to show). The same code differently configured is the same view type. Unknown properties are ignored, so a stored config survives other versions.
- **View tree**: the window's nested views, rooted at the shell. Every piece of content on screen is a node. A node's identity is its path, which keys its state and its text sessions, so the same thing may appear twice at once.
- **Window**, **node state**: under State in osis.
- **Content view**: a view type that presents one thing's content for some combination of aspects (note, event, person, stream, collection). Knows nothing of how it was reached: no tabs, no tags or sharing chrome. Has a **fit**: computed from the aspects present; none means not offered.
- **Opener**: the generic view type a thing opened from anywhere gets. Selects a content view, shows tabs if several fit, holds the thing's chrome (bar, context menu, Add, places, who can see it, change and undo), and nests the content view.
- **Raw view**: the content view showing and editing every aspect from its schema type, kind-free.
- **Collection view**: the content view of many things: a collection config resolved to entries, arranged, each element a child view.
- **Element spec**: which view type and config a collection uses for its elements; default a tile. A named content view there is an embedding, so a board's cards are note views configured to look like cards, never the opener's choice.
- **Tile**: the small view type of a thing from its summary.
- **Entry**, **source**, **arrangement**: under Model.
- **Block**: the closed, toolkit-free presentation vocabulary a view outputs.

## Model
- **Thing**: the unit. No `kind` aspect exists (notes/tags.md); a thing is whatever its aspects make it, and may be several at once.
- **Facet** (`app/src/facets/`, one file per aspect family): everything the app knows about one family of aspects, behind one contract: whether it applies to a thing (the aspects are present), its contribution to the thing's summary (name, descriptor words, icon, colour), its section of the page, its entries, its search text, what it offers to add to a thing or create, and any live subscription it needs. Facets are data-driven: a facet is a part that content views assemble.
- **Opening a thing**: every open goes through the opener (Terms), which picks the content view with the best fit (accounting for the most of what the thing carries, ties by registry order), offers tabs when several fit, remembers the viewer's choice per account (`ui:viewed_as.0` on the app group; it works on what they cannot write; a stored choice that no longer fits falls back), and takes the whole space for its content when one fits. A thing no designed view fits opens in the raw view, which is otherwise reached from the thing's context menu and is never a tab.
- A view whose fit is capability, not data held (`always_offered`: Look, on the account group, before any choice is made) is offered although it accounts for no aspect yet. Home is the opener on the account group with `no_chrome`; collection and Look are its tabs.
- **Embedding a thing**: a parent that wants a specific presentation names a content view and its config directly. That view is always the one shown, with no choice, tabs or chrome, whatever else would fit better.
- **Entry**: one item a view shows: a key, the thing it belongs to and opens, and whichever of title, text, author, time, span and actions it has. By default a thing is one entry from its summary. A facet may instead expand a thing into several, not necessarily things themselves (the occurrences of a repeating event; the kept writes of a message aspect).
- **Source**: what a view looks at: a thing's members, everything held, or the account's favorites, narrowed by aspects present and ordered.
- **Arrangement**: how a set of entries is placed, independent of where they came from. Cards, rows, outline (nesting by subgroup; a cycle is cut at a repeat), days (by span, admitting only what has one), stream (by time, oldest first, following the end). Cards, rows and outline show one entry per thing; days and stream expand, so a stream or a week of a group merges everything its members contribute.
- **Collection config** = source + narrowing + order + arrangement + element spec, as data: `ui:collection.0` on any thing (schema/ui.osis). So a saved collection is a thing like any other, with a name, tags, a place among favorites and a page. The calendar, people, tags and recent seeds are four values of this aspect and nothing else. Home is the app group, a thing whose collection's source is the favorites. A collection's arrangement can be changed by whoever looks at it (`ui:arranged.0`, per account on the app group: it works on what they cannot write), and that choice beats the stored one.
- **Everything held** is the closure from the app groups and every group this store syncs (`status().groups`, less the account's home and the app groups) through tags' members. Nothing has to have been made by this app to appear.
- **Create** is an empty thing plus what the chosen facet offers; the default-view rule then opens it in the view that now fits. **Add** on any thing offers the same list, so a note gains a time and a chat gains a body by the path that made them.
- Every search hit, list and favorite goes through the same summary. Placing into a shared tag confirms the reach (notes/tags.md guideline).
- Tagging never shares: tagging a tag nests it as a subgroup, and sharing through a tag is core's `add_with_grant` (notes/tags.md); the app grants nothing itself (Tess). Backlinks from markdown (`body.0` has no tid reference syntax) are a library-side question (Tess).

## Code shape
Kit owns the view system, so a small app gets all of it; the app is a registry and its own facets.
- `libs/kit/src/view/`: toolkit-free. `Block`, `Cx` and `Act`, the dependency graph and the tree of shown views, `ViewSpec`, the `Action` and `Facet` traits, sources, arrangements, node state, the tree.
- `libs/kit/src/views/`: the generic view types (opener, collection, tile, raw, note, shell layout) and the fit rule.
- `libs/kit/src/facets/`: facets of core aspects (name, body, members, places, reach, changes, look).
- `libs/kit/src/render/`: Masonry widgets for `Block`s and the shell driver; with kit's widgets, the only code touching the toolkit.
- `app/src/`: facets and content views of its own schemas (event, contact, the message log and its stream), registering them with kit; seeds, demo, main.

Reading and writing are split by type: a render gets `Cx`, an action `Act`.
- **`Cx`** derefs to `Reader`, every read: `cx.db` (`osis::ReadOnly`: a write, a listener, a session, the clock or creating the profile does not compile in a render; `cx.now()` and `cx.now_local()` are the time), `cx.things()`, `cx.tags_of(t)`, `cx.state(key, node)`, `cx.summary(t)`. It also has the node's `path()`, `config()` and `window`. Reads through a render's `db` subscribe (the dependency graph, below).
- **`Act`** derefs to `Data` (`Reader` plus every write: `set_open`, `toggle_favorite`, `delete`, `db.write()`), holds the effects and sets node state (`set_state`). Its reads are untracked.
- **The graph** (`view/graph.rs`, notes/fast-design.md): one node type, a key, a value, a `ReadSet`, a dirty flag. A view render is a node; `cx.memo(key, f)` is a node; a local cell (`Local`: search query, the minute tick, dark, pending typing) is a node set from outside. Equal output stops propagation. Things held, favorites, groups, summary and aspects are shared memos.
- `f` given to `memo` is a plain `fn(&Reader, &K)`, told only the key: it cannot capture, so a memo depends on its key and its reads, not on where it is called from.
- `Reader` shares what many nodes read as memos, so a node holds one listener per address it reads: `things`, `favorites`, `groups`, `summary`, `aspects`, `members`, `tag`, `collection`, `name`, `window_opt`.
- **The tree** (`view/tree.rs`): the views on screen, each a graph node. A read that changed marks its node, the shell's update runs marked nodes parents first; a parent that came out different reconciles its children, and what is not marked does not run. The shell is a `Surface`.

Closed and open sets, deliberately:
- `Block` and the arrangements are closed: they are the vocabulary, and a new word has to be general. A feature that wants a new `Block` first has to state its general concept.
- Facets, `Action`s and per-section UI state are open: a facet defines its own action structs (`impl Action`, compared by value so a model stays comparable) and its own state type, with no central enum to extend. Actions get a typed `Input` (press, text, reorder).
- A slot per facet section is rebuilt only when its model changes, so editors keep their caret. Editors are `Block`s, each bound to its own session on a `(thing, field)`, kept while shown.
- A new aspect family is a new file in `facets/` and a line in the registry, and it then appears on tiles, search, every arrangement and the raw view without another change; a designed interface for it is one more content view, which offers itself wherever it fits and can be embedded by name. A change that needs edits in `ui/` for one family has broken the rule above.

## Schemas: the architecture you can read
`schema/ui.osis` (namespace `ui:`) is the kit's data model; `schema/app.osis` (`osis_app:`) holds only what is specific to the first-party app. A reader of those two files should see the architecture without opening code: every concept in Terms that is stored is declared there, with the same name, documented for someone who has not read the code, a section per concept. Change them freely until the stability discussion, in place, no migrations. When a design changes, the schema changes first.
- **The line**: would a small app built on kit alone need it? Then it is kit and `ui:`. View specs and configs, collection configs, windows and node state, `viewed_as`, `arranged`, favorites, theme and mode are `ui:`. The app's marker, colour fallback, demo marker, and the state of facets the app itself owns are `osis_app:`.

## State in osis
All state a user could miss lives in osis, so it syncs, survives restart and is reactive by the same path as content: a state write fires a watch and the affected nodes re-read; there is no separate UI-state update path. The app is also osis's first demanding client: friction met here is a finding about osis (issues tagged `core-ask`), not a reason to route around it.
- **Window**: a thing per window, carrying that window's state, listed per device on the app group (`ui:windows.0: map<node tid, tid>`). Items of an internal non-tag subgroup of the app group, so they sync and are not in the universe. A window is an ordinary thing: its raw view works, and showing another device's window needs only its tid.
- **Node state**: a view type's state is its own typed aspects on the window, each `map<node path, T>`, declared in schema/app.osis. Reading and writing is `cx.state(KEY, node)`. Paths use the view type and child key (a tid or entry key), never an index, so they stay stable as siblings come and go.
- **Which lifetime**, chosen per aspect:
  - Account-wide, durable, on the app group: what a person decided about a thing (`viewed_as`, `arranged`), favorites, theme.
  - On the thing: anything meant to be shared with its other readers (`ui:collection.0`).
  - Per window, durable: where the window is and what is half-done: the open thing, a calendar's week, raw mode, a composer's draft and reply target. Restored at start.
  - Per window, ephemeral (`+` aspects, notes/ephemeral.md): passing UI: an open picker or menu.
  - Not in osis: what is too hot to be data: caret, focus, drag position, animation. Scroll position is a later candidate (as a stable entry anchor, never pixels).
- A composer's draft is an editor `Block` over its window aspect, the same as any text field.
- An app's own per-account data (favorites, arrangements, themes) lives in an internal group found by scanning home's subgroups for the app's marker aspect, reading the union and writing to the smallest tid (Tess: a well-known per-app thing is incoherent, since a tid depends on its first admin; the scan is the convention).
- Asks of the library: ephemeral aspects support watches, queries and backlinks like stored ones; the app can pump the watch dispatcher on its own UI thread (`Dispatcher::Pump`).

## Layers
A toolkit swap rewrites kit's `render/` and widgets only: `view/`, `views/`, `facets/` and `store` hold all behaviour and policy, toolkit-free. Kit's driver pieces are `Dispatcher::Pump` (watch callbacks on the UI thread, in `db.settle()`; `render` queues their messages and drains after it) and `list` (keyed reconciler: `reconcile` keeps the longest ordered run of unchanged rows and replaces every other row, `KeyedList` applies the steps to a `Flex` or `TileGrid`; a structural change ends a `TileGrid` drag).

## Look and themes
One main colour from the content (the open thing's, else the first among what it holds or links; a soft grey on home) drives accent, selection and a subtle background; everything else is a theme's parameters (notes/theming.md). Themes are Tess-approved: Frost, Glass, Workstation, Memphis, Slate (square, flat, modern), Cel (flat, white or dark grey, anime-ish); each has light and dark, mode (Light/Dark/Auto) separate. Backgrounds: the theme picks what is drawn, the content picks the colour and the arrangement (seeded from the tid, varied slightly by kind); subtle shading of the one colour, not splotches of several. Less UI: fewer bordered elements.

**Web mockup** `app/mockup/` (plain HTML/CSS/JS, no deps, no osis; serve the directory, e.g. `python3 -m http.server`): explores look and layout. Tess's brief: things and scopes (tags, views) are fungible tiles in one list or grid; an ordered favorites list; one search over names, content and scopes; with a view open and room enough, a left bar holds search and favorites. The look should feel like what 1996, 2006, 2016 and 2026 thought 2026 would be: coloured gradient backgrounds or abstract shapes, a little Apple liquid glass (never at a perf cost), almost no Material. Layout in style.css; themes.js and engine.css are the theme reference implementation.

## kit and app
Two projects, `libs/kit/` (package `osis-kit`) and `app/` (`osis-app`).
- **osis-kit**: the first-party UI toolkit over Masonry. Holds windowing and platform shells (the iOS shell too), the osis-Masonry driver, the look, common widgets (markdown editor, text, lists), generic osis widgets needing only the osis API (schema fallback view, who-can-see display, share confirmation dialog), and the patches we carry to low-level crates. A small special-purpose app that looks like the main one depends on kit alone. kit does not abstract over the osis API, nor over Masonry: it re-exports it (`kit::masonry`, one pinned version) and apps use its types directly; design an abstraction only when actually changing base.
- **osis-app**: facet views, lenses, home, create flow, actions, the view-state schema.
- **Own Cargo workspace** for both, depending on core by path: keeps the GUI stack (wgpu, Vello, winit) out of core's builds, gate and feature unification, and puts `[patch]` entries for forked crates at the GUI workspace root (notes/build.md Layout). Costs a second `target/` per worktree. Agent limits (notes/coordination.md) count GUI agents; the gate splits by changed paths (notes/build.md, Components pay for themselves).
- Tess: the app builder updates and refactors kit as needed (Masonry upgrades allowed); core is never edited from app work: gaps become `core-ask` issues.

## Toolkit: Masonry without Xilem
Masonry is a retained widget tree designed to sit under other frontends; Xilem's job is to own app state and diff it into Masonry. With osis holding the state and delivering fine-grained changes (watches per aspect, live queries over a visible range), Xilem solves a problem we do not have. What we get: Vello (2D, GPU compute; vello_hybrid for low-end GPUs and WebGL, vello_cpu as a no-GPU fallback), Parley (the best Rust text stack: rich layout, IME), AccessKit designed in, a renderer abstraction, and a funded multi-contributor org.

Costs: pre-1.0 with breaking releases (the layout system changed in Q1 2026): pin versions, upgrade deliberately, keep the driver small so churn lands in one place. Thinner docs than Slint, so agents read source. Small stock widget set: we build our own anyway.

Alternatives weighed:
- **Slint**: the most mature on all six targets (1.15 in Feb 2026 brought Android/iOS safe areas and virtual keyboard; mobile is Rust-only), excellent tooling and docs, tiny runtime, software renderer, royalty-free license for apps (verify terms). Against: UI in a separate DSL, drawing limited to paths, plain-text editing only, less low-level control. The pick under "light and simple now" alone.
- **Makepad**: the only Rust toolkit shipping web plus all five native targets from one codebase, shader-level custom drawing by default. Against: thin docs, small team, unusual DSL, no accessibility, needs a GPU.
- **Xilem** on top of Masonry: duplicates osis's reactivity.
- **egui**: lightest and everywhere, but the look is hard to escape and mobile text input is weak. **iced**, **GPUI**: desktop only. **Dioxus native**: immature, mobile is webview. **Compose Multiplatform**: Kotlin, JVM desktop. Flutter and webviews excluded by Tess.

## Platform work accepted
- Desktop (Linux, Windows, macOS): winit. Test with the gui-testing skill.
- Android: winit plus android-activity; IME is the rough spot (notes/android.md); AccessKit has an Android backend.
- iOS: winit's backend is thinly exercised, IME weak, no AccessKit backend. Expect a UIKit shell of our own hosting the render surface and feeding touch, keyboard and VoiceOver into Masonry.
- Web: later; needs WebGPU for Vello proper, vello_hybrid/vello_cpu for a canvas fallback.

Text: Parley's plain editor exists; rich editing does not. The markdown editor is ours: an editor over Parley layouts with styled spans, first as a styled-source editor (headings larger, links coloured, markup visible), not WYSIWYG; the one place a plain-text fallback is acceptable early.

## Prototype order
1. Linux desktop (Tess: Linux desktop first): home, rail, tiles, demo data, the theme engine, facet views with tags, reach and history, the calendar week and the tags tree. Built.
2. Android: experimental, notes/android.md (app/android; Tess asked for a prototype APK).
3. Time and People lenses, search, the schema fallback view.
4. iOS shell, web, durable view-state spec.

Open toolkit checks: backgrounds in Vello (gradients, sweep gradients, masks; beams wants a blur), bundling the OFL theme fonts through Parley's font collection.

## Running it
One device with demo data (in `libs/kit/`; the first build takes a few minutes): `cargo run --bin osis-app -- ~/osis-try/solo --demo --theme glass`. The store directory is made on first run; `--demo` adds the demo things once (keeping existing favorites); `--theme frost|glass|workstation|memphis|slate|cel` and `--auto|--light|--dark` set the look, as does the Look section of home's page. `--peer ADDR` (repeatable) adds peer addresses an existing store lacks.

Two nodes syncing through a local serving node (four terminals):
1. Repo root: `cargo run --bin osis -- -s ~/osis-try/host init`, then `cargo run --bin osis -- -s ~/osis-try/host serve --listen quic://127.0.0.1:47833 --admit open` (`open`: it is another account, so it takes no group as its own). Its first line is the serving address, `quic://127.0.0.1:47833#<key>` (stable across restarts of that store); leave it running.
2. `libs/kit/`: `cargo run --bin osis-app -- ~/osis-try/a --peer 'quic://127.0.0.1:47833#<key>' --demo` (quote the address: it holds a `#`). Close the window once it shows (a store is locked while open).
3. Repo root: `cargo run --bin osis -- -s ~/osis-try/a pair offer`. It prints an `osis://pair/...` line and waits.
4. Another terminal, repo root: `cargo run --bin osis -- -s ~/osis-try/b pair join 'osis://pair/...'`. It prints an `osis://pair-request/...` line and waits. Paste that into terminal 3 and press Enter: it prints an `osis://pair-reply/...` line; paste that into terminal 4. Both exit (`b` learns the peer from the offer).
5. `libs/kit/`: `cargo run --bin osis-app -- ~/osis-try/a` and `cargo run --bin osis-app -- ~/osis-try/b`. Within a few seconds `b` shows the demo data. Typing in one window shows in the other after a short pause (a text session commits after about 2 s idle) plus sync.

Joining a chat from another device:
1. `cd libs/kit && cargo build --bin osis-app`; `cd ../.. && cargo build --bin osis`.
2. Someone in the chat runs `osis -s STORE chat link $C` and sends the `osis://link/...` line.
3. `libs/kit/target/debug/osis-app ~/osis-chat --peer 'quic://HOST:PORT#KEY'`. Paste the link into the search field and press Enter: the thing opens once a peer answers (a target this account already reaches at the link's role opens at once: `Osis::redeem`). An address pasted the same way adds a peer. Open "You" among the favorites and type a name in its title to name yourself.
4. Later runs: the chat is in Everything held; favorite it or find it by name in the search field.

## Prototype (as built)
`osis-app DIR [--peer ADDR]... [--demo] [--theme ID] [--auto|--light|--dark]` (libs/kit/ workspace; Masonry `=0.4.0`, masonry_winit `=0.4.0`: wgpu 26, Vello 0.6, Parley 0.6, winit 0.30).

### The view system (libs/kit/src)
- `view/`: `Block`, `Cx` and `Act` (render and action contexts; Code shape), `graph`, `keyed`, `tree`, `Action`, `Facet`, `ViewSpec`, `Config`, sources, arrangements (`NEWEST` per source, `OUTLINE_NODES`), search, `Sessions` (one text session per editor, following its field: another editor's committed typing, a cleared draft or an undo shows in every open editor; actions commit pending typing (`commit(t)`) where it must land first: Send, Undo, Delete; `pending(t)`: the about chip counts pending typing as undoable; each keystroke bumps the `TYPED` cell, which that chip reads), `registry`.
- `views/`: `ViewType` (fits, parts or custom render, a `sample` subject for the cost harness), `render`, `expand` (a whole tree as a value, what tests read), `opener` (fit and default rule, tabs, bar, nests the content view filled), `chrome` (places, Add, reach, changed, undo, a node of its own so its changes do not rebuild the content), `collection`, `note`, `raw`, `tile`.
- `facets/`: `name`, `body`, `members` (collections and the arrangement chooser), `places`, `add`, `about` (reach, changed, undo), `look`, `fields` (raw's rows).
- `store`: `Data` (account state over an `Account` the app supplies, and the `Registry`): account groups, windows, favorites, look, open thing, universe.
- `render/`: `mod` (the shell: rail, search, the `Tree`'s surface; a slot rebuilds only when its model differs, and a stream, cards or rows block whose rows alone differ takes keyed steps, `view/keyed`, on its list widget) and `blocks` (Masonry widgets for `Block`s).
- `time`, `edit` (`shown_edits`, `map_byte`: carets across merges; typing goes in by `TextSession::edit`).

### The app (app/src)
`store` (`AppAccount`: the group among home's subgroups, the seeds; the registry), `facets/` (`event_time`, `event_place`, `contact`, `log`: the only file naming `osis_chat`, for chat's keys and edit rules, `color`), `views/` (`event`, `person`, `stream`), `time` (event times and repeats; `monday_of`, labels and the system zone in kit), `demo`, `main`. `demo` adds tags, people, notes and this week's events once per account.
- Event times: a wall time with a zone (IANA or `+HH:MM`) shows in the system zone, a floating one as written; `event_time::span` gives (start, end, all day) in local wall ms; a `duration` end is elapsed time; `nudge` moves an event, its end along in its own form; `time::occurrences` expands `event:repeat.0` over a window (bounded by `MAX_PERIODS`), leaving out occurrences another event replaces through `event:overrides.0`. App tests never depend on now or the system zone.
- Search: a query is any text; an `osis://` link is redeemed off the UI thread (`Data::redeem`, 60 s bound, a held target opens at once, a target not in the universe is placed in the account group); an address adds a peer.
- Two nodes racing: `things()` keeps one collection per `(collection.0, name.0)` (smallest tid) and `favorites()` maps the other group's entries onto those; `toggle_favorite` and `move_favorite` never copy entries between groups, so a concurrent unfavorite wins.
- `delete` also drops subgroup edges on groups I can write. `opened()` is `None` for a thing gone from `things()`. Reach walks live rosters; `undo` is `Scope::Thing` skipping the creation commit.
- Raw (`fields`): every aspect but the system's, flattened to scalar rows by schema type, edited as text and written at the row's path.
- The contact form writes a field of an absent struct alone; an email or phone rename is remove + put by key.

### The shell
Under 760 px an open thing fills the window with a back button; wider, a 264 px rail (home row, search, the favorites as a collection, New) sits beside it. Home is the opener of the account group, no bar, the brand and the search field above it. Layout is rebuilt on the open thing, width class, look or starting to search; every other change goes through node models. Cards, rows and outline draw their default tile elements inline from each `Entry` (no child node per tile, so the grid keeps drag-reorder); a named element spec is a real child view per element.

### kit modules
`theme` (the parameters, the six defaults, `Mode`, `Look::new(theme, dark, main)` resolving colours: background tinted by bgTint, panel at panelOpacity, card fill composited over the background, white text past fill 0.55, accent from the main colour, shadows stronger in dark), `backdrop` (all ten backgrounds as fills, gradients and paths in shades of the background colour, placed by four seeds hashed from the open thing and its kind; no blur or layers), `fonts` (every theme font and JetBrains Mono bundled in libs/kit/assets/fonts with their OFL texts, registered in `on_start`), `icons` (line icons as SVG path data), `text` (parley layouts in the theme font family list), `widgets` (`Chip`, `Wrap` (flow), `Root` (also fades the background to a new colour over 600 ms: the one motion), `Panel` (panel, inset, field), `Tile` (card, row, new; slant, shadow, gloss, icon roundness; bar's stripe and slash's corner flag), `TileGrid` (auto-fill columns), `IconButton`, `Limit` (centred max width), `style` (labels and borderless text inputs per text role, accent weights and caps, mono section labels, title marks)), `list` (reconciler), `window`.

### Patches
libs/kit/patches/, `[patch.crates-io]` in libs/kit/Cargo.toml, each with a `.diff` against upstream beside it; upgrading Masonry means re-vendoring and re-applying. All are upstream candidates.
- `masonry_winit` 0.4.0 (`masonry_winit-clipboard.diff`): upstream's clipboard is copypasta's X11 context, `unwrap`ped at startup, which panics on a Wayland-only session (no `DISPLAY`); the patch uses the Wayland clipboard over the event loop's own connection (dropped in `exiting`, before the loop drops the display), else X11, else a no-op.
- `masonry_winit` (`masonry_winit-a11y.diff`, applied after the two above): `accesskit_winit` optional behind the `accessibility` feature (default off; kit and app pass it through: `--features accessibility`); off, `src/a11y.rs` is a no-op adapter of the same shape. Its Linux adapter is zbus and ~55 crates. Also pins `smithay-clipboard` `=0.7.2`, copypasta's Wayland clipboard on winit 0.30's smithay-client-toolkit 0.19 (0.7.3 is on 0.20: a second Wayland stack). winit has no clipboard API, so copypasta stays (macOS, Windows, X11; Wayland through the pin); Android's is kit's own over JNI.
- `masonry_winit` (`masonry_winit-hooks.diff`): `AppDriver::on_resized(window_id, ctx, PhysicalSize<u32>)` (after the render root has the new size) and `on_theme_changed(window_id, ctx, winit::window::Theme)`, default no-ops.
- `masonry` 0.4.0 (`masonry-selection.diff`): `TextArea::selection_bytes()` (anchor, focus), the only way to read the caret, to keep it across a merge; its Cargo.toml allows `unfulfilled_lint_expectations`.
- `masonry_core` 0.4.0 (`masonry_core-tags.diff`): upstream's `remove_child` never frees a removed widget's tag, so re-adding a tag debug-panics and lookups find a dead id; the patch keeps the tag in `WidgetState` and frees it on removal (test `tags::`). Its Cargo.toml allows `unused_imports` and `unfulfilled_lint_expectations`.

### Tests
app/tests/it: `data`, `edit`, `fields`, `time`, `sync` (two devices, windows), `share` (two people by hand-delivered commits), `chat`, `views` (what a page shows, read as the tree). `libs/kit/tests/it/view_tree`: kit alone with a small `Account`. Redeeming a new link needs a serving peer, checked by hand. The `sync` and `share` tests copy commits through `osis::internals` (`export_bundle` covers only synced groups' sync IDs, which leaves out the app group); app code itself never uses `internals`. libs/kit/tests/it: `view_tree`, `list`, `tags`, `view_costs` (`osis_kit::testing::check_views`, also run by the app: every registered view through its `sample`, no address read twice by one node, each write to what it read runs exactly those nodes, an unread write runs nothing, the screen always matches a fresh render; one row changed builds one row), `theme` (every default readable in both modes; odd synced colours made opaque and sRGB; white card text darkens a pale tag colour; extreme parameters stay finite). The window is checked by hand with the gui-testing skill.

### What the prototype showed
(Asks of core: issues tagged `core-ask`.)
- The watch-driven model works with very little driver code; the cost is in re-reading (no queries) and one subscription per visible note.
- No well-known per-app root: the app finds its group by scanning home and tolerates duplicates (issues/app-group-helper.md).
- Masonry 0.4: `TextInput`/`TextArea` do not fill a flex slot by themselves (`SizedBox::expand`); `Portal` content needs `content_must_fill`; `reset_text` drops the selection (the app maps and restores it via the patched `selection_bytes`); user events reach the driver only as `Action`s; `NewWidget` takes a tag or properties, not both.

### Core features the app has yet to adopt
Remove each line once adopted.
- Undoing a creation deletes the thing (redo restores it): `Data::can_undo`'s creation skip can go.
- A thing watch sees a delete as aspects going absent and `has_content` is false for a deleted thing: `Data::opened` can check that instead of scanning `things()`.
- `groups_of(t)` returns `GroupsOf { item_of, subgroup_of, within }`: `tags_of` can read `item_of` and `subgroup_of` instead of scanning `all_tags()`.
- `Write::delete` removes the thing's memberships and subgroup edges in every group the node may write (skipping others): `Data::delete`'s scan for parent edges can go.
- A typed read of a stored value of another shape (or a newer version's enum case) reads as `None` with a `Mismatch` diagnostic: `Data::get`'s wrapper can go (`db.at(t, k).get()`).
- `db.changed(t) -> Option<ThingStamp>`: the last content change (not membership or sharing), else the creation, shown by `.shown()` (`min(ts, received)`, as `created`): `Data::changed` can use it instead of a listing (which scans every aspect) per thing.
- `Config.dispatch = Dispatcher::Pump(wake)`: callbacks run on the thread calling `db.settle()`; `wake` (any thread, maybe under the osis lock, once per batch) only posts the UI wake. kit wakes the event loop, then `db.settle()` on the UI thread; callbacks post into `render`'s queue, which the same wake drains.
- A membership change that leaves a durable thing in no synced group while the target group's own data syncs (an item of home, not a subgroup) fails `Invalid`; the app group already avoids this.
