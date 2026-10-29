# The first-party app
> Summary: Design direction for the first-party osis app over osis and schema/ (decided with the owner, pre-prototype): data-oriented UX (things with facet views, lenses, tags as filters), the look (color from the user's tags, flatish), state kept in osis including view state, the layer split (osis state, toolkit-free actions crate, Masonry driver and widgets), the kit/app split (osis-kit toolkit and osis-app in their own Cargo workspace), the toolkit decision (Masonry without Xilem) with the alternatives weighed, the platform work accepted, the prototype order, and the first prototype as built (kit module map, the notes app, patches, what it showed).

## Direction (owner)
- Fresh and timeless, not a bundle of generic apps over osis types. Bright colors, flatish but not distinctly flat, its own look rather than the native aesthetic.
- Oriented around data, not functionality: no "tab for notes, tab for calendar". Views show whatever combination of things they can meaningfully place.
- Responsive and lightweight on every device; webview is out. Native first, web later.
- Build first in something light, simple and running everywhere; if the UX suffers, rebuild differently. Taking on platform work (Rust embedding, possibly an iOS shell of our own) is accepted for the sake of the right foundations in text, accessibility and low-level control.
- Convergent design, not a mobile/desktop split: one layout keyed on width and input kind, phone layout designed first, desktop adds columns. Touch on desktop supported.

## Model
- **The thing is the unit.** No `kind` aspect exists (notes/tags.md); a thing is whatever its aspects make it, and may be several kinds (a meeting note is note and event).
- **Facet views.** Kind-specific views exist because aspects do not map 1:1 onto UI. Opening a thing picks the best-matching view for the aspects present (event aspects plus `/body` → the calendar view, which includes the freeform text area; `/body` alone → the notes view). When several views apply and none covers every aspect, the thing offers them side by side (tabs or a scroll list; not decided, not important).
- **Schema fallback view**, behind a context menu: shows and edits every aspect of a thing from its schema-declared types alone. Covers things whose schema the app has but no view for.
- **Create** offers a kind selector (note, event, contact, ...) plus "empty thing".
- **Lenses** are few and fixed: a filter plus an arrangement over all things, each admitting only what it can place. Time (event times; faint creation and edit ticks for the rest, from commit timestamps), People (contacts and profiles plus what links to them), Tags (the graph as navigation, with color), Search as the primary way in, and a home lens mixing today, recently touched things and people. User structure lives in tags and links, not in lenses.
- **Tags filter.** Tags also narrow a lens or find things within a collection.
- **Every thing shows** its tags, what links to it (`db.backlinks`), who can see it (roster) and its history (undo). Placing into a shared tag confirms the reach (notes/tags.md guideline).
- Backlinks from markdown (`/body` has no tid reference syntax): the owner is taking that to the library side. Not an app concern until then.

## Look
- Color comes from the data: `/tag.color` tints things, the chrome stays calm. The palette is the user's, which is what keeps it timeless.
- Flatish: soft elevation and warmth on cards, depth cues for stacking and drag, no decorative gradients. Vello's blurred rounded rects make this cheap.

## State in osis
- All app state lives in osis; widgets hold only what is too hot to be data (drag positions, caret blink, animation).
- Durable view state (open things, lens, filters, layout, window management if it grows) as things in a person-private group: a view can be moved between devices, and between apps or toolkits, and saved and restored. Not specified or built on the first pass, but the architecture assumes it.
- Ephemeral view state (selection, expanded panels, scroll anchor) as ephemeral things and aspects (notes/ephemeral.md): in memory, local unless placed in a synced group; hot live state across devices is synced ephemeral data, not commits.
- Needed from the API (asks for the library side): in-memory things must support watches, queries and backlinks exactly like stored things; and a mode where the app pumps the watch dispatcher on its own (UI) thread, removing the cross-thread hop and ordering questions.

## Layers
- **State**: osis (above).
- **Actions** (in `app/`): a toolkit-free Rust crate. Widgets emit intents (open, tag, share, edit); the crate turns them into osis writes and holds all behavior and policy, including the share confirmation's rule.
- **Driver** (in `kit/`): Masonry-specific glue. Watches fire, the driver edits the retained widget tree through Masonry's mutation API. Two pieces written once: marshaling watch callbacks onto the UI thread (until the dispatcher-pump mode exists), and a keyed list reconciler turning a changed query result into insert/move/remove on a list widget.
- **Widgets** (in `kit/`, product views in `app/`): our own look as Masonry widgets.
- A toolkit swap rewrites driver and widgets only; state and behavior survive. The earlier idea of a separate "view model" crate dissolves into the view-state schema plus the actions crate.

## Web mockup
`app/mockup/` (plain HTML/CSS/JS, no deps, no osis; serve the directory, e.g. `python3 -m http.server`) explores look and layout before building in kit. Owner brief: things and scopes (tags, views) are fungible tiles in one list or grid; an ordered favorites list; one search over names, content and scopes; with a view open and room enough, a left bar holds search and favorites. The look should feel like what 1996, 2006, 2016 and 2026 thought 2026 would be: colored gradient backgrounds or abstract shapes, a little Apple liquid glass (never at a perf cost), almost no Material. All look values are custom properties in looks.css over one layout in style.css.

Owner feedback on the first six looks:
- Themes: wanted. Every look needs light and dark (mode is separate from the look: Light/Dark/Auto).
- Dusk, Glass, Aero and Pearl read as tweaks of one thing; Glass preferred, with a less rounded sidebar selection and simpler, more vivid color. Dusk, Aero and Pearl were dropped (in git history); Glass, Workstation, Memphis remain.
- Tone down the amount of UI (not the color): simpler backgrounds, fewer bordered elements.
- Undecided whether the background follows the look (Workstation's synth sun suits it) or the content (color and shapes fade to what is open). The mockup has both behind a switcher: content mode takes up to three colors from the open thing and what it holds or links, and moves Glass's color fields per thing.

Open theme questions (owner: surface now, decide later, not worth much effort yet):
- Customization depth: a fixed compiled-in set, editable colors and a few properties, both (pick a base, adjust), or full styling. Leaning: a theme is data (tokens plus a few enumerated style choices such as corner shape, border/shadow kind, blur, background recipe), stored in osis so it syncs; no full CSS.
- Same themes on every platform: free with one codebase; a web build on DOM elements would map the same tokens to CSS, which stays easy only if themes stay data rather than per-theme widget code.

## kit and app (owner)
Two top-level projects, `kit/` (package `osis-kit`) and `app/` (`osis-app`).
- **osis-kit**: the first-party UI toolkit over Masonry (or another base if Masonry fails us). Holds windowing and platform shells (the iOS shell too), the osis-Masonry driver, the look (theme tokens, tag tinting, card styling), common widgets (markdown editor, text, lists), generic osis widgets needing only the osis API (schema fallback view, who-can-see display, share confirmation dialog), and the patches we carry to low-level crates. A small special-purpose app that looks and feels like the main one depends on kit alone.
- kit does not abstract over the osis API. Over Masonry: no wrapper for now; kit re-exports it (`kit::masonry`, one pinned version) and apps use its types directly. Design an abstraction only if we actually change base, knowing both sides.
- **osis-app**: facet views, lenses, home, create flow, the actions crate, the view-state schema.
- **Own Cargo workspace** for kit and app, depending on core by path: keeps the GUI stack (wgpu, Vello, winit) out of core's builds, gate and feature unification, and puts `[patch]` entries for forked crates at the GUI workspace root. Costs a second `target/` per worktree. Machine-load limits (notes/coordination.md) still count GUI agents.
- Gate split by changed paths (notes/build.md, Components pay for themselves).

## Toolkit: Masonry without Xilem
Masonry is a retained widget tree designed to sit under other frontends; Xilem's job is to own app state and diff it into Masonry. With osis owning the state and delivering fine-grained changes (watches per aspect, live queries over a visible range), Xilem solves a problem we do not have. What we get: Vello (2D, GPU compute; vello_hybrid for low-end GPUs and WebGL, vello_cpu as a no-GPU fallback), Parley (the best Rust text stack: rich layout, IME), AccessKit designed in, a renderer abstraction, and a funded multi-contributor org.

Costs: pre-1.0 with breaking releases (the layout system changed in Q1 2026): pin versions, upgrade deliberately, keep the driver small so churn lands in one place. Thinner docs than Slint, so agents read source. Small stock widget set: we build our own anyway.

Alternatives weighed:
- **Slint**: the most mature on all six targets today (1.15 in Feb 2026 brought Android/iOS safe areas and virtual keyboard; viewers in both app stores; mobile is Rust-only), excellent tooling and docs, tiny runtime, software renderer, royalty-free license for apps (verify terms). Against: UI in a separate DSL, drawing limited to paths, plain-text editing only, less low-level control. Would have been the pick under "light and simple now" alone.
- **Makepad**: the only Rust toolkit shipping web plus all five native targets from one codebase (1.0 ~April 2025; Robrix, Moly), shader-level custom drawing by default. Against: thin docs, small team, unusual DSL, no accessibility, needs a GPU, no 2026 release notes found.
- **Xilem** on top of Masonry: duplicates osis's reactivity.
- **egui**: lightest and everywhere, but the look is hard to escape and mobile text input is weak. **iced**, **GPUI**: desktop only. **Dioxus native**: immature, mobile is webview. **Compose Multiplatform**: Kotlin, JVM desktop. Flutter and webviews excluded by the owner.

## Platform work accepted
- Desktop (Linux, Windows, macOS): winit, works today. Start here; test with the gui-testing skill.
- Android: winit plus android-activity; IME is the rough spot and under active Linebender work (IME moving onto ui-events); AccessKit has an Android backend.
- iOS: winit's backend is thinly exercised, IME weak, no AccessKit backend. Expect a UIKit shell of our own hosting the render surface and feeding touch, keyboard and VoiceOver into Masonry.
- Web: later; needs WebGPU for Vello proper, vello_hybrid/vello_cpu for a canvas fallback.

## Text
Parley's plain editor exists; rich editing does not. The markdown editor is ours: an editor over Parley layouts with styled spans, first as a styled-source editor (headings larger, links colored, markup visible), not WYSIWYG. Also the one place a plain-text fallback is acceptable early.

## Prototype order
1. Linux desktop: a Thing view with the facet-selection logic, the Tags lens, view state in osis from day one.
2. An Android build within the first few iterations so the convergent layout stays honest.
3. Time and People lenses, search, the schema fallback view.
4. iOS shell, web, durable view-state spec.

## Prototype (as built)
First prototype: osis-kit plus a stripped-down notes app, proving the stack end to end; not the final UI (plain Masonry look, plain-text body). Two app instances on two paired devices syncing through a local `osis serve` show each other's creates, renames, body edits and deletes live.

**Workspace**: kit/Cargo.toml is the GUI workspace root (notes/build.md). Masonry `=0.4.0`, masonry_winit `=0.4.0` (wgpu 26, Vello 0.6, Parley 0.6, winit 0.30).

**kit modules**:
- `marshal`: `mailbox(waker) -> (Mailbox<M>, Inbox<M>)`. osis callbacks `post` from the dispatcher thread; the first post since the last drain calls `Wake` once; the UI thread `drain`s in post order. Until osis has a pump-on-the-UI-thread mode, the one cross-thread hop.
- `window`: `App` (event loop, window id, `waker()`), `Waker` (sends a `Wakeup` action through masonry_winit's `MasonryUserEvent::Action`, the only user event it routes to the driver), `run`. Wakes sent before the window exists are dropped by masonry_winit: a driver drains and re-posts in `AppDriver::on_start`.
- `list`: `reconcile(old, new) -> Vec<Op>` over `(key, value)` rows (removes back to front, then one pass keeping, moving up or inserting; `Update` where the value changed); `apply` for plain vectors; `KeyedList<K>` applies ops to a Masonry `Flex` (no spacers) and maps row widget ids back to keys. Masonry cannot move a widget between slots, so a move rebuilds that row.
- `theme`: `Theme` tokens (base, row, selected colors, gap, pad); `properties()` is Masonry's default set today. The own look replaces values here.
- `widgets`: `row` / `set_row` (a list row button with selection tint).
- kit re-exports `masonry` and `masonry_winit`; it has no osis dependency yet (nothing in it needs one).

**app** (`osis-app DIR [--server ADDR]...`; opens or creates the store, `Runtime::Own` over QUIC):
- `notes` (actions, toolkit-free): notes are `/name` + `/body` things owned by `me()` in the internal notes group, a group that is both an item (its own aspects sync) and a subgroup (its items sync) of home, marked by the app schema's `/osis-app/notes` (app/schema/osis-app.osis, keys by `generate_file` in build.rs). A group's members are its items and its subgroups' members, not its items' items: placing notes in a group that is only an item of home leaves them unsynced (osis reports `NotSynced`; the app shows diagnostics in its status line). Every marked group in home's subgroups is read (two devices racing at first start each make one); new notes and the selection go to the smallest tid. Selection is durable view state: `/osis-app/selected: map<tid, tid>` (device node -> note) on that group, until ephemeral data lands.
- `ui`: watches (home's `/group`, each notes group's `/group` and selection, each note's `/name`) post `Changed`; the UI re-reads everything and reconciles (O(notes) per change: no queries yet). The editor is two `TextSession`s (name, body); typing is spliced into them (one commit per pause; the splice is taken against the text the widget showed, so a remote merge not yet shown is kept; in a run of equal chars both are placed apart where they can be, so a deletion beside the merge is not dropped), `on_remote` resets the widget text; with no note open, typing is cleared. So the list shows a rename only after the session's idle commit (2 s).
- Tests: kit/tests/it (`list`, `marshal`), app/tests/it (`notes` over an in-memory database). The window was checked by hand with the gui-testing skill.

**Patches** (kit/patches/, `[patch.crates-io]` in kit/Cargo.toml; each with a `.diff` against upstream beside it): `masonry_winit` 0.4.0: its clipboard was copypasta's X11 context, `unwrap`ped at startup, so the app panicked on a Wayland-only session (no `DISPLAY`); now the Wayland clipboard over the event loop's own connection (dropped in `exiting`, before the loop drops the display), else X11, else a no-op. Upstream candidate. Upgrading Masonry means re-vendoring and re-applying.

**What the prototype showed** (asks of core: issues tagged `core-ask`):
- The watch-driven model works with very little driver code; the cost is in re-reading (no queries) and one subscription per visible note.
- `TextSession::on_remote` gives only the merged text, so a remote edit moves the caret to the end; a session dropped after `delete` commits its pending text and resurrects the thing (the app closes the editor before deleting).
- No well-known per-app root: the app finds its group by scanning home and tolerates duplicates.
- Masonry 0.4: `TextInput`/`TextArea` do not fill a flex slot by themselves (`SizedBox::expand`); `Portal` content needs `content_must_fill`; `reset_text` drops the selection; user events can only reach the driver as `Action`s.
