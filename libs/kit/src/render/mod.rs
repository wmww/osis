//! The shell (Masonry over kit): the window, the rail, the bar, one screen: the open thing's page
//! (home is the app group's page; `opened()` being `None` shows it). What is shown comes from
//! osis through a `Tree` of view nodes: a read that changed marks its node dirty on the UI thread
//! (`Dispatcher::Pump`), and only marked nodes run. A slot per facet section is rebuilt only when
//! its model changes, so editors keep their caret.

mod blocks;

use crate::edit::{map_byte, shown_edits};
use crate::facets::members::ToggleCreating;
use crate::schema::Mode as ModeChoice;
use crate::store::{Data, Reader};
use crate::view::search::{Paste, classify, search};
use crate::view::{Act, Block, Cx, DARK, Do, Graph, Icon, Input, Open, QUERY, Section, Surface, TICK, Tree, ViewSpec, WindowState};
use crate::view::sessions::Key;
use crate::views::{self, RAIL, open_spec};
use osis::{Subscription, Tid};
use crate::masonry::core::{ErasedAction, NewWidget, Properties, Widget, WidgetId, WidgetTag};
use crate::masonry::properties::Padding;
use crate::masonry::properties::types::{CrossAxisAlignment, Length};
use crate::masonry::widgets::{Flex, Portal, Prose, SizedBox, TextAction, TextArea};
use crate::masonry_winit::app::{AppDriver, DriverCtx, WindowId};
use crate::masonry_winit::winit::dpi::PhysicalSize;
use crate::masonry_winit::winit::window::Theme as WinitTheme;
use crate::theme::{Look, Mode, Theme, parse};
use crate::widgets::style::{self, Text};
use crate::widgets::{Blur, ChipPress, Limit, Panel, PanelKind, Press, Reorder, Root};
use crate::window::{Waker, Wakeup};
use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::sync::mpsc::{Receiver, Sender, channel};

pub const ROOT: WidgetTag<Root> = WidgetTag::new("root");
/// Holds the status label (a tag cannot be given together with properties).
const STATUS: WidgetTag<SizedBox> = WidgetTag::new("status");

/// Below this width (logical px) an open thing fills the window and home is a back button away.
const NARROW: f64 = 760.0;

/// What the shell hears besides graph nodes going dirty.
#[derive(Debug)]
pub enum Msg {
    /// An editor's session merged a write its widget does not show yet.
    Merged(Key),
    /// An osis diagnostic (a thing that will not sync, a callback that panicked, ...).
    Diagnostic(String),
    /// A redemption of a pasted link ended: the thing, or why not.
    Redeemed(Result<Tid, String>),
    /// A follow-end section was rebuilt and laid out: scroll to the end.
    ScrollEnd,
    /// A minute passed.
    Tick,
}

/// What the page's slot shows now, and what to forget when it goes.
struct Slot {
    id: WidgetId,
    model: Vec<Block>,
    built: blocks::Built,
}

/// What the shell reads from osis: everything that selects a screen, a node of the graph.
#[derive(Clone, Debug, PartialEq)]
struct Shell {
    t: Tid,
    home: bool,
    theme: Option<String>,
    mode: ModeChoice,
    color: Option<String>,
    searching: bool,
}

fn shell(r: &Reader, &(_, main): &(&'static str, Tid)) -> osis::Result<Shell> {
    let t = r.opened()?.unwrap_or(main);
    let home = t == main;
    let (theme, mode) = r.look()?;
    let color = if home { None } else { views::main_color(r, t)? };
    Ok(Shell { t, home, theme, mode, color, searching: !r.local(QUERY)?.trim().is_empty() })
}

/// What selects the widget structure of a screen.
#[derive(Clone, Debug, PartialEq)]
struct Layout {
    t: Tid,
    home: bool,
    narrow: bool,
    searching: bool,
}

/// `Ui` as the tree's surface.
struct Draw<'u, 'a, 'b> {
    ui: &'u mut Ui,
    ctx: &'u mut DriverCtx<'a, 'b>,
}

impl Surface for Draw<'_, '_, '_> {
    fn show(&mut self, path: &str, out: &Section) -> osis::Result<bool> {
        let ui = &mut *self.ui;
        // results in the rail mark the open thing
        let current = (path == "rail").then(|| ui.built.as_ref().map(|l| l.t)).flatten();
        let mut blocks = out.blocks.clone();
        // a pinned foot and following the end only when this node fills the page
        let (foot, filled) = (out.foot.clone(), ui.pinned.contains(path));
        if !filled {
            blocks.extend(foot.iter().cloned());
        }
        let changed = ui.fill_blocks(self.ctx, path, blocks, current)?;
        if filled {
            let key = format!("{path}#foot");
            let foot_changed = ui.fill_blocks(self.ctx, &key, foot, None)?;
            if (changed || foot_changed) && out.follow_end {
                // once laid out: the new content's height is known only then
                let _ = ui.tx.send(Msg::ScrollEnd);
                ui.waker.wake();
            }
            return Ok(changed || foot_changed);
        }
        Ok(changed)
    }

    fn gone(&mut self, path: &str) {
        let ui = &mut *self.ui;
        for k in [path.to_string(), format!("{path}#foot")] {
            if let Some(s) = ui.slots.remove(&k) {
                ui.acts.forget(&s.built);
            }
        }
        ui.pinned.remove(path);
    }
}

pub struct Ui {
    data: Data,
    window: WindowId,
    tx: Sender<Msg>,
    rx: Receiver<Msg>,
    waker: Waker,
    theme: Theme,
    mode: Mode,
    look: Arc<Look>,
    narrow: bool,
    built: Option<Layout>,
    state: WindowState,
    /// The views on screen.
    tree: Tree,
    slots: HashMap<String, Slot>,
    system_dark: Option<bool>,
    search_ids: Vec<WidgetId>,
    /// The widgets that report an action and what it does.
    acts: blocks::Acts,
    /// The page's scroll while a node follows the end.
    scroll: Option<WidgetId>,
    _diag_sub: Subscription,
    diag: Option<String>,
    focus_title: bool,
    redeeming: bool,
    /// Nodes that fill the page: their foot is pinned.
    pinned: BTreeSet<String>,
}

impl Ui {
    pub fn new(data: Data, window: WindowId, waker: Waker) -> osis::Result<Ui> {
        // osis callbacks run on this thread, inside the `settle` that the Wakeup drains after
        let (tx, rx) = channel();
        let (theme, mode) = data.look().unwrap_or((None, ModeChoice::Auto));
        let theme = Theme::named(theme.as_deref().unwrap_or("frost"));
        let mode = kit_mode(&mode);
        let m = tx.clone();
        let diag_sub = data.db.on_diagnostic(move |_, d| {
            let _ = m.send(Msg::Diagnostic(d.to_string()));
        })?;
        let look = Arc::new(Look::new(&theme, mode == Mode::Dark, None));
        let state = WindowState::default();
        state.graph.attach(&data);
        // a dirty node asks for an update
        let w = waker.clone();
        state.graph.set_notify(Arc::new(move || w.wake()));
        // the minute tick moves what shows an age
        let (m, w) = (tx.clone(), waker.clone());
        std::thread::spawn(move || {
            loop {
                std::thread::sleep(std::time::Duration::from_secs(60));
                if m.send(Msg::Tick).is_err() {
                    return;
                }
                w.wake();
            }
        });
        let m = tx.clone();
        state.sessions.set_notify(Arc::new(move |k| { let _ = m.send(Msg::Merged(k)); }));
        Ok(Ui {
            data,
            window,
            tx,
            rx,
            waker,
            theme,
            mode,
            look,
            narrow: false,
            built: None,
            state,
            tree: Tree::default(),
            slots: HashMap::new(),
            system_dark: None,
            search_ids: Vec::new(),
            acts: blocks::Acts::default(),
            scroll: None,
            _diag_sub: diag_sub,
            diag: None,
            focus_title: false,
            redeeming: false,
            pinned: BTreeSet::new(),
        })
    }

    /// The first look, for the initial root widget.
    pub fn look(&self) -> Arc<Look> {
        self.look.clone()
    }

    fn dark(&mut self, ctx: &mut DriverCtx<'_, '_>) -> bool {
        match self.mode {
            Mode::Light => false,
            Mode::Dark => true,
            Mode::Auto => *self.system_dark.get_or_insert_with(|| ctx.window(self.window).handle().theme() == Some(WinitTheme::Dark)),
        }
    }

    fn is_narrow(&mut self, ctx: &mut DriverCtx<'_, '_>) -> bool {
        let w = ctx.window(self.window);
        let scale = w.handle().scale_factor();
        let size = w.render_root().size();
        f64::from(size.width) / scale.max(0.1) < NARROW
    }

    /// Brings the screen to what the graph says.
    fn update(&mut self, ctx: &mut DriverCtx<'_, '_>, force: bool) {
        if let Err(e) = self.update_inner(ctx, force) {
            // a thing that cannot be shown must not leave a half-built screen whose presses go
            // nowhere: go home
            if matches!(self.data.opened(), Ok(Some(_))) && self.data.set_open(None).is_ok() {
                self.built = None;
                let _ = self.update_inner(ctx, true);
            }
            self.status(ctx, format!("error: {e}"));
        }
    }

    fn update_inner(&mut self, ctx: &mut DriverCtx<'_, '_>, force: bool) -> osis::Result<()> {
        self.narrow = self.is_narrow(ctx);
        self.data.db.settle();
        Graph::drain(&self.state.graph);
        let main = self.data.main_group()?;
        let sh = Graph::view(&self.state.graph, ("shell", main), move |r| shell(r, &("shell", main)))?.value;
        self.theme = Theme::named(sh.theme.as_deref().unwrap_or("frost"));
        self.mode = kit_mode(&sh.mode);
        let dark = self.dark(ctx);
        self.state.set_local(DARK, dark);
        if self.state.graph.peek(TICK) == 0
            && let Ok(t) = self.data.db.now()
        {
            self.state.set_local(TICK, t.0 / 60_000);
        }
        let look = Look::new(&self.theme, dark, sh.color.as_deref().and_then(parse));
        let layout = Layout { t: sh.t, home: sh.home, narrow: self.narrow, searching: sh.searching };
        let rebuild = force || self.built.as_ref() != Some(&layout) || look != *self.look;
        // starting a search changes the layout: the typing must carry on in the rebuilt field
        let keep_search = rebuild && ctx.render_root(self.window).focused_widget().is_some_and(|f| self.search_ids.contains(&f));
        if rebuild {
            self.look = Arc::new(look);
            // before the new screen's slots exist: what leaves takes its slot along
            let mut tree = std::mem::take(&mut self.tree);
            tree.clear(&self.state.clone(), &mut Draw { ui: self, ctx });
            self.tree = tree;
            self.build(ctx, &layout);
            self.show_roots(ctx, &layout, main)?;
            // focus rule: a new page puts the keyboard in a text field (home's search, a new
            // thing's title) or nowhere
            let title = std::mem::take(&mut self.focus_title).then(|| self.acts.editor_of(layout.t, "name.0")).flatten();
            let id = if layout.home { self.search_ids.first().copied() } else { title };
            let id = if keep_search { self.search_ids.first().copied() } else { id };
            let root = ctx.render_root(self.window);
            root.focus_on(id);
            if let Some(input) = id.filter(|_| keep_search) {
                root.edit_widget(input, |mut w| {
                    let mut a = w.downcast::<TextArea<true>>();
                    let end = a.widget.text().to_string().len();
                    TextArea::select_byte_range(&mut a, end, end);
                });
            }
            self.show_status(ctx);
        }
        let mut tree = std::mem::take(&mut self.tree);
        let r = tree.update(&self.state.clone(), &mut Draw { ui: self, ctx });
        self.tree = tree;
        r?;
        self.state.sessions.retain(|k| self.acts.editor_for(k).is_some());
        Ok(())
    }

    /// The tree's roots for a screen just built.
    fn show_roots(&mut self, ctx: &mut DriverCtx<'_, '_>, l: &Layout, main: Tid) -> osis::Result<()> {
        let window = self.state.clone();
        let mut tree = std::mem::take(&mut self.tree);
        let r = (|| {
            // every root is asked: one failing leaves the others up, and stays to recover
            let mut failed = None;
            let page = if l.home {
                ViewSpec { view_type: "opener".into(), subject: main, config: crate::view::Config::default().with("no_chrome", "true").with("title", "none") }
            } else {
                let mut s = open_spec(l.t);
                if self.narrow {
                    s.config = s.config.with("back", "true");
                }
                s
            };
            let key = format!("page:{}", l.t);
            self.fill_blocks(ctx, "page", vec![Block::View { key: key.clone(), spec: page.clone() }], None)?;
            keep_err(&mut failed, tree.show(&window, &mut Draw { ui: self, ctx }, &views::child_path("page", &key), &page));
            let results = |rail: bool| {
                let mut s = ViewSpec::new("results", main);
                if rail {
                    s.config = s.config.with(RAIL, "true");
                }
                s
            };
            if !l.home {
                if l.searching {
                    keep_err(&mut failed, tree.show(&window, &mut Draw { ui: self, ctx }, "rail", &results(true)));
                } else {
                    let spec = self.rail_spec(main);
                    self.fill_blocks(ctx, "rail", vec![Block::View { key: "favorites".into(), spec: spec.clone() }], None)?;
                    keep_err(&mut failed, tree.show(&window, &mut Draw { ui: self, ctx }, &views::child_path("rail", "favorites"), &spec));
                }
            }
            if self.slots.contains_key("results") {
                keep_err(&mut failed, tree.show(&window, &mut Draw { ui: self, ctx }, "results", &results(false)));
            }
            if self.slots.contains_key("new") {
                keep_err(&mut failed, tree.show(&window, &mut Draw { ui: self, ctx }, "new", &ViewSpec::new("creating", main)));
            }
            failed.map_or(Ok(()), Err)
        })();
        self.tree = tree;
        r
    }

    /// The device line, and the last diagnostic if any.
    fn show_status(&mut self, ctx: &mut DriverCtx<'_, '_>) {
        let s = format!("device {}{}", short(self.data.db.node()), self.diag.as_deref().map(|d| format!(" · {d}")).unwrap_or_default());
        self.status(ctx, s);
    }

    fn status(&mut self, ctx: &mut DriverCtx<'_, '_>, s: String) {
        let root = ctx.render_root(self.window);
        if root.get_widget_with_tag(STATUS).is_some() {
            root.edit_widget_with_tag(STATUS, |mut b| {
                if let Some(mut l) = SizedBox::child_mut(&mut b) {
                    TextArea::reset_text(&mut Prose::text_mut(&mut l.downcast()), &s);
                }
            });
        }
    }

    fn status_widget(&self) -> NewWidget<SizedBox> {
        NewWidget::new_with_tag(SizedBox::new(style::prose(&self.look, "", Text::Small)), STATUS)
    }

    /// An empty slot under `key`, filled by `fill`.
    fn slot(&mut self, key: &str) -> NewWidget<SizedBox> {
        let w = NewWidget::new(SizedBox::empty());
        self.slots.insert(key.to_string(), Slot { id: w.id(), model: Vec::new(), built: blocks::Built::default() });
        w
    }

    fn search_field(&mut self, big: bool) -> NewWidget<dyn Widget> {
        let look = self.look.clone();
        let query = self.state.graph.peek(QUERY);
        let (input, id) = style::input(&look, &query, if big { "Search notes, people, tags, views…" } else { "Search" }, Text::Body, false);
        self.search_ids.push(id);
        let pad = if big { (14.0, 18.0) } else { (8.0, 12.0) };
        let panel = NewWidget::new(Panel::new(input, look.clone(), PanelKind::Field, pad)).erased();
        #[cfg(target_os = "android")]
        {
            let chip = NewWidget::new(crate::widgets::Chip::new("Paste", None, crate::widgets::ChipMark::Icon(Icon::Plus), look.clone()));
            self.acts.press(chip.id(), Do::new(blocks::PasteSearch));
            return NewWidget::new(Flex::row().with_gap(Length::px(look.sp(8.0))).with_flex_child(panel, 1.0).with_child(chip)).erased();
        }
        #[allow(unreachable_code)]
        panel
    }

    fn build(&mut self, ctx: &mut DriverCtx<'_, '_>, l: &Layout) {
        self.acts.clear();
        self.slots.clear();
        self.search_ids.clear();
        self.scroll = None;
        self.pinned.clear();
        let w: NewWidget<dyn Widget> = if l.home { self.home_widget(l) } else { self.thing_widget() };
        let seed = if l.home { 0 } else { seed_of(&l.t.to_string()) };
        *ctx.window(self.window).base_color() = self.look.bg;
        let look = self.look.clone();
        ctx.render_root(self.window).edit_widget_with_tag(ROOT, |mut r| {
            Root::set_look(&mut r, look, seed);
            Root::set_child(&mut r, w);
        });
        self.built = Some(l.clone());
    }

    fn home_widget(&mut self, l: &Layout) -> NewWidget<dyn Widget> {
        let look = self.look.clone();
        let mut col = Flex::column().cross_axis_alignment(CrossAxisAlignment::Fill).with_gap(Length::px(look.sp(18.0)));
        col = col.with_child(style::label(&look, "osis", Text::Brand)).with_child(self.search_field(true));
        if l.searching {
            col = col.with_child(self.slot("results"));
        } else {
            col = col.with_flex_child(self.slot("page"), 1.0).with_child(self.slot("new"));
        }
        col = col.with_child(self.status_widget());
        let col = NewWidget::new_with_props(col, Properties::new().with(Padding::from_vh(look.sp(48.0), look.sp(16.0))));
        NewWidget::new(Limit::new(col, 940.0)).erased()
    }

    fn thing_widget(&mut self) -> NewWidget<dyn Widget> {
        let look = self.look.clone();
        let sp = |x: f64| look.sp(x);
        let page = self.slot("page");
        if self.narrow {
            let col = Flex::column().cross_axis_alignment(CrossAxisAlignment::Fill).with_flex_child(page, 1.0).with_child(self.status_widget());
            return NewWidget::new_with_props(col, Properties::new().with(Padding::all(sp(10.0)))).erased();
        }
        let home = NewWidget::new(crate::widgets::Tile::new(crate::widgets::TileStyle::Row, crate::widgets::TileIcon::Icon(Icon::Home), "osis", "Home", None, look.clone()));
        self.acts.press(home.id(), Do::new(Open(None)));
        let new = NewWidget::new(crate::widgets::Tile::new(crate::widgets::TileStyle::Row, crate::widgets::TileIcon::Icon(Icon::Plus), "New", "", None, look.clone()));
        self.acts.press(new.id(), Do::new(ToggleCreating));
        let search = self.search_field(false);
        let rail_list = self.slot("rail");
        let rail_new = self.slot("new");
        let rail = Flex::column()
            .cross_axis_alignment(CrossAxisAlignment::Fill)
            .with_gap(Length::px(sp(6.0)))
            .with_child(home)
            .with_child(search)
            .with_child(rail_list)
            .with_child(new)
            .with_child(rail_new)
            .with_child(self.status_widget());
        let rail = NewWidget::new(Portal::new(NewWidget::new(rail)).constrain_horizontal(true));
        let rail = NewWidget::new(Panel::new(rail, look.clone(), PanelKind::Panel, (14.0, 10.0)).fill_height(true));
        let row = Flex::row()
            .cross_axis_alignment(CrossAxisAlignment::Fill)
            .with_gap(Length::px(sp(16.0)))
            .with_child(NewWidget::new(SizedBox::new(rail).width(Length::px(264.0))))
            .with_flex_child(page, 1.0);
        NewWidget::new_with_props(row, Properties::new().with(Padding::all(sp(16.0)))).erased()
    }

    /// The rail, a collection view of the favorites.
    fn rail_spec(&self, main: Tid) -> ViewSpec {
        ViewSpec::new("collection", main).config_rail()
    }

    /// Shows `model` in the slot `key` if it changed; a form input with the focus keeps it (by
    /// place, caret at the end). Returns whether it rebuilt. Unknown slots are not on screen.
    fn fill_blocks(&mut self, ctx: &mut DriverCtx<'_, '_>, key: &str, model: Vec<Block>, current: Option<Tid>) -> osis::Result<bool> {
        let Some(slot) = self.slots.get(key) else { return Ok(false) };
        if slot.model == model {
            return Ok(false);
        }
        let id = slot.id;
        let focused = ctx.render_root(self.window).focused_widget();
        let place = focused.and_then(|f| slot.built.inputs.iter().position(|i| *i == f));
        let old = std::mem::take(&mut self.slots.get_mut(key).ok_or(osis::Error::Invalid("slot".into()))?.built);
        self.acts.forget(&old);
        let (w, built) = blocks::blocks(&self.data, &self.state, &self.look, &mut self.acts, key, &model, current);
        let root = ctx.render_root(self.window);
        root.edit_widget(id, |mut b| SizedBox::set_child(&mut b.downcast(), w));
        if let Some(input) = place.and_then(|p| built.inputs.get(p).copied())
            && root.focus_on(Some(input))
        {
            root.edit_widget(input, |mut w| {
                let mut a = w.downcast::<TextArea<true>>();
                let end = a.widget.text().to_string().len();
                TextArea::select_byte_range(&mut a, end, end);
            });
        }
        for (k, c) in &built.children {
            let p = views::child_path(key, k);
            if let Some(old) = self.slots.insert(p, Slot { id: *c, model: Vec::new(), built: blocks::Built::default() }) {
                self.acts.forget(&old.built);
            }
        }
        for (k, c) in &built.feet {
            let p = views::child_path(key, k);
            self.slots.insert(format!("{p}#foot"), Slot { id: *c, model: Vec::new(), built: blocks::Built::default() });
            self.pinned.insert(p.clone());
        }
        for (k, c) in &built.portals {
            self.scroll = Some(*c);
            self.pinned.insert(views::child_path(key, k));
        }
        if let Some(slot) = self.slots.get_mut(key) {
            slot.model = model;
            slot.built = built;
        }
        Ok(true)
    }

    /// Runs an action on the UI thread, then applies what it asked of the shell.
    fn run(&mut self, ctx: &mut DriverCtx<'_, '_>, d: Do, input: Input) {
        let act = Act::new(&self.data, &self.state);
        let r = d.run(&act, &input);
        let e = act.effects.borrow().clone();
        if let Err(e) = r {
            self.status(ctx, format!("error: {e}"));
        }
        if e.focus_title {
            self.focus_title = true;
        }
        if let Some(text) = e.paste {
            self.state.set_local(QUERY, text.trim().to_string());
            self.enter_search(ctx);
        }
    }

    fn enter_search(&mut self, ctx: &mut DriverCtx<'_, '_>) {
        let q = self.state.graph.peek(QUERY).trim().to_string();
        match classify(&q) {
            Paste::Link => self.start_redeem(ctx, q),
            Paste::Peer => {
                let r = q.parse::<osis::Address>().map_err(|e| e.to_string()).and_then(|a| self.data.db.add_peer(&a).map_err(|e| e.to_string()));
                match r {
                    Ok(()) => {
                        let _ = self.data.ensure_profile();
                        self.state.set_local(QUERY, String::new());
                        self.status(ctx, format!("peer {q} added"));
                        self.update(ctx, true);
                    }
                    Err(e) => self.status(ctx, format!("not added: {e}")),
                }
            }
            Paste::Query => {
                let dark = self.look.dark;
                let cx = Cx::new(&self.data, &self.state, dark);
                let first = search(&cx, &q).ok().and_then(|f| f.scopes.first().or(f.named.first()).or(f.mentions.first().map(|(t, _)| t)).or(f.in_scopes.first()).copied());
                drop(cx);
                if let Some(t) = first {
                    self.run(ctx, Do::new(Open(Some(t))), Input::Press);
                }
            }
        }
    }

    /// Redeems a link off the UI thread (it waits for the link's peer).
    fn start_redeem(&mut self, ctx: &mut DriverCtx<'_, '_>, link: String) {
        if self.redeeming {
            return;
        }
        self.redeeming = true;
        self.status(ctx, "joining…".into());
        let (parts, tx, waker) = (self.data.parts(), self.tx.clone(), self.waker.clone());
        std::thread::spawn(move || {
            let r = Data::from_parts(parts).redeem(&link).map_err(|e| e.to_string());
            let _ = tx.send(Msg::Redeemed(r));
            waker.wake();
        });
    }

    fn redeemed(&mut self, ctx: &mut DriverCtx<'_, '_>, r: Result<Tid, String>) {
        self.redeeming = false;
        match r {
            Ok(t) => {
                let _ = self.data.ensure_profile();
                self.state.set_local(QUERY, String::new());
                self.diag = None;
                if let Err(e) = self.data.set_open(Some(t)) {
                    self.status(ctx, format!("error: {e}"));
                }
            }
            Err(e) => {
                self.diag = Some(format!("join failed: {e}"));
                self.status(ctx, format!("join failed: {e}"));
            }
        }
    }

    fn typed(&mut self, ctx: &mut DriverCtx<'_, '_>, id: WidgetId, a: TextAction) {
        if self.search_ids.contains(&id) {
            match a {
                TextAction::Changed(q) => self.state.set_local(QUERY, q),
                TextAction::Entered(_) => self.enter_search(ctx),
            }
            return;
        }
        if let Some(key) = self.acts.editor(id) {
            match a {
                TextAction::Changed(text) => {
                    if let Err(e) = self.state.sessions.typed(&key, &text) {
                        self.status(ctx, format!("error: {e}"));
                    }
                }
                TextAction::Entered(_) => {
                    if let Some(d) = self.acts.on_enter(id) {
                        self.run(ctx, d, Input::Press);
                    }
                }
            }
            return;
        }
        if self.acts.has_form(id) {
            match a {
                TextAction::Changed(t) => self.acts.set_form_text(id, t),
                TextAction::Entered(t) => {
                    self.acts.set_form_text(id, t);
                    self.save_form(ctx, id);
                }
            }
        }
    }

    /// Saves a form input's text unless it is what was saved last.
    fn save_form(&mut self, ctx: &mut DriverCtx<'_, '_>, id: WidgetId) {
        let Some((d, text)) = self.acts.form_dirty(id) else { return };
        let r = d.run(&Act::new(&self.data, &self.state), &Input::Text(text.clone()));
        match r {
            Ok(()) => {
                // only once written: a rejected text is reported again on the next Enter or blur
                self.acts.set_form_saved(id, text);
            }
            Err(e) => self.status(ctx, format!("error: {e}")),
        }
    }

    /// A merge into an editor's session: show it, the selection mapped through the edits.
    fn show_merge(&mut self, ctx: &mut DriverCtx<'_, '_>, key: &Key) {
        let root = ctx.render_root(self.window);
        let Some((text, shown, reported)) = self.state.sessions.merged(key) else { return };
        if let Some(id) = self.acts.editor_for(key)
            && root.has_widget(id)
        {
            root.edit_widget(id, |mut w| {
                let mut a = w.downcast::<TextArea<true>>();
                let now = a.widget.text().to_string();
                if now == text {
                    return;
                }
                let (anchor, focus) = a.widget.selection_bytes();
                TextArea::reset_text(&mut a, &text);
                // the widget shows `shown` unless an input method is composing
                if now == shown {
                    let edits = shown_edits(&shown, reported, &text);
                    let m = |b| map_byte(&shown, &edits, &text, b);
                    TextArea::select_byte_range(&mut a, m(anchor), m(focus));
                }
            });
        }
    }

    fn scroll_end(&mut self, ctx: &mut DriverCtx<'_, '_>) {
        let Some(id) = self.scroll else { return };
        let root = ctx.render_root(self.window);
        if root.has_widget(id) {
            root.edit_widget(id, |mut w| {
                Portal::set_viewport_pos(&mut w.downcast::<Portal<Flex>>(), crate::masonry::kurbo::Point::new(0.0, 1e9));
            });
        }
    }
}

/// Keeps the first failure of several things all tried.
fn keep_err(failed: &mut Option<osis::Error>, r: osis::Result<()>) {
    if let Err(e) = r {
        failed.get_or_insert(e);
    }
}

fn seed_of(s: &str) -> u64 {
    s.bytes().fold(7u64, |a, b| a.wrapping_mul(31).wrapping_add(u64::from(b)))
}

fn kit_mode(m: &ModeChoice) -> Mode {
    match m {
        ModeChoice::Auto => Mode::Auto,
        ModeChoice::Light => Mode::Light,
        ModeChoice::Dark => Mode::Dark,
    }
}

/// The first 8 characters of a tid, for the status line.
fn short(t: Tid) -> String {
    t.to_string().chars().take(8).collect()
}

impl AppDriver for Ui {
    /// The window exists now: register the fonts; wakes before it were dropped by masonry_winit,
    /// so what is due runs now, and update once.
    fn on_start(&mut self, state: &mut crate::masonry_winit::app::MasonryState<'_>) {
        crate::fonts::register(state);
        self.data.db.settle();
        while self.rx.try_recv().is_ok() {}
        self.waker.wake();
    }

    /// A new width class rebuilds the screen (`update` compares it).
    fn on_resized(&mut self, _w: WindowId, ctx: &mut DriverCtx<'_, '_>, _size: PhysicalSize<u32>) {
        if self.built.is_some() && self.is_narrow(ctx) != self.narrow {
            self.update(ctx, false);
        }
    }

    /// Auto follows the system's light or dark.
    fn on_theme_changed(&mut self, _w: WindowId, ctx: &mut DriverCtx<'_, '_>, theme: WinitTheme) {
        self.system_dark = Some(theme == WinitTheme::Dark);
        if self.mode == Mode::Auto {
            self.update(ctx, false);
        }
    }

    fn on_action(&mut self, _w: WindowId, ctx: &mut DriverCtx<'_, '_>, id: WidgetId, action: ErasedAction) {
        if action.is::<Wakeup>() {
            self.data.db.settle();
            for m in self.rx.try_iter().collect::<Vec<_>>() {
                match m {
                    Msg::Diagnostic(d) => {
                        self.diag = Some(d);
                        self.show_status(ctx);
                    }
                    Msg::Merged(k) => self.show_merge(ctx, &k),
                    Msg::Redeemed(r) => self.redeemed(ctx, r),
                    Msg::ScrollEnd => self.scroll_end(ctx),
                    Msg::Tick => {
                        if let Ok(now) = self.data.db.now() {
                            self.state.set_local(TICK, now.0 / 60_000);
                        }
                    }
                }
            }
            self.update(ctx, false);
        } else if action.is::<Press>() {
            if let Some(d) = self.acts.pressed(id) {
                self.run(ctx, d, Input::Press);
            }
        } else if action.is::<Blur>() {
            if let Some(input) = self.acts.blur_input(id) {
                self.save_form(ctx, input);
            }
        } else if let Some(Reorder { from, to }) = action.downcast_ref::<Reorder>().copied() {
            if let Some(d) = self.acts.reorder(id) {
                self.run(ctx, d, Input::Reorder { from, to });
            }
        } else if let Some(p) = action.downcast_ref::<ChipPress>().copied() {
            let d = match p {
                ChipPress::Open => self.acts.pressed(id),
                ChipPress::Remove => self.acts.removed(id),
            };
            if let Some(d) = d {
                self.run(ctx, d, Input::Press);
            }
        } else if let Ok(a) = action.downcast::<TextAction>() {
            self.typed(ctx, id, *a);
        }
    }
}

/// The initial widget tree: the root over an empty screen (the first update builds it).
pub fn tree(look: Arc<Look>) -> NewWidget<dyn Widget> {
    NewWidget::new_with_tag(Root::new(NewWidget::new(SizedBox::empty()), look), ROOT).erased()
}
