//! The shell (Masonry over kit): the window, the rail, the bar, one screen: the open thing's page
//! (home is the app group's page; `opened()` being `None` shows it). What is shown comes from
//! osis through a `Tree` of view nodes: a read that changed marks its node dirty on the UI thread
//! (`Dispatcher::Pump`), and only marked nodes run. A slot per facet section is rebuilt only when
//! its model changes, so editors keep their caret.

mod blocks;
mod start;

pub use start::{Start, Started};

use crate::edit::{map_byte, shown_edits};
use crate::facets::members::ToggleCreating;
use crate::schema::Mode as ModeChoice;
use crate::store::{Data, Reader};
use crate::view::search::{Paste, classify, search};
use crate::input::Input as Pointers;
use crate::platform::Platform;
use crate::view::{Act, Block, Cx, DARK, Do, Graph, Icon, Input, Open, QUERY, Section, Surface, TICK, TYPE_IN, Tree, ViewSpec, WindowState};
use crate::view::keyed::{self, ListSteps};
use crate::view::paged::{Item, LIST_WINDOW, ListRow, ListWindow};
use crate::view::sessions::Key;
use crate::views::{self, RAIL, open_spec};
use osis::{Subscription, Tid};
use crate::masonry::app::RenderRoot;
use crate::masonry::peniko::Color;
use crate::masonry::core::{Capitalize, EnterKey, TextInputHints, TextPurpose};
use crate::masonry::core::{ErasedAction, Handled, NewWidget, PointerEvent, Properties, TextCommand, TextEvent, Widget, WidgetId, WidgetTag};
use crate::masonry::properties::Padding;
use crate::masonry::properties::types::{CrossAxisAlignment, Length};
use crate::masonry::widgets::{Flex, IndexedStack, Prose, SizedBox, TextAction, TextArea};
use crate::theme::{Look, Mode, Theme, parse};
use crate::widgets::style::{self, Text};
use crate::widgets::{Blur, ChipPress, Frame, GUTTER, ListAction, MenuPick, Page, Panel, PanelKind, Press, ROW_MIN, Root, VirtualList};
use crate::window::Waker;
use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::sync::mpsc::{Receiver, Sender, channel};

pub const ROOT: WidgetTag<Root> = WidgetTag::new("root");
/// Holds the status label (a tag cannot be given together with properties).
const STATUS: WidgetTag<SizedBox> = WidgetTag::new("status");

/// Space around the screen's columns and between them, before spacing.
const EDGE: f64 = 16.0;
/// The rail panel's padding (vertical, horizontal), before spacing.
const RAIL_PAD: (f64, f64) = (14.0, 10.0);

/// The rail's width: a row at its least useful width, the bar a long list keeps, the panel's sides.
fn rail_width(look: &Look) -> f64 {
    look.sp(ROW_MIN) + GUTTER + 2.0 * look.sp(RAIL_PAD.1)
}

/// The least width (logical px, clear of insets) that shows the rail: the rail and a page beside
/// it, with the screen's edges and the gap between. A page at its smallest useful width is as wide
/// as the rail, as it holds the same rows.
pub fn rail_needs(look: &Look) -> f64 {
    2.0 * rail_width(look) + 3.0 * look.sp(EDGE)
}

/// What the shell hears besides graph nodes going dirty.
#[derive(Debug)]
pub enum Msg {
    /// An editor's session merged a write its widget does not show yet.
    Merged(Key),
    /// An osis diagnostic (a thing that will not sync, a callback that panicked, ...).
    Diagnostic(String),
    /// A redemption of a pasted link ended: the thing, or why not.
    Redeemed(Result<Tid, String>),
    /// A minute passed.
    Tick,
    /// The long-press timer `seq` ran out (`input::Alarm`).
    LongPress(u64),
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

/// What selects the widget structure of a screen. Starting a search does not: the search field
/// stays the same widget (an input method keeps its session), and stacks beside it switch to
/// the results (`Ui::search_stacks`).
#[derive(Clone, Debug, PartialEq)]
struct Layout {
    t: Tid,
    home: bool,
    /// The rail beside the open thing's page: it fits (`rail_needs`). Home has none.
    rail: bool,
}

/// What `fill_blocks` did.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Filled {
    Same,
    /// Rows changed in their lists; the widgets around them stayed.
    Patched,
    /// As `Patched`, and rows that are child views came or went: the tree reconciles them.
    PatchedChildren,
    Rebuilt,
}

impl Filled {
    /// The node's children must be reconciled.
    fn children(self) -> bool {
        matches!(self, Filled::Rebuilt | Filled::PatchedChildren)
    }
}

/// `Ui` as the tree's surface.
struct Draw<'u> {
    ui: &'u mut Ui,
    rr: &'u mut RenderRoot,
}

impl Surface for Draw<'_> {
    fn show(&mut self, path: &str, out: &Section) -> osis::Result<bool> {
        let ui = &mut *self.ui;
        // the rail (results, favorites) marks the open thing
        let in_rail = path == RAIL || path.starts_with(&views::child_path(RAIL, ""));
        let current = in_rail.then(|| ui.built.as_ref().map(|l| l.t)).flatten();
        let mut blocks = out.blocks.clone();
        // a pinned foot and following the end only when this node fills the page
        let (foot, filled) = (out.foot.clone(), ui.pinned.contains(path));
        if !filled {
            blocks.extend(foot.iter().cloned());
        }
        let changed = ui.fill_blocks(self.rr, path, blocks, current)?;
        if filled {
            let key = format!("{path}#foot");
            let foot_changed = ui.fill_blocks(self.rr, &key, foot, None)?;
            return Ok(changed.children() || foot_changed.children());
        }
        Ok(changed.children())
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

/// The platform a shell gave `Ui::start`, and the pointer input through it.
struct Attached {
    platform: Box<dyn Platform>,
    input: Pointers,
    /// Root reports animation frames (a fling goes on).
    ticking: bool,
}

impl Attached {
    fn new(platform: Box<dyn Platform>, alarm: crate::input::Alarm) -> Attached {
        Attached { input: Pointers::new(platform.thresholds(), alarm), platform, ticking: false }
    }

    /// A pointer event, on its way to `rr` through the gestures.
    fn pointer(&mut self, rr: &mut RenderRoot, e: PointerEvent) {
        self.input.pointer(rr, &mut *self.platform, e);
        self.tick(rr);
    }

    /// A text event, on its way to `rr` past the selection menu.
    fn text_event(&mut self, rr: &mut RenderRoot, e: TextEvent) -> Handled {
        self.input.text_event(rr, &mut *self.platform, e)
    }

    /// The focused field may have changed: the selection menu follows it.
    fn follow(&mut self, rr: &mut RenderRoot) {
        self.input.follow(rr, &mut *self.platform);
    }

    /// The selection menu's item `c` was picked.
    fn pick(&mut self, rr: &mut RenderRoot, c: TextCommand) {
        self.input.pick(rr, &mut *self.platform, c);
    }

    /// An animation frame Root reported (`Frame`): a fling moves on; with none going on Root
    /// stops reporting (also when an `Attached` before this one asked it to).
    fn frame(&mut self, rr: &mut RenderRoot, interval: u64) {
        self.input.frame(rr, interval);
        if !self.input.flinging() {
            self.ticking = false;
            rr.edit_widget_with_tag(ROOT, |mut r| Root::set_ticking(&mut r, false));
        }
    }

    /// Root reports animation frames while a fling goes on.
    fn tick(&mut self, rr: &mut RenderRoot) {
        let on = self.input.flinging();
        if on != self.ticking {
            self.ticking = on;
            rr.edit_widget_with_tag(ROOT, |mut r| Root::set_ticking(&mut r, on));
        }
    }
}

pub struct Ui {
    data: Data,
    tx: Sender<Msg>,
    rx: Receiver<Msg>,
    waker: Waker,
    theme: Theme,
    mode: Mode,
    look: Arc<Look>,
    built: Option<Layout>,
    state: WindowState,
    /// The views on screen.
    tree: Tree,
    slots: HashMap<String, Slot>,
    /// The system's dark mode, followed by `Mode::Auto`.
    system_dark: bool,
    /// Physical pixels per logical pixel.
    scale: f64,
    /// What covers the window's edges (physical px: left, top, right, bottom).
    insets: [f64; 4],
    search_ids: Vec<WidgetId>,
    /// Stacks showing what is there without a search (child 0) or the results (child 1).
    search_stacks: Vec<WidgetId>,
    /// What the search stacks show.
    searching: bool,
    /// The platform and the pointer input through it, from `start` on.
    attached: Option<Attached>,
    /// Fields built to type in (`TYPE_IN`), served after the update.
    typing: Vec<WidgetId>,
    /// The widgets that report an action and what it does.
    acts: blocks::Acts,
    _diag_sub: Subscription,
    diag: Option<String>,
    redeeming: bool,
    /// Nodes that fill the page: their foot is pinned.
    pinned: BTreeSet<String>,
}

impl Ui {
    pub fn new(data: Data, waker: Waker) -> osis::Result<Ui> {
        // osis callbacks run on this thread, inside the `settle` that the Wakeup drains after
        let (tx, rx) = channel();
        let (theme, mode) = data.look().unwrap_or((None, ModeChoice::Auto));
        let theme = Theme::named(theme.as_deref());
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
            tx,
            rx,
            waker,
            theme,
            mode,
            look,
            built: None,
            state,
            tree: Tree::default(),
            slots: HashMap::new(),
            system_dark: false,
            scale: 1.0,
            insets: [0.0; 4],
            search_ids: Vec::new(),
            search_stacks: Vec::new(),
            searching: false,
            attached: None,
            typing: Vec::new(),
            acts: blocks::Acts::default(),
            _diag_sub: diag_sub,
            diag: None,
            redeeming: false,
            pinned: BTreeSet::new(),
        })
    }

    /// The first look, for the initial root widget.
    pub fn look(&self) -> Arc<Look> {
        self.look.clone()
    }

    fn dark(&self) -> bool {
        match self.mode {
            Mode::Light => false,
            Mode::Dark => true,
            Mode::Auto => self.system_dark,
        }
    }

    /// Whether the rail fits in the window's width clear of its insets, in `look`.
    fn rail_fits(&self, rr: &RenderRoot, look: &Look) -> bool {
        let [l, _, r, _] = self.insets;
        (f64::from(rr.size().width) - l - r) / self.scale.max(0.1) >= rail_needs(look)
    }

    /// Brings the screen to what the graph says.
    fn update(&mut self, rr: &mut RenderRoot, force: bool) {
        if let Err(e) = self.update_inner(rr, force) {
            // a thing that cannot be shown must not leave a half-built screen whose presses go
            // nowhere: go home
            if matches!(self.data.opened(), Ok(Some(_))) && self.data.set_open(None).is_ok() {
                self.built = None;
                let _ = self.update_inner(rr, true);
            }
            self.status(rr, format!("error: {e}"));
        }
    }

    fn update_inner(&mut self, rr: &mut RenderRoot, force: bool) -> osis::Result<()> {
        self.data.db.settle();
        Graph::drain(&self.state.graph);
        let main = self.data.main_group()?;
        let sh = Graph::view(&self.state.graph, ("shell", main), move |r| shell(r, &("shell", main)))?.value;
        self.theme = Theme::named(sh.theme.as_deref());
        self.mode = kit_mode(&sh.mode);
        let dark = self.dark();
        self.state.set_local(DARK, dark);
        if self.state.graph.peek(TICK) == 0
            && let Ok(t) = self.data.db.now()
        {
            self.state.set_local(TICK, t.0 / 60_000);
        }
        let look = Look::new(&self.theme, dark, sh.color.as_deref().and_then(parse));
        let layout = Layout { t: sh.t, home: sh.home, rail: !sh.home && self.rail_fits(rr, &look) };
        let rebuild = force || self.built.as_ref() != Some(&layout) || look != *self.look;
        self.searching = sh.searching;
        // a rebuild for another reason (a synced theme, the rail coming or going) keeps the typing in
        // the search field it was in
        let in_search = rr.focused_widget().and_then(|f| self.search_ids.iter().position(|i| *i == f));
        if rebuild {
            self.look = Arc::new(look);
            if let Some(a) = self.attached.as_mut() {
                a.input.set_look(self.look.clone());
            }
            // before the new screen's slots exist: what leaves takes its slot along
            let mut tree = std::mem::take(&mut self.tree);
            tree.clear(&self.state.clone(), &mut Draw { ui: self, rr });
            self.tree = tree;
            self.build(rr, &layout);
            self.show_roots(rr, &layout, main)?;
            // focus rule: keys go to home's search field, else nowhere until a field wants typing
            let id = if layout.home { self.search_ids.first().copied() } else { None };
            let kept = in_search.and_then(|i| self.search_ids.get(i).copied());
            rr.focus_on(kept.or(id));
            if let Some(input) = kept {
                rr.edit_widget(input, |mut w| {
                    let mut a = w.downcast::<TextArea<true>>();
                    let end = a.widget.text().to_string().len();
                    TextArea::select_byte_range(&mut a, end, end);
                });
            }
            self.show_status(rr);
        } else {
            for &id in &self.search_stacks {
                rr.edit_widget(id, |mut w| IndexedStack::set_active_child(&mut w.downcast(), usize::from(sh.searching)));
            }
        }
        let mut tree = std::mem::take(&mut self.tree);
        let r = tree.update(&self.state.clone(), &mut Draw { ui: self, rr });
        self.tree = tree;
        r?;
        self.state.sessions.retain(|k| self.acts.editor_for(k).is_some());
        self.serve_typing(rr);
        Ok(())
    }

    /// The first field to type in (`TYPE_IN`) that the update built takes the focus and wants the
    /// keyboard. `TYPE_IN` lasts one update: the one after it was set, which built the field or
    /// never will.
    fn serve_typing(&mut self, rr: &mut RenderRoot) {
        if let Some(id) = std::mem::take(&mut self.typing).into_iter().find(|id| rr.has_widget(*id)) {
            match self.attached.as_mut() {
                Some(a) => a.input.type_in(rr, &mut *a.platform, id),
                None => {
                    rr.focus_on(Some(id));
                }
            }
        }
        if self.state.graph.peek(TYPE_IN).is_some() {
            self.state.set_local(TYPE_IN, None);
        }
    }

    /// The tree's roots for a screen just built.
    fn show_roots(&mut self, rr: &mut RenderRoot, l: &Layout, main: Tid) -> osis::Result<()> {
        let window = self.state.clone();
        let mut tree = std::mem::take(&mut self.tree);
        let r = (|| {
            // every root is asked: one failing leaves the others up, and stays to recover
            let mut failed = None;
            let page = if l.home {
                ViewSpec { view_type: "opener".into(), subject: main, config: crate::view::Config::default().with("no_chrome", "true").with("title", "none") }
            } else {
                // without the rail nothing else leads home
                let mut s = open_spec(l.t);
                if !l.rail {
                    s.config = s.config.with("back", "true");
                }
                s
            };
            let key = format!("page:{}", l.t);
            self.fill_blocks(rr, "page", vec![Block::View { key: key.clone(), spec: page.clone() }], None)?;
            keep_err(&mut failed, tree.show(&window, &mut Draw { ui: self, rr }, &views::child_path("page", &key), &page));
            let results = |rail: bool| {
                let mut s = ViewSpec::new("results", main);
                if rail {
                    s.config = s.config.with(RAIL, "true");
                }
                s
            };
            if !l.home {
                let spec = self.rail_spec(main);
                self.fill_blocks(rr, "rail", vec![Block::View { key: "favorites".into(), spec: spec.clone() }], None)?;
                keep_err(&mut failed, tree.show(&window, &mut Draw { ui: self, rr }, &views::child_path("rail", "favorites"), &spec));
                keep_err(&mut failed, tree.show(&window, &mut Draw { ui: self, rr }, &views::child_path(RAIL, "results"), &results(true)));
            }
            if self.slots.contains_key("results") {
                keep_err(&mut failed, tree.show(&window, &mut Draw { ui: self, rr }, "results", &results(false)));
            }
            if self.slots.contains_key("new") {
                keep_err(&mut failed, tree.show(&window, &mut Draw { ui: self, rr }, "new", &ViewSpec::new("creating", main)));
            }
            failed.map_or(Ok(()), Err)
        })();
        self.tree = tree;
        r
    }

    /// The device line, and the last diagnostic if any.
    fn show_status(&mut self, rr: &mut RenderRoot) {
        let s = format!("device {}{}", short(self.data.db.node()), self.diag.as_deref().map(|d| format!(" · {d}")).unwrap_or_default());
        self.status(rr, s);
    }

    fn status(&mut self, rr: &mut RenderRoot, s: String) {
        let root = &mut *rr;
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

    /// `plain`, or the search's `results` while searching.
    fn search_stack(&mut self, plain: NewWidget<impl Widget + ?Sized>, results: NewWidget<impl Widget + ?Sized>) -> NewWidget<dyn Widget> {
        let w = NewWidget::new(IndexedStack::new().with_child(plain).with_child(results).with_active_child(usize::from(self.searching)));
        self.search_stacks.push(w.id());
        w.erased()
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
        let hints = TextInputHints { purpose: TextPurpose::Search, enter: EnterKey::Search, capitalize: Capitalize::None, suggest: true, multiline: false };
        let (input, id) = style::input(&look, &query, if big { "Search notes, people, tags, views…" } else { "Search" }, Text::Body, false, hints);
        self.search_ids.push(id);
        let pad = if big { (14.0, 18.0) } else { (8.0, 12.0) };
        NewWidget::new(Panel::new(input, look.clone(), PanelKind::Field, pad)).erased()
    }

    fn build(&mut self, rr: &mut RenderRoot, l: &Layout) {
        self.acts.clear();
        self.slots.clear();
        self.search_ids.clear();
        self.search_stacks.clear();
        self.pinned.clear();
        let w: NewWidget<dyn Widget> = if l.home { self.home_widget() } else { self.thing_widget(l.rail) };
        let seed = if l.home { 0 } else { seed_of(&l.t.to_string()) };
        let look = self.look.clone();
        rr.edit_widget_with_tag(ROOT, |mut r| {
            Root::set_look(&mut r, look, seed);
            Root::set_child(&mut r, w);
        });
        self.built = Some(l.clone());
    }

    fn home_widget(&mut self) -> NewWidget<dyn Widget> {
        let look = self.look.clone();
        let mut col = Flex::column().cross_axis_alignment(CrossAxisAlignment::Fill).with_gap(Length::px(look.sp(18.0)));
        col = col.with_child(style::heading(&look, "osis", Text::Brand)).with_child(self.search_field(true));
        let page = Flex::column().cross_axis_alignment(CrossAxisAlignment::Fill).with_gap(Length::px(look.sp(18.0))).with_flex_child(self.slot("page"), 1.0).with_child(self.slot("new"));
        let results = self.slot("results");
        col = col.with_flex_child(self.search_stack(NewWidget::new(page), results), 1.0);
        col = col.with_child(self.status_widget());
        let col = NewWidget::new_with_props(col, Properties::new().with(Padding::from_vh(look.sp(48.0), look.sp(16.0))));
        NewWidget::new(Page::new(col, look)).erased()
    }

    fn thing_widget(&mut self, rail: bool) -> NewWidget<dyn Widget> {
        let look = self.look.clone();
        let sp = |x: f64| look.sp(x);
        let page = self.slot("page");
        if !rail {
            let col = Flex::column().cross_axis_alignment(CrossAxisAlignment::Fill).with_flex_child(page, 1.0).with_child(self.status_widget());
            return NewWidget::new_with_props(col, Properties::new().with(Padding::all(sp(EDGE)))).erased();
        }
        let home = NewWidget::new(crate::widgets::Tile::new(crate::widgets::TileStyle::Row, crate::widgets::TileIcon::Icon(Icon::Home), "osis", "Home", None, look.clone()));
        self.acts.press(home.id(), Do::new(Open(None)));
        let new = NewWidget::new(crate::widgets::Tile::new(crate::widgets::TileStyle::Row, crate::widgets::TileIcon::Icon(Icon::Plus), "New", "", None, look.clone()));
        self.acts.press(new.id(), Do::new(ToggleCreating));
        let search = self.search_field(false);
        let rail_list = self.slot("rail");
        let rail_results = self.slot(&views::child_path(RAIL, "results"));
        let rail_list = self.search_stack(rail_list, rail_results);
        let rail_new = self.slot("new");
        let rail = Flex::column()
            .cross_axis_alignment(CrossAxisAlignment::Fill)
            .with_gap(Length::px(sp(6.0)))
            .with_child(home)
            .with_child(search)
            .with_flex_child(rail_list, 1.0)
            .with_child(new)
            .with_child(rail_new)
            .with_child(self.status_widget());
        let rail = NewWidget::new(Page::new(NewWidget::new(rail), look.clone()));
        let rail = NewWidget::new(Panel::new(rail, look.clone(), PanelKind::Panel, RAIL_PAD).fill_height(true));
        let row = Flex::row()
            .cross_axis_alignment(CrossAxisAlignment::Fill)
            .with_gap(Length::px(sp(EDGE)))
            .with_child(NewWidget::new(SizedBox::new(rail).width(Length::px(rail_width(&look)))))
            .with_flex_child(page, 1.0);
        NewWidget::new_with_props(row, Properties::new().with(Padding::all(sp(EDGE)))).erased()
    }

    /// The rail, a collection view of the favorites.
    fn rail_spec(&self, main: Tid) -> ViewSpec {
        ViewSpec::new("collection", main).config_rail()
    }

    /// Shows `model` in the slot `key` if it changed: rows that changed in their lists alone, else
    /// a rebuild, where a form input with the focus keeps it (by place, caret at the end). Unknown
    /// slots are not on screen.
    fn fill_blocks(&mut self, rr: &mut RenderRoot, key: &str, model: Vec<Block>, current: Option<Tid>) -> osis::Result<Filled> {
        let Some(slot) = self.slots.get(key) else { return Ok(Filled::Same) };
        if slot.model == model {
            return Ok(Filled::Same);
        }
        if let Some(steps) = keyed::steps(&slot.model, &model)
            && steps.iter().all(|(i, _)| slot.built.lists.contains_key(i))
        {
            let children = self.patch(rr, key, &model, steps, current);
            if let Some(slot) = self.slots.get_mut(key) {
                slot.model = model;
            }
            return Ok(if children { Filled::PatchedChildren } else { Filled::Patched });
        }
        let id = slot.id;
        let focused = rr.focused_widget();
        let place = focused.and_then(|f| slot.built.inputs.iter().position(|i| *i == f));
        let old = std::mem::take(&mut self.slots.get_mut(key).ok_or(osis::Error::Invalid("slot".into()))?.built);
        self.acts.forget(&old);
        let (w, built) = blocks::blocks(&self.data, &self.state, &self.look, &mut self.acts, key, &model, current);
        let root = &mut *rr;
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
        if let Some(id) = built.typing {
            self.typing.push(id);
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
        for k in &built.pinned {
            self.pinned.insert(views::child_path(key, k));
        }
        if let Some(slot) = self.slots.get_mut(key) {
            slot.model = model;
            slot.built = built;
        }
        Ok(Filled::Rebuilt)
    }

    /// Applies row steps to the lists of the slot `key`: only the rows named are touched, and the
    /// row at the top stays where it is. Returns whether child views came or went.
    fn patch(&mut self, rr: &mut RenderRoot, key: &str, model: &[Block], steps: ListSteps, current: Option<Tid>) -> bool {
        let root = &mut *rr;
        let mut made = Vec::new();
        let mut views_went = false;
        let Ui { slots, acts, data, state, look, .. } = self;
        let Some(slot) = slots.get_mut(key) else { return false };
        for (i, ops) in steps {
            let Some(list) = slot.built.lists.get_mut(&i) else { continue };
            let Some(Block::List(m)) = model.get(i) else { continue };
            views_went |= list.keyed.rows().any(|b| !b.children.is_empty());
            let mut maker = blocks::Maker { data, window: state, look, acts, current, path: key, style: m.shape.style, rows: &m.rows, children: Vec::new() };
            root.edit_widget(list.widget, |mut w| {
                let mut w = w.downcast::<VirtualList>();
                // the row at the top, by key: rows come and go around it
                let anchor = list.keyed.keys().nth(w.widget.anchor()).cloned();
                // gone: the next row shown takes its place
                let at = anchor.as_ref().and_then(|k| {
                    let mut old = list.keyed.keys().skip_while(|o| *o != k);
                    old.find_map(|o| m.rows.iter().position(|r| r.key == *o))
                });
                list.keyed.apply(&mut w, &ops, &mut maker);
                let spans = m.rows.iter().map(|r| matches!(r.item, Item::Label(_))).collect();
                let fixed = usize::from(matches!(m.rows.last(), Some(ListRow { item: Item::New(_), .. })));
                VirtualList::set_window(&mut w, m.first.unwrap_or(0), m.total, m.more_before, m.more_after, spans, fixed);
                VirtualList::set_anchor(&mut w, at);
            });
            made.append(&mut maker.children);
        }
        let any = !made.is_empty() || views_went;
        for (k, c) in made {
            let p = views::child_path(key, &k);
            slots.insert(p, Slot { id: c, model: Vec::new(), built: blocks::Built::default() });
        }
        any
    }

    /// A list asked for another window: its anchor is named by key, so what the graph answers is
    /// placed around that row.
    fn list_moved(&mut self, id: WidgetId, anchor: usize, before: usize, after: usize, stuck: bool) {
        let Some((window, slot, block)) = self.acts.list_of(id) else { return };
        let Some(m) = self.slots.get(&slot) else { return };
        let scope = match m.model.get(block) {
            Some(Block::List(l)) => l.shape.scope.clone(),
            _ => String::new(),
        };
        let v = if stuck {
            ListWindow { scope, ..ListWindow::default() }
        } else {
            let Some(key) = m.built.lists.get(&block).and_then(|l| l.keyed.keys().nth(anchor).cloned()) else { return };
            let row = match m.model.get(block) {
                Some(Block::List(l)) => l.first().map(|f| f + anchor),
                _ => None,
            };
            ListWindow { anchor: Some(key), row, before, after, scope }
        };
        self.state.graph.set_local_at(LIST_WINDOW, &window, v);
    }

    /// A list asked for the window around a row it has no key for.
    fn list_jump(&mut self, id: WidgetId, row: usize, before: usize, after: usize) {
        let Some((window, slot, block)) = self.acts.list_of(id) else { return };
        let scope = match self.slots.get(&slot).and_then(|s| s.model.get(block)) {
            Some(Block::List(l)) => l.shape.scope.clone(),
            _ => String::new(),
        };
        self.state.graph.set_local_at(LIST_WINDOW, &window, ListWindow { anchor: None, row: Some(row), before, after, scope });
    }

    /// Runs an action on the UI thread, then applies what it asked of the shell.
    fn run(&mut self, rr: &mut RenderRoot, d: Do, input: Input) {
        if let Err(e) = d.run(&Act::new(&self.data, &self.state), &input) {
            self.status(rr, format!("error: {e}"));
        }
    }

    fn enter_search(&mut self, rr: &mut RenderRoot) {
        let q = self.state.graph.peek(QUERY).trim().to_string();
        match classify(&q) {
            Paste::Link => self.start_redeem(rr, q),
            Paste::Peer => {
                let r = q.parse::<osis::Address>().map_err(|e| e.to_string()).and_then(|a| self.data.db.add_peer(&a).map_err(|e| e.to_string()));
                match r {
                    Ok(()) => {
                        let _ = self.data.ensure_profile();
                        self.state.set_local(QUERY, String::new());
                        self.status(rr, format!("peer {q} added"));
                        self.update(rr, true);
                    }
                    Err(e) => self.status(rr, format!("not added: {e}")),
                }
            }
            Paste::Query => {
                let dark = self.look.dark;
                let cx = Cx::new(&self.data, &self.state, dark);
                let first = search(&cx, &q).ok().and_then(|f| f.scopes.first().or(f.named.first()).or(f.mentions.first().map(|(t, _)| t)).or(f.in_scopes.first()).copied());
                drop(cx);
                if let Some(t) = first {
                    self.run(rr, Do::new(Open(Some(t))), Input::Press);
                }
            }
        }
    }

    /// Redeems a link off the UI thread (it waits for the link's peer).
    fn start_redeem(&mut self, rr: &mut RenderRoot, link: String) {
        if self.redeeming {
            return;
        }
        self.redeeming = true;
        self.status(rr, "joining…".into());
        let (parts, tx, waker) = (self.data.parts(), self.tx.clone(), self.waker.clone());
        std::thread::spawn(move || {
            let r = Data::from_parts(parts).redeem(&link).map_err(|e| e.to_string());
            let _ = tx.send(Msg::Redeemed(r));
            waker.wake();
        });
    }

    fn redeemed(&mut self, rr: &mut RenderRoot, r: Result<Tid, String>) {
        self.redeeming = false;
        match r {
            Ok(t) => {
                let _ = self.data.ensure_profile();
                self.state.set_local(QUERY, String::new());
                self.diag = None;
                if let Err(e) = self.data.set_open(Some(t)) {
                    self.status(rr, format!("error: {e}"));
                }
            }
            Err(e) => {
                self.diag = Some(format!("join failed: {e}"));
                self.status(rr, format!("join failed: {e}"));
            }
        }
    }

    fn typed(&mut self, rr: &mut RenderRoot, id: WidgetId, a: TextAction) {
        if self.search_ids.contains(&id) {
            match a {
                TextAction::Changed(q) => self.state.set_local(QUERY, q),
                TextAction::Entered(_) => self.enter_search(rr),
            }
            return;
        }
        if let Some(key) = self.acts.editor(id) {
            match a {
                TextAction::Changed(text) => {
                    if let Err(e) = self.state.sessions.typed(&key, &text) {
                        self.status(rr, format!("error: {e}"));
                    }
                }
                TextAction::Entered(_) => {
                    if let Some(d) = self.acts.on_enter(id) {
                        self.run(rr, d, Input::Press);
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
                    self.save_form(rr, id);
                }
            }
        }
    }

    /// Saves a form input's text unless it is what was saved last.
    fn save_form(&mut self, rr: &mut RenderRoot, id: WidgetId) {
        let Some((d, text)) = self.acts.form_dirty(id) else { return };
        let r = d.run(&Act::new(&self.data, &self.state), &Input::Text(text.clone()));
        match r {
            Ok(()) => {
                // only once written: a rejected text is reported again on the next Enter or blur
                self.acts.set_form_saved(id, text);
            }
            Err(e) => self.status(rr, format!("error: {e}")),
        }
    }

    /// A merge into an editor's session: show it, the selection mapped through the edits.
    fn show_merge(&mut self, rr: &mut RenderRoot, key: &Key) {
        let root = &mut *rr;
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
}

/// Gives Root `insets` (physical px) in logical px at `scale`.
fn set_root_insets(rr: &mut RenderRoot, scale: f64, insets: [f64; 4]) {
    let (s, i) = (scale.max(0.1), insets);
    let i = crate::masonry::kurbo::Insets::new(i[0] / s, i[1] / s, i[2] / s, i[3] / s);
    rr.edit_widget_with_tag(ROOT, |mut r| Root::set_insets(&mut r, i));
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

/// What a platform shell calls: it owns the window and its `RenderRoot`, and calls these on the UI
/// thread (desktop: `window::App`; Android: osis-android), through `Started` (start.rs).
impl Ui {
    /// The window exists: register the fonts, run what is due, update once. `platform` is the
    /// shell's, `scale` physical pixels per logical pixel, `dark` the system's dark mode.
    pub fn start(&mut self, rr: &mut RenderRoot, platform: Box<dyn Platform>, scale: f64, dark: bool) {
        crate::fonts::register(rr);
        self.attach(platform, scale, dark);
    }

    /// `start` for a window whose fonts are registered.
    fn attach(&mut self, platform: Box<dyn Platform>, scale: f64, dark: bool) {
        let (m, w) = (self.tx.clone(), self.waker.clone());
        let alarm = Box::new(move |seq, after| {
            let (m, w) = (m.clone(), w.clone());
            std::thread::spawn(move || {
                std::thread::sleep(after);
                if m.send(Msg::LongPress(seq)).is_ok() {
                    w.wake();
                }
            });
        });
        let mut a = Attached::new(platform, alarm);
        a.input.set_look(self.look.clone());
        self.attached = Some(a);
        self.scale = scale;
        self.system_dark = dark;
        self.data.db.settle();
        while self.rx.try_recv().is_ok() {}
        self.waker.wake();
    }

    /// The window's size or scale changed: the rail coming or going rebuilds the screen.
    pub fn resized(&mut self, rr: &mut RenderRoot, scale: f64) {
        if scale != self.scale {
            self.scale = scale;
            self.root_insets(rr);
        }
        self.rail_check(rr);
    }

    fn rail_check(&mut self, rr: &mut RenderRoot) {
        let flips = self.built.as_ref().is_some_and(|b| !b.home && self.rail_fits(rr, &self.look) != b.rail);
        if flips {
            self.update(rr, false);
        }
    }

    /// The system's dark mode changed: Auto follows it.
    pub fn theme_changed(&mut self, rr: &mut RenderRoot, dark: bool) {
        self.system_dark = dark;
        if self.mode == Mode::Auto {
            self.update(rr, false);
        }
    }

    /// The system's Back: an open selection menu closes; else an open thing goes home (as its bar's
    /// back button does). False when there is nowhere to go back to, so the system handles it.
    pub fn back(&mut self, rr: &mut RenderRoot) -> bool {
        if let Some(a) = self.attached.as_mut()
            && a.input.back(rr, &mut *a.platform)
        {
            return true;
        }
        if !matches!(self.data.opened(), Ok(Some(_))) {
            return false;
        }
        if let Err(e) = self.data.set_open(None) {
            self.status(rr, format!("error: {e}"));
        }
        self.update(rr, false);
        true
    }

    /// What covers the window's edges (physical pixels: left, top, right, bottom): the screen is
    /// laid out clear of it, and the width that leaves is what the layout follows.
    pub fn set_insets(&mut self, rr: &mut RenderRoot, insets: [f64; 4]) {
        self.insets = insets;
        self.root_insets(rr);
        self.rail_check(rr);
    }

    /// Gives Root the insets in logical px at the current scale.
    fn root_insets(&mut self, rr: &mut RenderRoot) {
        set_root_insets(rr, self.scale, self.insets);
    }

    /// A pointer event, on its way to `rr` through the gestures (`input`).
    pub fn pointer(&mut self, rr: &mut RenderRoot, e: PointerEvent) {
        match self.attached.as_mut() {
            Some(a) => a.pointer(rr, e),
            None => {
                rr.handle_pointer_event(e);
            }
        }
    }

    /// A text event (a key, an input method's edit, a command such as a keyboard's own Copy
    /// button, the window's focus), on its way to `rr`: every shell's go through here.
    pub fn text_event(&mut self, rr: &mut RenderRoot, e: TextEvent) -> Handled {
        match self.attached.as_mut() {
            Some(a) => a.text_event(rr, e),
            None => rr.handle_text_event(e),
        }
    }

    /// The platform's selection menu had item `c` picked.
    pub fn menu_pick(&mut self, rr: &mut RenderRoot, c: TextCommand) {
        if let Some(a) = self.attached.as_mut() {
            a.pick(rr, c);
        }
    }

    /// The platform closed its selection menu by itself.
    pub fn menu_gone(&mut self) {
        if let Some(a) = self.attached.as_mut() {
            a.input.menu_gone();
        }
    }

    /// An input-method session started or ended (a text field gained or lost the focus).
    pub fn text_focus(&mut self, rr: &mut RenderRoot) {
        if let Some(a) = self.attached.as_mut() {
            a.input.text_focus(rr, &mut *a.platform);
            a.follow(rr);
        }
    }

    /// The focused widget asked to paste (`RenderRootSignal::ClipboardRead`): the clipboard's
    /// text replaces its selection (`input::paste`).
    pub fn paste(&mut self, rr: &mut RenderRoot) {
        if let Some(a) = self.attached.as_mut() {
            crate::input::paste(rr, &mut *a.platform);
            a.follow(rr);
        }
    }

    /// A widget cut or copied `text` (`RenderRootSignal::ClipboardStore`).
    pub fn copy(&mut self, text: String) {
        if let Some(a) = self.attached.as_mut() {
            a.platform.set_clipboard(text);
        }
    }

    /// The colour under everything, for the shell to clear with.
    pub fn base_color(&self) -> Color {
        self.look.bg
    }

    /// A `Waker` woke the UI thread: run osis callbacks and what they posted, then update.
    pub fn wake(&mut self, rr: &mut RenderRoot) {
        self.data.db.settle();
        for m in self.rx.try_iter().collect::<Vec<_>>() {
            match m {
                Msg::Diagnostic(d) => {
                    self.diag = Some(d);
                    self.show_status(rr);
                }
                Msg::Merged(k) => self.show_merge(rr, &k),
                Msg::Redeemed(r) => self.redeemed(rr, r),
                Msg::Tick => {
                    if let Ok(now) = self.data.db.now() {
                        self.state.set_local(TICK, now.0 / 60_000);
                    }
                }
                Msg::LongPress(seq) => {
                    if let Some(a) = self.attached.as_mut() {
                        a.input.long_press(rr, &mut *a.platform, seq);
                    }
                }
            }
        }
        self.update(rr, false);
        if let Some(a) = self.attached.as_mut() {
            a.follow(rr);
        }
    }

    /// A widget submitted an action.
    pub fn action(&mut self, rr: &mut RenderRoot, id: WidgetId, action: ErasedAction) {
        if let Some(Frame(interval)) = action.downcast_ref::<Frame>().copied() {
            if let Some(a) = self.attached.as_mut() {
                a.frame(rr, interval);
            }
        } else if action.is::<Press>() {
            if let Some(d) = self.acts.pressed(id) {
                self.run(rr, d, Input::Press);
            }
        } else if action.is::<Blur>() {
            if let Some(input) = self.acts.blur_input(id) {
                self.save_form(rr, input);
            }
        } else if let Some(a) = action.downcast_ref::<ListAction>().copied() {
            match a {
                ListAction::Moved { anchor, before, after, stuck } => {
                    self.list_moved(id, anchor, before, after, stuck);
                    self.update(rr, false);
                }
                ListAction::Jump { row, before, after } => {
                    self.list_jump(id, row, before, after);
                    self.update(rr, false);
                }
                ListAction::Reorder { from, to } => {
                    let first = self.acts.list_of(id).and_then(|(_, s, b)| match self.slots.get(&s)?.model.get(b)? {
                        Block::List(l) => l.first(),
                        _ => None,
                    });
                    if let (Some(d), Some(f)) = (self.acts.reorder(id), first) {
                        self.run(rr, d, Input::Reorder { from: from + f, to: to + f });
                    }
                }
            }
        } else if let Some(p) = action.downcast_ref::<ChipPress>().copied() {
            let d = match p {
                ChipPress::Open => self.acts.pressed(id),
                ChipPress::Remove => self.acts.removed(id),
            };
            if let Some(d) = d {
                self.run(rr, d, Input::Press);
            }
        } else if let Some(MenuPick(c)) = action.downcast_ref::<MenuPick>().copied() {
            if let Some(a) = self.attached.as_mut() {
                a.pick(rr, c);
            }
        } else if let Ok(a) = action.downcast::<TextAction>() {
            self.typed(rr, id, *a);
            if let Some(a) = self.attached.as_mut() {
                a.follow(rr);
            }
        }
    }
}

/// The initial widget tree: the root over an empty screen (the first update builds it).
pub fn tree(look: Arc<Look>) -> NewWidget<dyn Widget> {
    NewWidget::new_with_tag(Root::new(NewWidget::new(SizedBox::empty()), look), ROOT).erased()
}
