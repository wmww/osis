//! The window (Masonry over kit). Home: search, favorites, new. An open thing: its pane, with a
//! rail (home, search, favorites, new) beside it when the window is wide, else a back button.
//!
//! Everything shown comes from osis through `Data`: watches post into the kit mailbox, the UI
//! thread re-reads and rebuilds what changed. A screen is built whole when what is open, the
//! width class or the look changes; otherwise only its lists (slots) are rebuilt, and only when
//! their content differs, so the editors keep their caret. Widgets keep only the search text and
//! the text being typed (sent on into osis text sessions).

use crate::data::{Data, Kind, Tile};
use crate::edit::splice;
use crate::schema::{Mode as ModeChoice, View};
use osis::core::{BODY, NAME};
use osis::{Path, Subscription, TextSession, Tid};
use osis_kit::icons::Icon;
use osis_kit::marshal::{Inbox, Mailbox};
use osis_kit::masonry::core::{ErasedAction, NewWidget, Properties, Widget, WidgetId, WidgetTag};
use osis_kit::masonry::kurbo::Size;
use osis_kit::masonry::properties::Padding;
use osis_kit::masonry::properties::types::{CrossAxisAlignment, Length};
use osis_kit::masonry::widgets::{Flex, Label, Portal, SizedBox, TextAction, TextArea};
use osis_kit::masonry_winit::app::{AppDriver, DriverCtx, WindowId};
use osis_kit::theme::{Look, Mode, Theme, parse};
use osis_kit::widgets::style::{self, Text};
use osis_kit::widgets::{IconButton, Limit, Panel, PanelKind, Press, Resized, Root, TileGrid, TileIcon, TileStyle};
use osis_kit::window::Wakeup;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

pub const ROOT: WidgetTag<Root> = WidgetTag::new("root");
// Masonry 0.4 never forgets a tag of a removed widget, so rebuilt widgets are found by id.
const HOME_BODY: &str = "home-body";
const RAIL_LIST: &str = "rail-list";
const PANE_EXTRA: &str = "pane-extra";

/// Below this width (logical px) an open thing fills the window and home is a back button away.
const NARROW: f64 = 760.0;

/// What a watch says changed; the UI re-reads osis for all of them.
#[derive(Debug)]
pub enum Msg {
    /// Something shown may have changed.
    Changed,
    /// A text session merged a remote edit into the open thing's name or body.
    Remote(Tid),
    /// An osis diagnostic (a thing that will not sync, a callback that panicked, ...).
    Diagnostic(String),
}

/// What a press on a widget does.
#[derive(Clone, Debug)]
enum Act {
    Theme(&'static str),
    Mode(ModeChoice),
    Open(Tid),
    Home,
    New,
    Favorite(Tid),
    Delete(Tid),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Screen {
    Home,
    Thing(Tid),
}

/// A titled group of tiles in a slot.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Section {
    label: String,
    /// Small rows instead of cards (a thing's tags).
    rows: bool,
    tiles: Vec<Tile>,
    /// Ends with the "new note" tile.
    new: bool,
}

/// What a slot shows: lines of text, then sections.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Content {
    lines: Vec<String>,
    sections: Vec<Section>,
    /// Shown when there are no sections.
    empty: Option<String>,
}

/// The open thing's text sessions: typing goes there, one commit per pause.
struct Editor {
    tid: Tid,
    name: TextSession,
    body: Option<TextSession>,
    name_id: WidgetId,
    body_id: Option<WidgetId>,
    /// The name and body texts as the widgets show them (a remote merge may be newer).
    shown: (String, String),
}

pub struct Ui {
    data: Data,
    window: WindowId,
    mb: Mailbox<Msg>,
    inbox: Inbox<Msg>,
    theme: Theme,
    mode: Mode,
    look: Arc<Look>,
    narrow: bool,
    /// What is built: the screen, its width class.
    built: Option<(Screen, bool)>,
    /// Each slot's widget and what it shows now.
    slots: HashMap<&'static str, (WidgetId, Option<Content>)>,
    status_id: Option<WidgetId>,
    query: String,
    search_ids: Vec<WidgetId>,
    acts: HashMap<WidgetId, Act>,
    star: Option<WidgetId>,
    editor: Option<Editor>,
    subs: BTreeMap<Tid, Subscription>,
    _diag_sub: Subscription,
    diag: Option<String>,
}

impl Ui {
    pub fn new(data: Data, window: WindowId, mb: Mailbox<Msg>, inbox: Inbox<Msg>) -> Ui {
        let (theme, mode) = data.look().unwrap_or((None, ModeChoice::Auto));
        let theme = Theme::named(theme.as_deref().unwrap_or("frost"));
        let mode = kit_mode(&mode);
        let m = mb.clone();
        let diag_sub = data.db.on_diagnostic(move |_, d| {
            m.post(Msg::Diagnostic(format!("{:?}: {}", d.kind, d.detail)));
        });
        let look = Arc::new(Look::new(&theme, mode == Mode::Dark, None));
        Ui {
            data,
            window,
            mb,
            inbox,
            theme,
            mode,
            look,
            narrow: false,
            built: None,
            slots: HashMap::new(),
            status_id: None,
            query: String::new(),
            search_ids: Vec::new(),
            acts: HashMap::new(),
            star: None,
            editor: None,
            subs: BTreeMap::new(),
            _diag_sub: diag_sub,
            diag: None,
        }
    }

    /// The first look, for the initial root widget.
    pub fn look(&self) -> Arc<Look> {
        self.look.clone()
    }

    fn dark(&self, ctx: &mut DriverCtx<'_, '_>) -> bool {
        match self.mode {
            Mode::Light => false,
            Mode::Dark => true,
            Mode::Auto => ctx.window(self.window).handle().theme() == Some(osis_kit::masonry_winit::winit::window::Theme::Dark),
        }
    }

    /// Re-reads osis and brings the window to it; `force` rebuilds the screen.
    fn refresh(&mut self, ctx: &mut DriverCtx<'_, '_>, force: bool) {
        if let Err(e) = self.refresh_inner(ctx, force) {
            // a thing that cannot be shown (a synced aspect of another shape under its editor,
            // say) must not leave a half-built screen whose presses go nowhere: go home
            if matches!(self.data.opened(), Ok(Some(_))) && self.data.set_open(None).is_ok() {
                self.editor = None;
                let _ = self.refresh_inner(ctx, true);
            }
            self.status(ctx, format!("error: {e}"));
        }
    }

    fn refresh_inner(&mut self, ctx: &mut DriverCtx<'_, '_>, force: bool) -> osis::Result<()> {
        let open = self.data.opened()?;
        let screen = match open {
            Some(t) => Screen::Thing(t),
            None => Screen::Home,
        };
        let main = match screen {
            Screen::Thing(t) => self.data.main_color(t)?.and_then(|c| parse(&c)),
            Screen::Home => None,
        };
        let (theme, mode) = self.data.look()?;
        self.theme = Theme::named(theme.as_deref().unwrap_or("frost"));
        self.mode = kit_mode(&mode);
        let dark = self.dark(ctx);
        let look = Look::new(&self.theme, dark, main);
        let rebuild = force || self.built != Some((screen, self.narrow)) || look != *self.look;
        if rebuild {
            self.look = Arc::new(look);
            self.build(ctx, screen)?;
        }
        self.fill_slots(ctx, screen)?;
        self.watch()?;
        if rebuild || self.diag.is_some() {
            let s = format!("device {}{}", short(self.data.db.node()), self.diag.as_deref().map(|d| format!(" · {d}")).unwrap_or_default());
            self.status(ctx, s);
        }
        Ok(())
    }

    /// One watch per thing shown anywhere (and home and the app groups, whose items are lists).
    fn watch(&mut self) -> osis::Result<()> {
        let mut want: BTreeSet<Tid> = self.data.things()?;
        want.insert(self.data.db.home());
        want.extend(self.data.groups()?);
        self.subs.retain(|t, _| want.contains(t));
        for t in want {
            if !self.subs.contains_key(&t) {
                let mb = self.mb.clone();
                let s = self.data.db.watch_thing(t, move |_, _| {
                    mb.post(Msg::Changed);
                });
                self.subs.insert(t, s);
            }
        }
        Ok(())
    }

    fn status(&mut self, ctx: &mut DriverCtx<'_, '_>, s: String) {
        let root = ctx.render_root(self.window);
        if let Some(id) = self.status_id.filter(|id| root.has_widget(*id)) {
            root.edit_widget(id, |mut l| Label::set_text(&mut l.downcast(), s));
        }
    }

    // ---- building screens

    fn build(&mut self, ctx: &mut DriverCtx<'_, '_>, screen: Screen) -> osis::Result<()> {
        self.acts.clear();
        self.slots.clear();
        self.search_ids.clear();
        self.star = None;
        self.status_id = None;
        if self.editor.as_ref().map(|e| Screen::Thing(e.tid)) != Some(screen) {
            // dropping the sessions commits pending typing
            self.editor = None;
        }
        let w = match screen {
            Screen::Home => self.home(),
            Screen::Thing(t) => self.thing(t)?,
        };
        // the arrangement: from the thing, varied by its kind
        let seed = match screen {
            Screen::Home => 0,
            Screen::Thing(t) => {
                let k = self.data.kind(t)?;
                seed_of(t) ^ seed_of_str(&format!("{k:?}")).rotate_left(17)
            }
        };
        let look = self.look.clone();
        *ctx.window(self.window).base_color() = self.look.bg;
        ctx.render_root(self.window).edit_widget_with_tag(ROOT, |mut r| {
            Root::set_look(&mut r, look, seed);
            Root::set_child(&mut r, w);
        });
        self.built = Some((screen, self.narrow));
        Ok(())
    }

    /// An empty slot named `key`, filled by `slot`.
    fn slot_widget(&mut self, key: &'static str) -> NewWidget<SizedBox> {
        let w = NewWidget::new(SizedBox::empty());
        self.slots.insert(key, (w.id(), None));
        w
    }

    fn status_widget(&mut self) -> NewWidget<Label> {
        let l = style::label(&self.look, "", Text::Small);
        self.status_id = Some(l.id());
        l
    }

    fn act(&mut self, w: NewWidget<impl Widget + ?Sized>, a: Act) -> NewWidget<dyn Widget> {
        self.acts.insert(w.id(), a);
        w.erased()
    }

    fn search_field(&mut self, big: bool) -> NewWidget<dyn Widget> {
        let look = self.look.clone();
        let (input, id) = style::input(&look, &self.query, if big { "Search notes, people, tags, views…" } else { "Search" }, if big { Text::Body } else { Text::Muted }, false);
        self.search_ids.push(id);
        let pad = if big { (14.0, 18.0) } else { (9.0, 12.0) };
        NewWidget::new(Panel::new(input, look, PanelKind::Field, pad)).erased()
    }

    fn home(&mut self) -> NewWidget<dyn Widget> {
        let look = self.look.clone();
        let gap = Length::px(look.sp(18.0));
        let col = Flex::column()
            .cross_axis_alignment(CrossAxisAlignment::Fill)
            .with_gap(gap)
            .with_child(style::label(&look, "osis", Text::Brand))
            .with_child(self.search_field(true))
            .with_child(self.slot_widget(HOME_BODY))
            .with_child(self.look_picker())
            .with_child(self.status_widget());
        let pad = Properties::new().with(Padding::from_vh(look.sp(48.0), look.sp(16.0)));
        let col = NewWidget::new_with_props(col, pad);
        let limited = NewWidget::new(Limit::new(col, 940.0));
        NewWidget::new(Portal::new(limited).constrain_horizontal(true)).erased()
    }

    /// Theme and mode choices (home's foot).
    fn look_picker(&mut self) -> NewWidget<dyn Widget> {
        let look = self.look.clone();
        let mut col = Flex::column().cross_axis_alignment(CrossAxisAlignment::Fill).with_gap(Length::px(look.sp(6.0)));
        col = col.with_child(style::label(&look, "Look", Text::Section));
        let mut themes = TileGrid::new(look.clone(), 120.0).gap(4.0);
        for th in Theme::defaults() {
            let tint = th.surface.of(look.dark);
            let cur = th.id == self.theme.id;
            let w = NewWidget::new(osis_kit::widgets::Tile::new(TileStyle::Row, TileIcon::Initials(th.name.chars().take(1).collect()), th.name, "", Some(osis_kit::theme::mix(tint, th.background.of(!look.dark), 0.7)), look.clone()).current(cur));
            themes = themes.with_child(self.act(w, Act::Theme(th.id)));
        }
        col = col.with_child(NewWidget::new(themes));
        let mut modes = TileGrid::new(look.clone(), 120.0).gap(4.0).max_cols(3);
        for (m, name, icon) in [(ModeChoice::Auto, "Auto", Icon::Recent), (ModeChoice::Light, "Light", Icon::Eye), (ModeChoice::Dark, "Dark", Icon::Star)] {
            let cur = kit_mode(&m) == self.mode;
            let w = NewWidget::new(osis_kit::widgets::Tile::new(TileStyle::Row, TileIcon::Icon(icon), name, "", None, look.clone()).current(cur));
            modes = modes.with_child(self.act(w, Act::Mode(m)));
        }
        col = col.with_child(NewWidget::new(modes));
        NewWidget::new_with_props(col, Properties::new().with(Padding::from_vh(look.sp(24.0), 0.0))).erased()
    }

    fn thing(&mut self, t: Tid) -> osis::Result<NewWidget<dyn Widget>> {
        let look = self.look.clone();
        let sp = |x: f64| look.sp(x);
        let tile = self.data.tile(t)?;
        // the bar: back (narrow), what it is, favorite, delete
        let mut bar = Flex::row().with_gap(Length::px(sp(8.0)));
        if self.narrow {
            let b = NewWidget::new(IconButton::new(Icon::Back, "Home", look.clone()));
            bar = bar.with_child(self.act(b, Act::Home));
        }
        bar = bar.with_child(style::label(&look, tile.kind.label(), Text::Muted)).with_flex_spacer(1.0);
        let fav = self.data.is_favorite(t)?;
        let star = NewWidget::new(IconButton::new(Icon::Star, "Favorite", look.clone()).on(fav));
        self.star = Some(star.id());
        bar = bar.with_child(self.act(star, Act::Favorite(t)));
        if !matches!(tile.kind, Kind::View(_)) {
            let del = NewWidget::new(IconButton::new(Icon::Trash, "Delete", look.clone()));
            bar = bar.with_child(self.act(del, Act::Delete(t)));
        }
        // the body: title, the kind's own content, the text
        let has_body = matches!(tile.kind, Kind::Note | Kind::Event | Kind::Contact);
        self.open_editor(t, has_body)?;
        let extra = self.slot_widget(PANE_EXTRA);
        let Some(ed) = self.editor.as_mut() else { return Err(osis::Error::Invalid("no editor".into())) };
        let (title, name_id) = style::input(&look, &ed.shown.0, "Untitled", Text::Title, false);
        ed.name_id = name_id;
        let mut body = Flex::column().cross_axis_alignment(CrossAxisAlignment::Fill).with_gap(Length::px(sp(16.0)));
        if let Some(m) = style::title_mark(&look) {
            body = body.with_child(m);
        }
        body = body.with_child(title);
        body = body.with_child(extra);
        if has_body {
            let placeholder = if tile.kind == Kind::Contact { "Notes about them…" } else { "Write something…" };
            let (text, body_id) = style::input(&look, &ed.shown.1, placeholder, Text::Body, true);
            ed.body_id = Some(body_id);
            body = body.with_child(text);
        }
        let body = NewWidget::new_with_props(body, Properties::new().with(Padding::all(sp(28.0))));
        let scroll = NewWidget::new(Portal::new(body).constrain_horizontal(true).content_must_fill(true));
        let pane_body = NewWidget::new(Panel::new(scroll, look.clone(), PanelKind::Panel, (0.0, 0.0)).fill_height(true));
        let pane = Flex::column()
            .cross_axis_alignment(CrossAxisAlignment::Fill)
            .with_gap(Length::px(sp(10.0)))
            .with_child(NewWidget::new_with_props(bar, Properties::new().with(Padding::from_vh(0.0, sp(4.0)))))
            .with_flex_child(pane_body, 1.0);
        if self.narrow {
            return Ok(NewWidget::new_with_props(pane, Properties::new().with(Padding::all(sp(10.0)))).erased());
        }
        // the rail
        let home = NewWidget::new(osis_kit::widgets::Tile::new(TileStyle::Row, TileIcon::Icon(Icon::Home), "osis", "Home", None, look.clone()));
        let new = NewWidget::new(osis_kit::widgets::Tile::new(TileStyle::Row, TileIcon::Icon(Icon::Plus), "New note", "", None, look.clone()));
        let rail = Flex::column()
            .cross_axis_alignment(CrossAxisAlignment::Fill)
            .with_gap(Length::px(sp(6.0)))
            .with_child(self.act(home, Act::Home))
            .with_child(self.search_field(false))
            .with_child(self.slot_widget(RAIL_LIST))
            .with_child(self.act(new, Act::New))
            .with_child(self.status_widget());
        let rail = NewWidget::new(Portal::new(NewWidget::new(rail)).constrain_horizontal(true));
        let rail = NewWidget::new(Panel::new(rail, look.clone(), PanelKind::Panel, (14.0, 10.0)).fill_height(true));
        let row = Flex::row()
            .cross_axis_alignment(CrossAxisAlignment::Fill)
            .with_gap(Length::px(sp(16.0)))
            .with_child(NewWidget::new(SizedBox::new(rail).width(Length::px(264.0))))
            .with_flex_child(NewWidget::new(pane), 1.0);
        Ok(NewWidget::new_with_props(row, Properties::new().with(Padding::all(sp(16.0)))).erased())
    }

    /// Text sessions on `t`'s name (and body); kept if `t` is already open.
    fn open_editor(&mut self, t: Tid, body: bool) -> osis::Result<()> {
        if self.editor.as_ref().is_some_and(|e| e.tid == t && e.body.is_some() == body) {
            if let Some(e) = self.editor.as_mut() {
                e.shown = (e.name.text(), e.body.as_ref().map(|b| b.text()).unwrap_or_default());
            }
            return Ok(());
        }
        self.editor = None;
        let db = &self.data.db;
        let name = db.edit_text(t, NAME, Path::root())?;
        let mb = self.mb.clone();
        name.on_remote(move |_| {
            mb.post(Msg::Remote(t));
        });
        let body = if body {
            let b = db.edit_text(t, BODY, Path::root())?;
            let mb = self.mb.clone();
            b.on_remote(move |_| {
                mb.post(Msg::Remote(t));
            });
            Some(b)
        } else {
            None
        };
        let shown = (name.text(), body.as_ref().map(|b| b.text()).unwrap_or_default());
        self.editor = Some(Editor { tid: t, name, body, name_id: WidgetId::next(), body_id: None, shown });
        Ok(())
    }

    // ---- slots

    fn fill_slots(&mut self, ctx: &mut DriverCtx<'_, '_>, screen: Screen) -> osis::Result<()> {
        match screen {
            Screen::Home => {
                let c = if self.query.trim().is_empty() { self.favorites_content(TileStyle::Card)? } else { self.search_content()? };
                self.slot(ctx, HOME_BODY, c, TileStyle::Card, None);
            }
            Screen::Thing(t) => {
                if !self.narrow {
                    let c = if self.query.trim().is_empty() { self.favorites_content(TileStyle::Row)? } else { self.search_content()? };
                    self.slot(ctx, RAIL_LIST, c, TileStyle::Row, Some(t));
                }
                let c = self.extra_content(t)?;
                self.slot(ctx, PANE_EXTRA, c, TileStyle::Card, None);
                let fav = self.data.is_favorite(t)?;
                if let Some(id) = self.star {
                    let root = ctx.render_root(self.window);
                    if root.has_widget(id) {
                        root.edit_widget(id, |mut w| IconButton::set_on(&mut w.downcast(), fav));
                    }
                }
            }
        }
        Ok(())
    }

    fn favorites_content(&self, style: TileStyle) -> osis::Result<Content> {
        let mut tiles = Vec::new();
        for t in self.data.favorites()? {
            tiles.push(self.data.tile(t)?);
        }
        Ok(Content { lines: vec![], sections: vec![Section { label: "Favorites".into(), rows: style == TileStyle::Row, tiles, new: style == TileStyle::Card }], empty: None })
    }

    fn search_content(&self) -> osis::Result<Content> {
        let f = self.data.search(&self.query)?;
        let tiles = |v: &[Tid]| -> osis::Result<Vec<Tile>> { v.iter().map(|t| self.data.tile(*t)).collect() };
        let mut sections = Vec::new();
        for (label, v) in [("Scopes", &f.scopes), ("Things", &f.named)] {
            if !v.is_empty() {
                sections.push(Section { label: label.into(), rows: false, tiles: tiles(v)?, new: false });
            }
        }
        if !f.mentions.is_empty() {
            let mut ts = Vec::new();
            for (t, snip) in &f.mentions {
                let mut tile = self.data.tile(*t)?;
                tile.sub = snip.clone();
                ts.push(tile);
            }
            sections.push(Section { label: "Mentions".into(), rows: false, tiles: ts, new: false });
        }
        if !f.in_scopes.is_empty() {
            sections.push(Section { label: "In those scopes".into(), rows: false, tiles: tiles(&f.in_scopes)?, new: false });
        }
        Ok(Content { lines: vec![], sections, empty: Some(format!("Nothing matches “{}”.", self.query.trim())) })
    }

    /// What a thing's pane shows between its title and its text.
    fn extra_content(&self, t: Tid) -> osis::Result<Content> {
        let d = &self.data;
        let tiles = |v: &[Tid]| -> osis::Result<Vec<Tile>> { v.iter().map(|t| d.tile(*t)).collect() };
        let mut c = Content::default();
        match d.kind(t)? {
            Kind::Event => {
                if let Some(s) = d.get(t, crate::event::START)? {
                    c.lines.push(crate::data::fmt_when(&s, d.get(t, crate::event::END)?.as_ref()));
                }
                c.lines.extend(d.get(t, crate::event::LOCATION)?);
            }
            Kind::Contact => {
                if let Some(o) = d.get(t, crate::contact::ORG)? {
                    c.lines.extend([o.title, o.name].into_iter().filter(|s| !s.is_empty()));
                }
                c.lines.extend(d.get(t, crate::contact::EMAILS)?.unwrap_or_default().into_keys());
                c.lines.extend(d.get(t, crate::contact::PHONES)?.unwrap_or_default().into_keys());
            }
            Kind::Tag => {
                let (subs, items) = d.tag_contents(t)?;
                if !subs.is_empty() {
                    c.sections.push(Section { label: "Tags inside".into(), rows: false, tiles: tiles(&subs)?, new: false });
                }
                c.sections.push(Section { label: "Items".into(), rows: false, tiles: tiles(&items)?, new: false });
                return Ok(c);
            }
            Kind::View(v) => {
                let label = match v {
                    View::Calendar => "Events",
                    View::People => "People",
                    View::Tags => "Tags",
                    View::Recent => "Last touched first",
                };
                c.sections.push(Section { label: label.into(), rows: false, tiles: tiles(&d.view_items(&v)?)?, new: false });
                return Ok(c);
            }
            Kind::Note => {}
        }
        let tags = d.tags_of(t)?;
        if !tags.is_empty() {
            c.sections.push(Section { label: "Tags".into(), rows: true, tiles: tiles(&tags)?, new: false });
        }
        Ok(c)
    }

    /// Shows `c` in the slot `tag` unless it already does.
    fn slot(&mut self, ctx: &mut DriverCtx<'_, '_>, key: &'static str, c: Content, style: TileStyle, current: Option<Tid>) {
        let Some((id, shown)) = self.slots.get(key) else { return };
        if shown.as_ref() == Some(&c) {
            return;
        }
        let id = *id;
        let w = self.content(&c, style, current, key == PANE_EXTRA);
        let root = ctx.render_root(self.window);
        if root.has_widget(id) {
            root.edit_widget(id, |mut b| SizedBox::set_child(&mut b.downcast(), w));
        }
        self.slots.insert(key, (id, Some(c)));
    }

    fn content(&mut self, c: &Content, style: TileStyle, current: Option<Tid>, small: bool) -> NewWidget<dyn Widget> {
        let look = self.look.clone();
        let mut col = Flex::column().cross_axis_alignment(CrossAxisAlignment::Fill).with_gap(Length::px(look.sp(if style == TileStyle::Row { 4.0 } else { 10.0 })));
        for l in &c.lines {
            col = col.with_child(style::label(&look, l, Text::Muted));
        }
        if c.sections.iter().all(|s| s.tiles.is_empty() && !s.new)
            && let Some(e) = &c.empty
        {
            col = col.with_child(style::label(&look, e, Text::Muted));
        }
        for s in &c.sections {
            if s.tiles.is_empty() && !s.new {
                continue;
            }
            col = col.with_child(style::label(&look, &s.label, Text::Section));
            let (min, cols, gap) = match style {
                TileStyle::Row => (100.0, 1, 3.0),
                _ if s.rows => (150.0, 0, 6.0),
                _ if small => (150.0, 0, 12.0),
                _ => (158.0, 0, 12.0),
            };
            let style = if s.rows { TileStyle::Row } else { style };
            let mut grid = TileGrid::new(look.clone(), min).max_cols(cols).gap(gap);
            for t in &s.tiles {
                let w = NewWidget::new(osis_kit::widgets::Tile::new(style, icon_of(t), &t.name, &t.sub, t.color.as_deref().and_then(parse), look.clone()).current(current == Some(t.tid)));
                self.acts.insert(w.id(), Act::Open(t.tid));
                grid = grid.with_child(w);
            }
            if s.new {
                let w = NewWidget::new(osis_kit::widgets::Tile::new(TileStyle::New, TileIcon::Icon(Icon::Plus), "New note", "Start writing", None, look.clone()));
                self.acts.insert(w.id(), Act::New);
                grid = grid.with_child(w);
            }
            col = col.with_child(NewWidget::new(grid));
        }
        NewWidget::new(col).erased()
    }

    // ---- input

    fn press(&mut self, ctx: &mut DriverCtx<'_, '_>, a: Act) {
        let r = match a {
            Act::Open(t) => {
                self.query.clear();
                self.data.set_open(Some(t))
            }
            Act::Home => self.data.set_open(None),
            Act::New => {
                self.query.clear();
                self.data.create_note().map(|_| ())
            }
            Act::Favorite(t) => self.data.toggle_favorite(t),
            Act::Theme(id) => self.data.set_theme(id),
            Act::Mode(m) => self.data.set_mode(m),
            Act::Delete(t) => {
                // close the editor first: its sessions commit pending typing on drop, which
                // after the delete would recreate the thing
                self.editor = None;
                self.data.delete(t)
            }
        };
        if let Err(e) = r {
            self.status(ctx, format!("error: {e}"));
        }
        self.refresh(ctx, false);
    }

    fn typed(&mut self, ctx: &mut DriverCtx<'_, '_>, id: WidgetId, a: TextAction) {
        if self.search_ids.contains(&id) {
            match a {
                TextAction::Changed(q) => {
                    self.query = q;
                    // the other search field (if any) shows it too on the next build
                    self.refresh(ctx, false);
                }
                TextAction::Entered(_) => {
                    let first = self.data.search(&self.query).ok().and_then(|f| f.scopes.first().or(f.named.first()).or(f.mentions.first().map(|(t, _)| t)).or(f.in_scopes.first()).copied());
                    if let Some(t) = first {
                        self.press(ctx, Act::Open(t));
                    }
                }
            }
            return;
        }
        let TextAction::Changed(text) = a else { return };
        let r = match self.editor.as_mut() {
            Some(e) if id == e.name_id => splice(&e.name, &std::mem::replace(&mut e.shown.0, text.clone()), &text),
            Some(e) if Some(id) == e.body_id => match &e.body {
                Some(b) => splice(b, &std::mem::replace(&mut e.shown.1, text.clone()), &text),
                None => Ok(()),
            },
            _ => Ok(()),
        };
        if let Err(e) = r {
            self.status(ctx, format!("error: {e}"));
        }
    }

    /// A remote merge into the open thing's sessions: show it.
    fn remote(&mut self, ctx: &mut DriverCtx<'_, '_>, t: Tid) {
        let Some(e) = self.editor.as_mut().filter(|e| e.tid == t) else { return };
        let (n, b) = (e.name.text(), e.body.as_ref().map(|b| b.text()).unwrap_or_default());
        e.shown = (n.clone(), b.clone());
        let ids = [(Some(e.name_id), n), (e.body_id, b)];
        let root = ctx.render_root(self.window);
        for (id, text) in ids {
            if let Some(id) = id
                && root.has_widget(id)
            {
                root.edit_widget(id, |mut w| {
                    let mut a = w.downcast::<TextArea<true>>();
                    if a.widget.text() != text.as_str() {
                        TextArea::reset_text(&mut a, &text);
                    }
                });
            }
        }
    }
}

fn icon_of(t: &Tile) -> TileIcon {
    TileIcon::Icon(match &t.kind {
        Kind::View(View::Calendar) => Icon::Calendar,
        Kind::View(View::People) => Icon::People,
        Kind::View(View::Tags) => Icon::Tags,
        Kind::View(View::Recent) => Icon::Recent,
        Kind::Tag => Icon::Tag,
        Kind::Event => Icon::Event,
        Kind::Note => Icon::Note,
        Kind::Contact => return TileIcon::Initials(initials(&t.name)),
    })
}

fn initials(name: &str) -> String {
    let s: String = name.split_whitespace().filter_map(|w| w.chars().next()).take(2).collect();
    if s.is_empty() { "?".into() } else { s.to_uppercase() }
}

/// A seed for the background's arrangement, from the thing's tid.
fn seed_of(t: Tid) -> u64 {
    seed_of_str(&t.to_string())
}

fn seed_of_str(s: &str) -> u64 {
    s.bytes().fold(7u64, |a, b| a.wrapping_mul(31).wrapping_add(u64::from(b)))
}

fn kit_mode(m: &ModeChoice) -> Mode {
    match m {
        ModeChoice::Auto => Mode::Auto,
        ModeChoice::Light => Mode::Light,
        ModeChoice::Dark => Mode::Dark,
    }
}

/// The first 8 hex digits of a tid, for the status line.
fn short(t: Tid) -> String {
    t.to_string().chars().take(8).collect()
}

impl AppDriver for Ui {
    /// The window exists now: wakes posted before it were dropped by masonry_winit, so start the
    /// mailbox over and refresh once.
    fn on_start(&mut self, state: &mut osis_kit::masonry_winit::app::MasonryState<'_>) {
        osis_kit::fonts::register(state);
        self.inbox.drain();
        self.mb.post(Msg::Changed);
    }

    fn on_action(&mut self, _w: WindowId, ctx: &mut DriverCtx<'_, '_>, id: WidgetId, action: ErasedAction) {
        if action.is::<Wakeup>() {
            let mut changed = false;
            for m in self.inbox.drain() {
                match m {
                    Msg::Changed => changed = true,
                    Msg::Diagnostic(d) => {
                        self.diag = Some(d);
                        changed = true;
                    }
                    Msg::Remote(t) => self.remote(ctx, t),
                }
            }
            if changed {
                self.refresh(ctx, false);
            }
        } else if let Some(Resized(size)) = action.downcast_ref::<Resized>().copied() {
            let narrow = narrow(size);
            if narrow != self.narrow || self.built.is_none() {
                self.narrow = narrow;
                self.refresh(ctx, false);
            }
        } else if action.is::<Press>() {
            if let Some(a) = self.acts.get(&id).cloned() {
                self.press(ctx, a);
            }
        } else if let Ok(a) = action.downcast::<TextAction>() {
            self.typed(ctx, id, *a);
        }
    }
}

fn narrow(size: Size) -> bool {
    size.width < NARROW
}

/// The initial widget tree: the root over an empty screen (the first refresh builds it).
pub fn tree(look: Arc<Look>) -> NewWidget<dyn Widget> {
    NewWidget::new_with_tag(Root::new(NewWidget::new(SizedBox::empty()), look), ROOT).erased()
}
