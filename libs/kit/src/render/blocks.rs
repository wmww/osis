//! Masonry widgets for `Block`s: the only code that touches widgets apart from the shell.

use crate::store::Data;
use crate::view::paged::{Item, List, ListRow, Style};
use crate::view::{Block, ChipMark, Composer, Do, Entry, FormRow, Mark, Pick, TextRole, WindowState};
use osis::Tid;
use crate::icons::Icon;
use crate::masonry::core::{NewWidget, Properties, Widget, WidgetId};
use crate::masonry::properties::Padding;
use crate::masonry::properties::types::{CrossAxisAlignment, Length};
use crate::masonry::widgets::{Flex, SizedBox, TextInput};
use crate::theme::{Look, parse};
use crate::widgets::style::{self, Text};
use crate::list::{KeyedList, Rows};
use crate::widgets::{Chip as KChip, ChipMark as KMark, Panel, PanelKind, Tile, TileGrid, TileIcon, TileStyle, VirtualList, Wrap};
use std::collections::HashMap;
use std::sync::Arc;

/// Pastes the clipboard into the search field (Android: no Ctrl+V or soft keyboard text).
#[cfg(target_os = "android")]
#[derive(Clone, Debug, PartialEq)]
pub struct PasteSearch;

#[cfg(target_os = "android")]
impl crate::view::Action for PasteSearch {
    fn run(&self, act: &crate::view::Act, _: &crate::view::Input) -> osis::Result<()> {
        act.effects.borrow_mut().paste = crate::platform::clipboard();
        Ok(())
    }
}

/// A form input: what it saves, the value last saved, the text it shows now.
struct FormInput {
    save: Do,
    saved: String,
    text: String,
}

/// What a slot's widgets registered, so it can be forgotten with them.
#[derive(Default)]
pub struct Built {
    /// Form inputs in order (the focus stays with the same place across a rebuild).
    pub inputs: Vec<WidgetId>,
    /// Child views' slots: key and the slot's widget.
    pub children: Vec<(String, WidgetId)>,
    /// The pinned foot's slot of a filled child: its key and widget.
    pub feet: Vec<(String, WidgetId)>,
    /// Filled children, by key: their foot is pinned.
    pub pinned: Vec<String>,
    /// The kept lists, by the index of their block.
    pub lists: HashMap<usize, RowList>,
    ids: Vec<WidgetId>,
}

/// A list's widget and what each row registered.
pub struct RowList {
    pub widget: WidgetId,
    pub keyed: KeyedList<String, Built>,
}

/// The widgets that report an action, and what it does.
#[derive(Default)]
pub struct Acts {
    press: HashMap<WidgetId, Do>,
    remove: HashMap<WidgetId, Do>,
    reorder: HashMap<WidgetId, Do>,
    /// A list widget's path for its window (`LIST_WINDOW`), and the slot and block holding it.
    lists: HashMap<WidgetId, (String, String, usize)>,
    forms: HashMap<WidgetId, FormInput>,
    blur: HashMap<WidgetId, WidgetId>,
    editors: HashMap<WidgetId, crate::view::sessions::Key>,
    enter: HashMap<WidgetId, Do>,
}

impl Acts {
    pub fn clear(&mut self) {
        *self = Acts::default();
    }
    pub fn press(&mut self, id: WidgetId, d: Do) {
        self.press.insert(id, d);
    }
    pub fn pressed(&self, id: WidgetId) -> Option<Do> {
        self.press.get(&id).cloned()
    }
    pub fn removed(&self, id: WidgetId) -> Option<Do> {
        self.remove.get(&id).cloned()
    }
    pub fn reorder(&self, id: WidgetId) -> Option<Do> {
        self.reorder.get(&id).cloned()
    }
    /// The list widget's window key, slot and block.
    pub fn list_of(&self, id: WidgetId) -> Option<(String, String, usize)> {
        self.lists.get(&id).cloned()
    }
    pub fn blur_input(&self, id: WidgetId) -> Option<WidgetId> {
        self.blur.get(&id).copied()
    }
    pub fn editor(&self, id: WidgetId) -> Option<crate::view::sessions::Key> {
        self.editors.get(&id).cloned()
    }
    /// The widget of the editor of this session.
    pub fn editor_for(&self, key: &crate::view::sessions::Key) -> Option<WidgetId> {
        self.editors.iter().find(|(_, k)| *k == key).map(|(id, _)| *id)
    }
    /// The widget of the first editor on `(t, ak)`.
    pub fn editor_of(&self, t: Tid, ak: &str) -> Option<WidgetId> {
        self.editors.iter().find(|(_, k)| k.1 == t && k.2 == ak && k.3.is_none()).map(|(id, _)| *id)
    }
    pub fn on_enter(&self, id: WidgetId) -> Option<Do> {
        self.enter.get(&id).cloned()
    }
    pub fn has_form(&self, id: WidgetId) -> bool {
        self.forms.contains_key(&id)
    }
    pub fn set_form_text(&mut self, id: WidgetId, t: String) {
        if let Some(f) = self.forms.get_mut(&id) {
            f.text = t;
        }
    }
    pub fn form_dirty(&self, id: WidgetId) -> Option<(Do, String)> {
        let f = self.forms.get(&id)?;
        (f.text.trim() != f.saved.trim()).then(|| (f.save.clone(), f.text.clone()))
    }
    pub fn set_form_saved(&mut self, id: WidgetId, t: String) {
        if let Some(f) = self.forms.get_mut(&id) {
            f.saved = t;
        }
    }
    pub fn forget(&mut self, b: &Built) {
        for row in b.lists.values().flat_map(|l| l.keyed.rows()) {
            self.forget(row);
        }
        for id in &b.ids {
            self.press.remove(id);
            self.remove.remove(id);
            self.reorder.remove(id);
            self.lists.remove(id);
            self.forms.remove(id);
            self.blur.remove(id);
            self.editors.remove(id);
            self.enter.remove(id);
        }
    }
}

struct R<'a> {
    data: &'a Data,
    window: &'a WindowState,
    look: &'a Arc<Look>,
    acts: &'a mut Acts,
    built: Built,
    current: Option<Tid>,
    path: &'a str,
    /// The block being placed, while it can keep a list: where the list is recorded.
    listing: Option<usize>,
    /// The slot being filled (`Acts::list_of`).
    list_slot: Option<String>,
}

/// Runs of rows the shell patches: makes one row and forgets one row.
pub struct Maker<'a> {
    pub data: &'a Data,
    pub window: &'a WindowState,
    pub look: &'a Arc<Look>,
    pub acts: &'a mut Acts,
    pub current: Option<Tid>,
    pub path: &'a str,
    pub style: Style,
    pub rows: &'a [ListRow],
    /// Child views new rows opened, for the shell to give slots.
    pub children: Vec<(String, WidgetId)>,
}

impl Rows<String, Built> for Maker<'_> {
    fn make(&mut self, i: usize, _: &String) -> (NewWidget<dyn Widget>, Built) {
        let mut r = R { data: self.data, window: self.window, look: self.look, acts: &mut *self.acts, built: Built::default(), current: self.current, path: self.path, listing: None, list_slot: None };
        let w = match self.rows.get(i) {
            Some(row) => r.list_row(row, self.style).0,
            None => NewWidget::new(SizedBox::empty()).erased(),
        };
        self.children.extend(r.built.children.iter().cloned());
        (w, r.built)
    }
    fn dropped(&mut self, row: Built) {
        self.acts.forget(&row);
    }
}

/// The widgets of `blocks`, registering what they do.
#[allow(clippy::too_many_arguments)]
pub fn blocks(data: &Data, window: &WindowState, look: &Arc<Look>, acts: &mut Acts, path: &str, blocks: &[Block], current: Option<Tid>) -> (NewWidget<dyn Widget>, Built) {
    let mut r = R { data, window, look, acts, built: Built::default(), current, path, listing: None, list_slot: Some(path.to_string()) };
    let mut col = Flex::column().cross_axis_alignment(CrossAxisAlignment::Fill).with_gap(Length::px(look.sp(8.0)));
    // what fills the space takes what the column is given: a lone child view, or a filled one
    let fill = |b: &Block| matches!(b, Block::Filled { .. } | Block::List(_)) || (blocks.len() == 1 && matches!(b, Block::View { .. }));
    for (i, b) in blocks.iter().enumerate() {
        r.listing = matches!(b, Block::List(_)).then_some(i);
        if let Some(w) = r.block(b) {
            col = if fill(b) { col.with_flex_child(w, 1.0) } else { col.with_child(w) };
        }
    }
    (NewWidget::new(col).erased(), r.built)
}

fn tint(c: &Option<String>) -> Option<crate::masonry::peniko::Color> {
    c.as_deref().and_then(parse)
}

fn tile_icon(m: &Mark) -> TileIcon {
    match m {
        Mark::Icon(i) => TileIcon::Icon(*i),
        Mark::Initials(s) => TileIcon::Initials(s.clone()),
    }
}

impl R<'_> {
    fn press(&mut self, id: WidgetId, d: Do) {
        self.acts.press.insert(id, d);
        self.built.ids.push(id);
    }

    fn block(&mut self, b: &Block) -> Option<NewWidget<dyn Widget>> {
        let look = self.look.clone();
        Some(match b {
            Block::Heading(s) => style::label(&look, s, Text::Title).erased(),
            Block::Line(s) => style::prose(&look, s, Text::Muted).erased(),
            Block::Label(s) => style::label(&look, s, Text::Section).erased(),
            Block::Chips(c) => self.chips(c),
            Block::Tabs(tabs) => {
                let mut wrap = Wrap::new(look.clone());
                for t in tabs {
                    let w = NewWidget::new(KChip::new(&t.label, None, KMark::Icon(Icon::List), look.clone()).flat(!t.current));
                    self.press(w.id(), t.press.clone());
                    wrap = wrap.with_child(w);
                }
                NewWidget::new(wrap).erased()
            }
            Block::List(l) => self.list(l),
            Block::Days(days) => self.days(days),
            Block::View { key, .. } => self.child(key).erased(),
            Block::Filled { key, has_foot, plain, fills, below, .. } => self.filled(key, *has_foot, *plain, *fills, below),
            Block::Bar { back, descriptor, favorite, star, more, menu } => self.bar(back, descriptor, *favorite, star, more, menu),
            Block::Form { rows, wide } => self.form(rows, *wide),
            Block::Editor { thing, ak, key, placeholder, role, multiline, lead } => self.editor(*thing, ak, key, placeholder, *role, *multiline, lead)?,
            Block::Composer(c) => self.composer(c),
            Block::Pick { cols, options } => self.pick(*cols, options),
        })
    }

    /// An empty slot for the child view at `key`.
    fn child(&mut self, key: &str) -> NewWidget<SizedBox> {
        let w = NewWidget::new(SizedBox::empty());
        self.built.children.push((key.to_string(), w.id()));
        w
    }

    /// A child filling the space: panel, scroll, what is below it, the pinned foot under them.
    fn filled(&mut self, key: &str, has_foot: bool, plain: bool, fills: bool, below: &[Block]) -> NewWidget<dyn Widget> {
        let look = self.look.clone();
        let sp = |x: f64| look.sp(x);
        let mut body = Flex::column().cross_axis_alignment(CrossAxisAlignment::Fill).with_gap(Length::px(sp(16.0)));
        if let Some(m) = style::title_mark(&look) {
            body = body.with_child(m);
        }
        // a child with a list scrolls that list: it takes the height, the rest stays put
        body = if fills { body.with_flex_child(self.child(key), 1.0) } else { body.with_child(self.child(key)) };
        for b in below {
            if let Some(w) = self.block(b) {
                body = body.with_child(w);
            }
        }
        let body = NewWidget::new_with_props(body, Properties::new().with(Padding::all(sp(28.0))));
        let scroll: NewWidget<dyn Widget> = if fills { body.erased() } else { NewWidget::new(crate::masonry::widgets::Portal::new(body).constrain_horizontal(true).content_must_fill(true)).erased() };
        self.built.pinned.push(key.to_string());
        let mut col = Flex::column().cross_axis_alignment(CrossAxisAlignment::Fill).with_gap(Length::px(sp(10.0)));
        col = if plain { col.with_flex_child(scroll, 1.0) } else { col.with_flex_child(NewWidget::new(Panel::new(scroll, look.clone(), PanelKind::Panel, (0.0, 0.0)).fill_height(true)), 1.0) };
        if has_foot {
            let foot = NewWidget::new(SizedBox::empty());
            self.built.feet.push((key.to_string(), foot.id()));
            col = col.with_child(NewWidget::new(Panel::new(foot, look.clone(), PanelKind::Panel, (12.0, 14.0))));
        }
        NewWidget::new(col).erased()
    }

    fn bar(&mut self, back: &Option<Do>, descriptor: &str, favorite: bool, star: &Do, more: &Do, menu: &[crate::view::Chip]) -> NewWidget<dyn Widget> {
        use crate::widgets::IconButton;
        let look = self.look.clone();
        let sp = |x: f64| look.sp(x);
        let mut bar = Flex::row().with_gap(Length::px(sp(8.0)));
        if let Some(d) = back {
            let b = NewWidget::new(IconButton::new(Icon::Back, "Home", look.clone()));
            self.press(b.id(), d.clone());
            bar = bar.with_child(b);
        }
        bar = bar.with_child(style::label(&look, descriptor, Text::Muted)).with_flex_spacer(1.0);
        let s = NewWidget::new(IconButton::new(Icon::Star, "Favorite", look.clone()).on(favorite));
        self.press(s.id(), star.clone());
        bar = bar.with_child(s);
        let m = NewWidget::new(IconButton::new(Icon::More, "More", look.clone()));
        self.press(m.id(), more.clone());
        bar = bar.with_child(m);
        let bar = NewWidget::new_with_props(bar, Properties::new().with(Padding::from_vh(0.0, sp(4.0))));
        if menu.is_empty() {
            return bar.erased();
        }
        let menu = self.chips(menu);
        NewWidget::new(Flex::column().cross_axis_alignment(CrossAxisAlignment::Fill).with_gap(Length::px(sp(6.0))).with_child(bar).with_child(menu)).erased()
    }

    fn chips(&mut self, chips: &[crate::view::Chip]) -> NewWidget<dyn Widget> {
        let look = self.look.clone();
        let mut wrap = Wrap::new(look.clone());
        for m in chips {
            let mark = match m.mark {
                ChipMark::Dot => KMark::Dot,
                ChipMark::Icon(i) => KMark::Icon(i),
            };
            let w = NewWidget::new(KChip::new(&m.label, tint(&m.color), mark, look.clone()).flat(m.flat).removable(m.remove.is_some()));
            if let Some(d) = &m.press {
                self.press(w.id(), d.clone());
            }
            if let Some(d) = &m.remove {
                self.acts.remove.insert(w.id(), d.clone());
                self.built.ids.push(w.id());
            }
            wrap = wrap.with_child(w);
        }
        NewWidget::new(wrap).erased()
    }

    fn tile(&mut self, style: TileStyle, e: &Entry) -> NewWidget<Tile> {
        self.window.graph.add_row();
        let w = NewWidget::new(Tile::new(style, tile_icon(&e.mark), &e.title, &e.text, tint(&e.color), self.look.clone()).current(self.current == Some(e.thing)));
        self.press(w.id(), Do::new(crate::view::Open(Some(e.thing))));
        w
    }

    /// A row of a list: its widget, and whether it runs the full width.
    fn list_row(&mut self, row: &ListRow, style: Style) -> (NewWidget<dyn Widget>, bool) {
        let look = self.look.clone();
        match &row.item {
            Item::Entry(e) => (
                match style {
                    Style::Stream => self.stream_entry(e),
                    Style::Card => self.tile(TileStyle::Card, e).erased(),
                    Style::Row => self.tile(TileStyle::Row, e).erased(),
                },
                false,
            ),
            Item::Label(s) => (style::label(&look, s, Text::Section).erased(), true),
            Item::View(_) => (self.child(&row.key).erased(), false),
            Item::New(d) => {
                let w = NewWidget::new(Tile::new(TileStyle::New, TileIcon::Icon(Icon::Plus), "New", "Note, event, person, tag", None, look));
                self.press(w.id(), d.clone());
                (w.erased(), false)
            }
        }
    }

    /// A windowed list.
    fn list(&mut self, l: &List) -> NewWidget<dyn Widget> {
        let look = self.look.clone();
        let listing = self.listing.take();
        let (min, gap, cols) = match l.shape.style {
            Style::Stream => (100.0, 8.0, 1),
            Style::Card => (158.0, 12.0, l.shape.cols),
            Style::Row if l.shape.cols == 1 => (100.0, 3.0, 1),
            Style::Row => (220.0, 4.0, l.shape.cols),
        };
        let mut w = VirtualList::new(look, min, cols, gap, l.shape.follow_end);
        let mut keyed = KeyedList::default();
        for row in &l.rows {
            let outer = std::mem::take(&mut self.built);
            let (row_w, span) = self.list_row(row, l.shape.style);
            let built = std::mem::replace(&mut self.built, outer);
            self.built.children.extend(built.children.iter().cloned());
            w = w.with_child(row_w, span);
            keyed.push(row.key.clone(), built);
        }
        let fixed = usize::from(matches!(l.rows.last(), Some(ListRow { item: Item::New(_), .. })));
        if l.shape.reorder.is_some() {
            w = w.reorderable(fixed);
        }
        w = w.anchored(l.anchor, l.first.unwrap_or(0), l.more_before, l.more_after);
        let w = NewWidget::new(w);
        if let (Some(i), Some(slot)) = (listing, self.list_slot.clone()) {
            self.built.lists.insert(i, RowList { widget: w.id(), keyed });
            self.acts.lists.insert(w.id(), (l.id.clone(), slot, i));
            self.built.ids.push(w.id());
        }
        if let Some(d) = &l.shape.reorder {
            self.acts.reorder.insert(w.id(), d.clone());
            self.built.ids.push(w.id());
        }
        w.erased()
    }

    fn days(&mut self, days: &[crate::view::Day]) -> NewWidget<dyn Widget> {
        let look = self.look.clone();
        let mut g = TileGrid::new(look.clone(), 118.0).max_cols(7).gap(8.0);
        for d in days {
            let mut day = Flex::column().cross_axis_alignment(CrossAxisAlignment::Fill).with_gap(Length::px(look.sp(4.0)));
            day = day.with_child(style::label(&look, &d.label, if d.today { Text::Body } else { Text::Muted }));
            if d.entries().is_empty() {
                day = day.with_child(style::label(&look, "Free", Text::Small));
            }
            for e in d.entries() {
                self.window.graph.add_row();
                let w = NewWidget::new(Tile::new(TileStyle::Row, TileIcon::Bar, &e.title, &e.text, tint(&e.color), look.clone()));
                self.press(w.id(), Do::new(crate::view::Open(Some(e.thing))));
                day = day.with_child(w);
            }
            if d.more() > 0 {
                day = day.with_child(style::label(&look, &format!("+{} more", d.more()), Text::Small));
            }
            let kind = if d.today { PanelKind::Highlight } else { PanelKind::Inset };
            g = g.with_child(NewWidget::new(Panel::new(NewWidget::new(day), look.clone(), kind, (10.0, 8.0))));
        }
        NewWidget::new(g).erased()
    }

    /// One entry in a stream: who and when, what it answers, its text, its actions.
    fn stream_entry(&mut self, e: &Entry) -> NewWidget<dyn Widget> {
        self.window.graph.add_row();
        let look = self.look.clone();
        let mut col = Flex::column().cross_axis_alignment(CrossAxisAlignment::Fill).with_gap(Length::px(look.sp(4.0)));
        let head = e.author.clone().unwrap_or_else(|| e.title.clone());
        col = col.with_child(style::prose(&look, &head, Text::Small));
        if let Some(q) = &e.quote {
            col = col.with_child(style::prose(&look, &format!("↩ {q}"), Text::Muted));
        }
        col = col.with_child(style::prose(&look, &e.text, Text::Body));
        if !e.actions.is_empty() {
            let row = Flex::row().with_flex_spacer(1.0).with_child(self.chips(&e.actions));
            col = col.with_child(NewWidget::new(row));
        }
        let kind = if e.raised { PanelKind::Highlight } else { PanelKind::Inset };
        NewWidget::new(Panel::new(NewWidget::new(col), look, kind, (10.0, 12.0))).erased()
    }

    fn form(&mut self, rows: &[FormRow], wide: bool) -> NewWidget<dyn Widget> {
        let look = self.look.clone();
        let mut col = Flex::column().cross_axis_alignment(CrossAxisAlignment::Fill).with_gap(Length::px(look.sp(8.0)));
        for r in rows {
            let mut label = Flex::column().cross_axis_alignment(CrossAxisAlignment::Start).with_child(style::label(&look, &r.label, Text::Muted));
            if !r.sub.is_empty() {
                label = label.with_child(style::label(&look, &r.sub, Text::Small));
            }
            let indent = look.sp(16.0) * r.depth as f64;
            let label = NewWidget::new_with_props(label, Properties::new().with(Padding { left: indent, right: 0.0, top: 0.0, bottom: 0.0 }));
            let value: NewWidget<dyn Widget> = match &r.save {
                None => style::label(&look, &r.value, Text::Body).erased(),
                Some(d) => self.form_input(&r.value, &r.placeholder, d.clone()).erased(),
            };
            let row = Flex::row()
                .cross_axis_alignment(CrossAxisAlignment::Center)
                .with_gap(Length::px(look.sp(12.0)))
                .with_child(NewWidget::new(SizedBox::new(label).width(Length::px(if wide { 220.0 } else { 120.0 }))))
                .with_flex_child(value, 1.0);
            col = col.with_child(NewWidget::new(row));
        }
        NewWidget::new(col).erased()
    }

    /// A form field: the input in a field panel that reports losing focus.
    fn form_input(&mut self, value: &str, placeholder: &str, save: Do) -> NewWidget<Panel> {
        let (input, id) = style::input(self.look, value, placeholder, Text::Body, false);
        let panel = NewWidget::new(Panel::new(input, self.look.clone(), PanelKind::Field, (5.0, 8.0)).report_blur(true));
        self.acts.forms.insert(id, FormInput { save, saved: value.to_string(), text: value.to_string() });
        self.acts.blur.insert(panel.id(), id);
        self.built.ids.extend([id, panel.id()]);
        self.built.inputs.push(id);
        panel
    }

    #[allow(clippy::too_many_arguments)]
    fn editor(&mut self, thing: Tid, ak: &str, map: &Option<String>, placeholder: &str, role: TextRole, multiline: bool, lead: &Option<(Mark, Option<String>)>) -> Option<NewWidget<dyn Widget>> {
        let look = self.look.clone();
        let key = (self.path.to_string(), thing, ak.to_string(), map.clone());
        let shown = self.window.sessions.show(self.data, &key).ok()?;
        let role_t = match role {
            TextRole::Title => Text::Title,
            TextRole::Body => Text::Body,
            TextRole::Muted => Text::Muted,
        };
        let (w, id): (NewWidget<TextInput>, _) = style::input(&look, &shown, placeholder, role_t, multiline);
        self.acts.editors.insert(id, key);
        self.built.ids.push(id);
        if let Some((m, c)) = lead {
            // an avatar beside the title
            let avatar = NewWidget::new(Tile::new(TileStyle::Row, tile_icon(m), "", "", tint(c), look.clone()));
            let row = Flex::row().with_gap(Length::px(look.sp(4.0))).with_child(NewWidget::new(SizedBox::new(avatar).width(Length::px(46.0)))).with_flex_child(w, 1.0);
            return Some(NewWidget::new(row).erased());
        }
        Some(w.erased())
    }

    fn composer(&mut self, c: &Composer) -> NewWidget<dyn Widget> {
        let look = self.look.clone();
        let mut col = Flex::column().cross_axis_alignment(CrossAxisAlignment::Fill).with_gap(Length::px(look.sp(8.0)));
        let last = c.fields.len().saturating_sub(1);
        for (i, f) in c.fields.iter().enumerate() {
            let key = (self.path.to_string(), f.thing, f.ak.clone(), Some(f.key.clone()));
            let text = self.window.sessions.show(self.data, &key).unwrap_or_default();
            let (input, id) = style::input(&look, &text, &f.placeholder, Text::Body, false);
            let panel = NewWidget::new(Panel::new(input, look.clone(), PanelKind::Field, (8.0, 12.0)));
            self.acts.editors.insert(id, key);
            self.built.ids.push(id);
            self.built.inputs.push(id);
            if i == last {
                self.acts.enter.insert(id, c.send.clone());
                let send = NewWidget::new(KChip::new("Send", None, KMark::Icon(Icon::Plus), look.clone()));
                self.press(send.id(), c.send.clone());
                #[allow(unused_mut)]
                let mut row = Flex::row().with_gap(Length::px(look.sp(8.0))).with_flex_child(panel, 1.0).with_child(send);
                #[cfg(target_os = "android")]
                {
                    let paste = NewWidget::new(KChip::new("Paste and send", None, KMark::Icon(Icon::Plus), look.clone()));
                    self.press(paste.id(), Do::new(PasteAndSend(c.send.clone())));
                    row = row.with_child(paste);
                }
                col = col.with_child(NewWidget::new(row));
            } else {
                col = col.with_child(panel);
            }
        }
        NewWidget::new(col).erased()
    }

    fn pick(&mut self, cols: usize, options: &[Pick]) -> NewWidget<dyn Widget> {
        let look = self.look.clone();
        let mut g = TileGrid::new(look.clone(), 120.0).gap(4.0);
        if cols > 0 {
            g = g.max_cols(cols);
        }
        for o in options {
            let w = NewWidget::new(Tile::new(TileStyle::Row, tile_icon(&o.mark), &o.label, "", tint(&o.tint), look.clone()).current(o.current));
            self.press(w.id(), o.press.clone());
            g = g.with_child(w);
        }
        NewWidget::new(g).erased()
    }
}

/// Runs a composer's send on the clipboard's text (Android).
#[cfg(target_os = "android")]
#[derive(Clone, Debug, PartialEq)]
struct PasteAndSend(Do);

#[cfg(target_os = "android")]
impl crate::view::Action for PasteAndSend {
    fn run(&self, act: &crate::view::Act, _: &crate::view::Input) -> osis::Result<()> {
        let text = crate::platform::clipboard().unwrap_or_default();
        self.0.run(act, &crate::view::Input::Text(text))
    }
}
