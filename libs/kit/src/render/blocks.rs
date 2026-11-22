//! Masonry widgets for `Block`s: the only code that touches widgets apart from the shell.

use crate::store::Data;
use crate::view::paged::{Item, List, ListRow, Style};
use crate::view::{Block, ChipMark, Composer, Do, Entry, FormRow, Mark, Pick, TYPE_IN, TextRole, WindowState};
use osis::Tid;
use crate::icons::Icon;
use crate::masonry::core::{Capitalize, EnterKey, NewWidget, Properties, TextInputHints, Widget, WidgetId, WidgetMut};
use crate::masonry::properties::Padding;
use crate::masonry::properties::types::{CrossAxisAlignment, Length};
use crate::masonry::widgets::{Flex, SizedBox, TextInput};
use crate::theme::{Look, parse};
use crate::widgets::style::{self, Text};
use crate::view::keyed::Op;
use crate::widgets::{Chip as KChip, Panel, PanelKind, Tile, TileGrid, TileIcon, TileStyle, Page, VirtualList, Wrap};
use std::collections::HashMap;
use std::sync::Arc;

/// A form input: what it saves, the value last saved, the text it shows now.
pub struct FormInput {
    pub save: Do,
    pub saved: String,
    pub text: String,
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
    /// The field to type in now (`TYPE_IN`).
    pub typing: Option<WidgetId>,
    /// The kept lists, by the index of their block.
    pub lists: HashMap<usize, RowList>,
    ids: Vec<WidgetId>,
}

/// A list's widget and, row by row, its key and what the row registered.
pub struct RowList {
    pub widget: WidgetId,
    pub rows: Vec<(String, Built)>,
}

impl RowList {
    /// The keys shown, in order.
    pub fn keys(&self) -> impl Iterator<Item = &String> {
        self.rows.iter().map(|(k, _)| k)
    }

    /// Applies `ops` (from `reconcile` against `keys()`) to `list` and to the rows. Masonry cannot
    /// move a widget between slots, so a row that moved or changed is rebuilt.
    pub fn apply(&mut self, list: &mut WidgetMut<'_, VirtualList>, ops: &[Op<String>], maker: &mut Maker) {
        for op in ops {
            match op {
                Op::Remove(i) if *i < self.rows.len() => {
                    maker.acts.forget(&self.rows.remove(*i).1);
                    VirtualList::remove_row(list, *i);
                }
                Op::Insert(i, k) if *i <= self.rows.len() => {
                    let (w, b) = maker.make(*i);
                    self.rows.insert(*i, (k.clone(), b));
                    VirtualList::insert_row(list, *i, w);
                }
                _ => {}
            }
        }
    }
}

/// What a widget reporting an action does with it.
#[derive(Default)]
pub struct Hooks {
    pub press: Option<Do>,
    /// A chip's ×.
    pub remove: Option<Do>,
    pub reorder: Option<Do>,
    /// A list widget's path for its window (`LIST_WINDOW`), and the slot and block holding it.
    pub list: Option<(String, String, usize)>,
    pub form: Option<FormInput>,
    /// A field panel reporting its input's blur: that input.
    pub blur: Option<WidgetId>,
    pub editor: Option<crate::view::sessions::Key>,
    /// Run on Enter.
    pub enter: Option<Do>,
}

/// The widgets that report an action, and what each does.
#[derive(Default)]
pub struct Acts(HashMap<WidgetId, Hooks>);

impl Acts {
    pub fn clear(&mut self) {
        self.0.clear();
    }
    pub fn get(&self, id: WidgetId) -> Option<&Hooks> {
        self.0.get(&id)
    }
    pub fn get_mut(&mut self, id: WidgetId) -> Option<&mut Hooks> {
        self.0.get_mut(&id)
    }
    pub fn at(&mut self, id: WidgetId) -> &mut Hooks {
        self.0.entry(id).or_default()
    }
    /// The widget of the editor of this session.
    pub fn editor_for(&self, key: &crate::view::sessions::Key) -> Option<WidgetId> {
        self.0.iter().find(|(_, h)| h.editor.as_ref() == Some(key)).map(|(id, _)| *id)
    }
    pub fn forget(&mut self, b: &Built) {
        for (_, row) in b.lists.values().flat_map(|l| &l.rows) {
            self.forget(row);
        }
        for id in &b.ids {
            self.0.remove(id);
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
    /// The slot being filled.
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

impl Maker<'_> {
    /// The row at `i` of the new list, and what it registered.
    fn make(&mut self, i: usize) -> (NewWidget<dyn Widget>, Built) {
        let mut r = R { data: self.data, window: self.window, look: self.look, acts: &mut *self.acts, built: Built::default(), current: self.current, path: self.path, listing: None, list_slot: None };
        let w = match self.rows.get(i) {
            Some(row) => r.list_row(row, self.style).0,
            None => NewWidget::new(SizedBox::empty()).erased(),
        };
        self.children.extend(r.built.children.iter().cloned());
        (w, r.built)
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
    /// What `id` does, to fill in; forgotten with the slot.
    fn hook(&mut self, id: WidgetId) -> &mut Hooks {
        self.built.ids.push(id);
        self.acts.at(id)
    }

    fn press(&mut self, id: WidgetId, d: Do) {
        self.hook(id).press = Some(d);
    }

    fn block(&mut self, b: &Block) -> Option<NewWidget<dyn Widget>> {
        let look = self.look.clone();
        Some(match b {
            Block::Heading(s) => style::heading(&look, s, Text::Title),
            Block::Line(s) => style::prose(&look, s, Text::Muted).erased(),
            Block::Label(s) => style::heading(&look, s, Text::Section),
            Block::Chips(c) => self.chips(c),
            Block::Tabs(tabs) => {
                let mut wrap = Wrap::new(look.clone());
                for t in tabs {
                    let w = NewWidget::new(KChip::new(&t.label, None, ChipMark::Icon(Icon::List), look.clone()).flat(!t.current));
                    self.press(w.id(), t.press.clone());
                    wrap = wrap.with_child(w);
                }
                NewWidget::new(wrap).erased()
            }
            Block::List(l) => self.list(l),
            Block::Days(days) => self.days(days),
            Block::View { key, .. } => self.child(key).erased(),
            Block::Filled { key, has_foot, plain, above, below, .. } => self.filled(key, *has_foot, *plain, above, below),
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

    /// A child filling a page: what is above it as the page's head, the child and what is below
    /// it in a panel, the child's foot as the page's foot.
    fn filled(&mut self, key: &str, has_foot: bool, plain: bool, above: &[Block], below: &[Block]) -> NewWidget<dyn Widget> {
        let look = self.look.clone();
        let sp = |x: f64| look.sp(x);
        let mut head = Flex::column().cross_axis_alignment(CrossAxisAlignment::Fill).with_gap(Length::px(sp(8.0)));
        for b in above {
            if let Some(w) = self.block(b) {
                head = head.with_child(w);
            }
        }
        // the child takes what the page leaves when everything fits
        let mut body = Flex::column().cross_axis_alignment(CrossAxisAlignment::Fill).with_gap(Length::px(sp(16.0))).with_flex_child(self.child(key), 1.0);
        for b in below {
            if let Some(w) = self.block(b) {
                body = body.with_child(w);
            }
        }
        let body = NewWidget::new_with_props(body, Properties::new().with(Padding::all(sp(28.0))));
        self.built.pinned.push(key.to_string());
        let body: NewWidget<dyn Widget> = if plain { body.erased() } else { NewWidget::new(Panel::new(body, look.clone(), PanelKind::Panel, (0.0, 0.0)).fill_height(true)).erased() };
        let mut page = Page::new(body, look.clone());
        if !above.is_empty() {
            page = page.with_head(NewWidget::new(head), sp(10.0));
        }
        if has_foot {
            let foot = NewWidget::new(SizedBox::empty());
            self.built.feet.push((key.to_string(), foot.id()));
            page = page.with_foot(NewWidget::new(Panel::new(foot, look.clone(), PanelKind::Panel, (12.0, 14.0))), sp(10.0));
        }
        NewWidget::new(page).erased()
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
            let w = NewWidget::new(KChip::new(&m.label, tint(&m.color), m.mark, look.clone()).flat(m.flat).removable(m.remove.is_some()));
            if let Some(d) = &m.press {
                self.press(w.id(), d.clone());
            }
            if let Some(d) = &m.remove {
                self.hook(w.id()).remove = Some(d.clone());
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
            Item::Label(s) => (style::heading(&look, s, Text::Section), true),
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
            Style::Row => (crate::widgets::ROW_MIN, 4.0, l.shape.cols),
        };
        let mut w = VirtualList::new(look, min, cols, gap, l.shape.follow_end);
        let mut keyed = Vec::new();
        for row in &l.rows {
            let outer = std::mem::take(&mut self.built);
            let (row_w, span) = self.list_row(row, l.shape.style);
            let built = std::mem::replace(&mut self.built, outer);
            self.built.children.extend(built.children.iter().cloned());
            w = w.with_child(row_w, span);
            keyed.push((row.key.clone(), built));
        }
        let fixed = usize::from(matches!(l.rows.last(), Some(ListRow { item: Item::New(_), .. })));
        if l.shape.reorder.is_some() {
            w = w.reorderable(fixed);
        }
        w = w.anchored(l.anchor, l.first.unwrap_or(0), l.total, l.more_before, l.more_after);
        let w = NewWidget::new(w);
        if let (Some(i), Some(slot)) = (listing, self.list_slot.clone()) {
            self.built.lists.insert(i, RowList { widget: w.id(), rows: keyed });
            self.hook(w.id()).list = Some((l.id.clone(), slot, i));
        }
        if let Some(d) = &l.shape.reorder {
            self.hook(w.id()).reorder = Some(d.clone());
        }
        w.erased()
    }

    fn days(&mut self, days: &[crate::view::Day]) -> NewWidget<dyn Widget> {
        let look = self.look.clone();
        let mut g = TileGrid::new(look.clone(), 118.0).max_cols(7).gap(8.0);
        for d in days {
            let mut day = Flex::column().cross_axis_alignment(CrossAxisAlignment::Fill).with_gap(Length::px(look.sp(4.0)));
            day = day.with_child(style::label(&look, &d.label, if d.today { Text::Body } else { Text::Muted }));
            if d.entries.is_empty() {
                day = day.with_child(style::label(&look, "Free", Text::Small));
            }
            for e in &d.entries {
                self.window.graph.add_row();
                let w = NewWidget::new(Tile::new(TileStyle::Row, TileIcon::Bar, &e.title, &e.text, tint(&e.color), look.clone()));
                self.press(w.id(), Do::new(crate::view::Open(Some(e.thing))));
                day = day.with_child(w);
            }
            if d.more > 0 {
                let w = NewWidget::new(KChip::new(&format!("+{} more", d.more), None, ChipMark::Icon(Icon::List), look.clone()).flat(true));
                self.press(w.id(), d.see_all.clone());
                day = day.with_child(w);
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
        // raw values (dates, ids, numbers) as typed: no corrections
        let hints = TextInputHints { capitalize: Capitalize::None, suggest: false, enter: EnterKey::Done, ..Default::default() };
        let (input, id) = style::input(self.look, value, placeholder, Text::Body, false, hints);
        let panel = NewWidget::new(Panel::new(input, self.look.clone(), PanelKind::Field, (5.0, 8.0)).report_blur(true));
        self.hook(id).form = Some(FormInput { save, saved: value.to_string(), text: value.to_string() });
        self.hook(panel.id()).blur = Some(id);
        self.built.inputs.push(id);
        panel
    }

    #[allow(clippy::too_many_arguments)]
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
        let hints = TextInputHints { suggest: true, enter: EnterKey::Done, ..Default::default() };
        let (w, id): (NewWidget<TextInput>, _) = style::input(&look, &shown, placeholder, role_t, multiline, hints);
        self.hook(id).editor = Some(key);
        if self.built.typing.is_none() && self.window.graph.peek(TYPE_IN).is_some_and(|(t, a)| t == thing && a == ak) {
            self.built.typing = Some(id);
        }
        if let Some((m, c)) = lead {
            // an avatar beside the title
            let avatar = NewWidget::new(Tile::new(TileStyle::Row, tile_icon(m), "", "", tint(c), look.clone()));
            let row = Flex::row().with_gap(Length::px(look.sp(4.0))).with_child(NewWidget::new(SizedBox::new(avatar).width(Length::px(46.0)))).with_flex_child(w, 1.0);
            return Some(NewWidget::new(row).erased());
        }
        Some(if role_t == Text::Title { style::marked(&look, w, Text::Title, false) } else { w.erased() })
    }

    fn composer(&mut self, c: &Composer) -> NewWidget<dyn Widget> {
        let look = self.look.clone();
        let mut col = Flex::column().cross_axis_alignment(CrossAxisAlignment::Fill).with_gap(Length::px(look.sp(8.0)));
        let last = c.fields.len().saturating_sub(1);
        for (i, f) in c.fields.iter().enumerate() {
            let key = (self.path.to_string(), f.thing, f.ak.clone(), Some(f.key.clone()));
            let text = self.window.sessions.show(self.data, &key).unwrap_or_default();
            let enter = if i == last { EnterKey::Send } else { EnterKey::Next };
            let hints = TextInputHints { suggest: true, enter, ..Default::default() };
            let (input, id) = style::input(&look, &text, &f.placeholder, Text::Body, false, hints);
            let panel = NewWidget::new(Panel::new(input, look.clone(), PanelKind::Field, (8.0, 12.0)));
            self.hook(id).editor = Some(key);
            self.built.inputs.push(id);
            if i == last {
                self.hook(id).enter = Some(c.send.clone());
                let send = NewWidget::new(KChip::new("Send", None, ChipMark::Icon(Icon::Plus), look.clone()));
                self.press(send.id(), c.send.clone());
                let row = Flex::row().with_gap(Length::px(look.sp(8.0))).with_flex_child(panel, 1.0).with_child(send);
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
