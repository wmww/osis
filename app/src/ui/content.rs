//! What the screens' slots show, as plain comparable models read from `Data`, and their widgets.
//! A slot is rebuilt only when its model changed.

use super::{Act, Ui};
use crate::data::{Data, Kind, NewKind, Tile};
use crate::schema::View;
use osis::Tid;
use osis_kit::icons::Icon;
use osis_kit::masonry::core::{NewWidget, Widget};
use osis_kit::masonry::properties::types::{CrossAxisAlignment, Length};
use osis_kit::masonry::widgets::Flex;
use osis_kit::theme::parse;
use osis_kit::widgets::style::{self, Text};
use osis_kit::widgets::{Chip, ChipMark, Panel, PanelKind, TileGrid, TileIcon, TileStyle, Wrap};

/// How a run of tiles is laid out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Grid {
    /// Cards in columns.
    Cards,
    /// Rows, one column (the rail).
    Rail,
    /// Rows in columns (a thing's tags, compact lists).
    Rows,
}

/// A chip's model.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChipM {
    pub label: String,
    pub color: Option<String>,
    pub mark: Mark,
    /// An action, not a thing: drawn flat.
    pub flat: bool,
    pub open: Act,
    pub remove: Option<Act>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mark {
    Dot,
    Icon(Icon),
}

impl ChipM {
    pub fn action(icon: Icon, label: &str, open: Act) -> ChipM {
        ChipM { label: label.into(), color: None, mark: Mark::Icon(icon), flat: true, open, remove: None }
    }
}

/// One piece of a slot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Block {
    /// Secondary text.
    Line(String),
    /// A section heading.
    Label(String),
    /// `favorites`: the favorites, in order, dragged to reorder.
    Tiles { tiles: Vec<Tile>, grid: Grid, new: bool, favorites: bool },
    Chips(Vec<ChipM>),
    /// Calendar days: a label, whether it is today, the events.
    Days(Vec<(String, bool, Vec<Tile>)>),
    /// The schema fallback view's rows of a thing.
    Fields(Tid, Vec<crate::fields::Row>),
    /// A kind's own form (labels and inputs saved on Enter).
    Form(Tid, Vec<crate::fields::FormRow>),
}

/// What a slot shows.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Content {
    pub blocks: Vec<Block>,
}

impl Content {
    fn label(&mut self, s: &str) {
        self.blocks.push(Block::Label(s.into()));
    }
    fn line(&mut self, s: impl Into<String>) {
        self.blocks.push(Block::Line(s.into()));
    }
    fn tiles(&mut self, tiles: Vec<Tile>, grid: Grid) {
        self.blocks.push(Block::Tiles { tiles, grid, new: false, favorites: false });
    }
}

fn tiles(d: &Data, v: &[Tid]) -> osis::Result<Vec<Tile>> {
    v.iter().map(|t| d.tile(*t)).collect()
}

/// The chips offering a new thing of each kind.
fn new_kinds() -> Block {
    Block::Chips(vec![
        ChipM::action(Icon::Note, "Note", Act::Create(NewKind::Note)),
        ChipM::action(Icon::Event, "Event", Act::Create(NewKind::Event)),
        ChipM::action(Icon::Contact, "Person", Act::Create(NewKind::Contact)),
        ChipM::action(Icon::Tag, "Tag", Act::Create(NewKind::Tag)),
    ])
}

impl Ui {
    /// Home's body (`rail`: the rail's list): favorites, or search results while typing.
    pub(super) fn list_content(&self, rail: bool) -> osis::Result<Content> {
        let d = &self.data;
        let grid = if rail { Grid::Rail } else { Grid::Cards };
        let mut c = Content::default();
        if !self.query.trim().is_empty() {
            let f = d.search(&self.query)?;
            if f.is_empty() {
                c.line(format!("Nothing matches “{}”.", self.query.trim()));
            }
            for (label, v) in [("Scopes", &f.scopes), ("Things", &f.named)] {
                if !v.is_empty() {
                    c.label(label);
                    c.tiles(tiles(d, v)?, grid);
                }
            }
            if !f.mentions.is_empty() {
                c.label("Mentions");
                let mut ts = Vec::new();
                for (t, snip) in &f.mentions {
                    let mut tile = d.tile(*t)?;
                    tile.sub = snip.clone();
                    ts.push(tile);
                }
                c.tiles(ts, grid);
            }
            if !f.in_scopes.is_empty() {
                c.label("In those scopes");
                c.tiles(tiles(d, &f.in_scopes)?, grid);
            }
            return Ok(c);
        }
        c.label("Favorites");
        c.blocks.push(Block::Tiles { tiles: tiles(d, &d.favorites()?)?, grid, new: !rail, favorites: true });
        if self.view.creating && !rail {
            c.blocks.push(new_kinds());
        }
        Ok(c)
    }

    /// The rail's foot: "New", then the kinds while choosing.
    pub(super) fn rail_new_content(&self) -> Content {
        let mut c = Content::default();
        if self.view.creating {
            c.blocks.push(new_kinds());
        }
        c
    }

    /// What a thing's pane shows between its title and its text.
    pub(super) fn extra_content(&self, t: Tid) -> osis::Result<Content> {
        let d = &self.data;
        let mut c = Content::default();
        if self.view.all_fields {
            c.label("All fields");
            c.line("Every aspect from its schema type. Enter saves a field; an empty optional field becomes none.");
            c.blocks.push(Block::Fields(t, d.field_rows(t)?));
            return Ok(c);
        }
        match d.kind(t)? {
            Kind::Event => {
                if let Some(s) = d.get(t, crate::event::START)? {
                    c.line(crate::data::fmt_when(&s, d.get(t, crate::event::END)?.as_ref()));
                    use crate::time::{DAY, HOUR, MINUTE};
                    let mut chips = vec![ChipM::action(Icon::Back, "Day earlier", Act::Nudge(t, -DAY, 0)), ChipM::action(Icon::Plus, "Day later", Act::Nudge(t, DAY, 0))];
                    if matches!(s, crate::event::Start::At(_)) {
                        chips.extend([
                            ChipM::action(Icon::Clock, "−1 h", Act::Nudge(t, -HOUR, 0)),
                            ChipM::action(Icon::Clock, "+1 h", Act::Nudge(t, HOUR, 0)),
                            ChipM::action(Icon::Clock, "Shorter", Act::Nudge(t, 0, -30 * MINUTE)),
                            ChipM::action(Icon::Clock, "Longer", Act::Nudge(t, 0, 30 * MINUTE)),
                        ]);
                    }
                    c.blocks.push(Block::Chips(chips));
                    // how it repeats: the current choice is a filled chip
                    use crate::event::RepeatFreq as F;
                    let cur = d.get(t, crate::event::REPEAT)?;
                    let custom = cur.as_ref().is_some_and(|r| r.interval != 1 || !r.weekdays.is_empty() || !r.monthdays.is_empty() || r.until.is_some() || r.count.is_some());
                    let mut rep = Vec::new();
                    for (label, f) in [("Once", None), ("Daily", Some(F::Daily)), ("Weekly", Some(F::Weekly)), ("Monthly", Some(F::Monthly)), ("Yearly", Some(F::Yearly))] {
                        let on = cur.as_ref().map(|r| r.freq.clone()) == f && !custom;
                        rep.push(ChipM { label: label.into(), color: None, mark: Mark::Icon(Icon::Recent), flat: !on, open: Act::Repeat(t, f), remove: None });
                    }
                    if custom {
                        rep.push(ChipM { label: "Custom (All fields)".into(), color: None, mark: Mark::Icon(Icon::List), flat: false, open: Act::AllFields, remove: None });
                    }
                    c.blocks.push(Block::Chips(rep));
                }
            }
            Kind::Contact => {
                c.blocks.push(Block::Form(t, d.contact_form(t)?));
            }
            Kind::Tag => {
                let (subs, items) = d.tag_contents(t)?;
                if !subs.is_empty() {
                    c.label("Tags inside");
                    c.tiles(tiles(d, &subs)?, Grid::Cards);
                }
                c.label("Items");
                if items.is_empty() {
                    c.line("Nothing tagged yet.");
                }
                c.tiles(tiles(d, &items)?, Grid::Cards);
                return Ok(c);
            }
            Kind::View(View::Calendar) => {
                use crate::time::{DAY, monday_of, now_local};
                let now = now_local();
                let monday = monday_of(now) + self.view.week * 7 * DAY;
                let w = self.view.week;
                c.blocks.push(Block::Chips(vec![
                    ChipM::action(Icon::Back, "Earlier", Act::Week(w - 1)),
                    ChipM::action(Icon::Calendar, "This week", Act::Week(0)),
                    ChipM::action(Icon::Plus, "Later", Act::Week(w + 1)),
                ]));
                c.label(&format!("{} – {}", crate::data::fmt_day(monday / DAY), crate::data::fmt_day(monday / DAY + 6)));
                let mut days = Vec::new();
                for (day, evs) in d.week(monday)? {
                    let mut ts = Vec::new();
                    for x in evs {
                        let mut tile = d.tile(x.tid)?;
                        let place = d.get(x.tid, crate::event::LOCATION)?.filter(|p| !p.is_empty());
                        // a timed event from an earlier day: until its end, or all day when it goes on
                        let mut time = if x.all_day || (x.start < day && x.end >= day + DAY) {
                            "All day".to_string()
                        } else if x.start < day {
                            format!("Until {}", crate::data::fmt_time(x.end))
                        } else {
                            crate::data::fmt_time(x.start)
                        };
                        if x.repeats {
                            time.push_str(" ↻");
                        }
                        tile.sub = match place {
                            Some(p) => format!("{time} · {p}"),
                            None => time,
                        };
                        ts.push(tile);
                    }
                    days.push((crate::data::fmt_day(day / DAY), now.div_euclid(DAY) == day / DAY, ts));
                }
                c.blocks.push(Block::Days(days));
                return Ok(c);
            }
            Kind::View(View::Tags) => {
                let tree = d.tag_tree()?;
                if tree.is_empty() {
                    c.line("No tags yet.");
                }
                c.tiles(tiles(d, &tree.iter().map(|(g, _)| *g).collect::<Vec<_>>())?, Grid::Cards);
                for (g, subs) in &tree {
                    if !subs.is_empty() {
                        c.label(&format!("In {}", d.name(*g)?));
                        c.tiles(tiles(d, subs)?, Grid::Rows);
                    }
                }
                return Ok(c);
            }
            Kind::View(v) => {
                let items = d.view_items(&v)?;
                if items.is_empty() {
                    c.line("Nothing here yet.");
                }
                let grid = if v == View::Recent { Grid::Rows } else { Grid::Cards };
                let mut ts = tiles(d, &items)?;
                if v == View::Recent {
                    for tile in &mut ts {
                        tile.sub = d.edited(tile.tid);
                    }
                }
                c.tiles(ts, grid);
                return Ok(c);
            }
            Kind::Note => {}
        }
        // tags: chips, removable, then "+ Tag" or the picker
        let tags = d.tags_of(t)?;
        let mut chips = Vec::new();
        for g in &tags {
            chips.push(ChipM { label: d.name(*g)?, color: d.own_color(*g)?, mark: Mark::Dot, flat: false, open: Act::Open(*g), remove: Some(Act::RemoveTag(t, *g)) });
        }
        chips.push(ChipM::action(Icon::Plus, if self.view.picker { "Done" } else { "Tag" }, Act::Picker));
        c.blocks.push(Block::Chips(chips));
        if let Some((pt, g, who)) = &self.view.pending
            && *pt == t
        {
            // the grant is write capped by each member's role on the tag (Data::add_tag)
            let g = d.name(*g)?;
            c.line(format!("{g} is shared with {who}. Tag it there? They will see it, and whoever can edit {g} can edit it too."));
            c.blocks.push(Block::Chips(vec![ChipM::action(Icon::Tag, "Tag and share", Act::Confirm), ChipM::action(Icon::Back, "Cancel", Act::Cancel)]));
        } else if self.view.picker {
            let others: Vec<Tid> = d.all_tags()?.into_iter().filter(|g| !tags.contains(g) && *g != t).collect();
            c.label("Add a tag");
            if others.is_empty() {
                c.line("No other tags yet.");
            }
            let mut chips = Vec::new();
            for g in others {
                chips.push(ChipM { label: d.name(g)?, color: d.own_color(g)?, mark: Mark::Dot, flat: false, open: Act::AddTag(t, g), remove: None });
            }
            c.blocks.push(Block::Chips(chips));
        }
        Ok(c)
    }

    /// Below a thing: who can see it, when it changed, undo.
    pub(super) fn meta_content(&self, t: Tid) -> osis::Result<Content> {
        let d = &self.data;
        let mut c = Content::default();
        if matches!(d.kind(t)?, Kind::View(_)) {
            return Ok(c);
        }
        let r = d.reach(t)?;
        let mut who = r.who();
        if !r.via.is_empty() {
            let via: osis::Result<Vec<String>> = r.via.iter().map(|g| d.name(*g)).collect();
            who = format!("{who} · via {}", via?.join(", "));
        }
        c.blocks.push(Block::Chips(vec![ChipM::action(Icon::Eye, &who, Act::None), ChipM::action(Icon::Clock, &d.edited(t), Act::None), ChipM::action(Icon::Back, "Undo", Act::Undo(t))]));
        Ok(c)
    }

    /// The widgets for `c`; registers what presses do.
    pub(super) fn content_widget(&mut self, c: &Content, current: Option<Tid>) -> NewWidget<dyn Widget> {
        let look = self.look.clone();
        let mut col = Flex::column().cross_axis_alignment(CrossAxisAlignment::Fill).with_gap(Length::px(look.sp(8.0)));
        for b in &c.blocks {
            match b {
                Block::Line(s) => col = col.with_child(style::label(&look, s, Text::Muted)),
                Block::Label(s) => col = col.with_child(style::label(&look, s, Text::Section)),
                Block::Tiles { tiles, grid, new, favorites } => {
                    if tiles.is_empty() && !new {
                        continue;
                    }
                    let (min, cols, gap, style) = match grid {
                        Grid::Rail => (100.0, 1, 3.0, TileStyle::Row),
                        Grid::Rows => (220.0, 0, 4.0, TileStyle::Row),
                        Grid::Cards => (158.0, 0, 12.0, TileStyle::Card),
                    };
                    let mut g = TileGrid::new(look.clone(), min).max_cols(cols).gap(gap);
                    for t in tiles {
                        let w = NewWidget::new(osis_kit::widgets::Tile::new(style, icon_of(t), &t.name, &t.sub, t.color.as_deref().and_then(parse), look.clone()).current(current == Some(t.tid)));
                        self.acts.insert(w.id(), Act::Open(t.tid));
                        g = g.with_child(w);
                    }
                    if *favorites {
                        g = g.reorderable(usize::from(*new));
                    }
                    if *new {
                        let w = NewWidget::new(osis_kit::widgets::Tile::new(TileStyle::New, TileIcon::Icon(Icon::Plus), "New", "Note, event, person, tag", None, look.clone()));
                        self.acts.insert(w.id(), Act::New);
                        g = g.with_child(w);
                    }
                    let g = NewWidget::new(g);
                    if *favorites {
                        self.acts.insert(g.id(), Act::None);
                        self.reorder_grids.insert(g.id());
                    }
                    col = col.with_child(g);
                }
                Block::Days(days) => {
                    let mut g = TileGrid::new(look.clone(), 118.0).max_cols(7).gap(8.0);
                    for (label, today, evs) in days {
                        let mut day = Flex::column().cross_axis_alignment(CrossAxisAlignment::Fill).with_gap(Length::px(look.sp(4.0)));
                        day = day.with_child(style::label(&look, label, if *today { Text::Body } else { Text::Muted }));
                        if evs.is_empty() {
                            day = day.with_child(style::label(&look, "Free", Text::Small));
                        }
                        for t in evs {
                            let w = NewWidget::new(osis_kit::widgets::Tile::new(TileStyle::Row, TileIcon::Bar, &t.name, &t.sub, t.color.as_deref().and_then(parse), look.clone()));
                            self.acts.insert(w.id(), Act::Open(t.tid));
                            day = day.with_child(w);
                        }
                        let kind = if *today { PanelKind::Highlight } else { PanelKind::Inset };
                        g = g.with_child(NewWidget::new(Panel::new(NewWidget::new(day), look.clone(), kind, (10.0, 8.0))));
                    }
                    col = col.with_child(NewWidget::new(g));
                }
                Block::Fields(t, rows) => {
                    for r in rows {
                        let indent = look.sp(16.0) * r.depth as f64;
                        let label = Flex::column()
                            .cross_axis_alignment(CrossAxisAlignment::Start)
                            .with_child(style::label(&look, &r.label, Text::Muted))
                            .with_child(style::label(&look, &r.ty, Text::Small));
                        let label = NewWidget::new_with_props(label, osis_kit::masonry::core::Properties::new().with(osis_kit::masonry::properties::Padding { left: indent, right: 0.0, top: 0.0, bottom: 0.0 }));
                        let value: NewWidget<dyn Widget> = if r.edit == crate::fields::Edit::None {
                            style::label(&look, &r.value, Text::Body).erased()
                        } else {
                            let (input, id) = style::input(&look, &r.value, if r.optional { "none" } else { "" }, Text::Body, false);
                            self.form_input(id, *t, crate::fields::FormAct::Field(r.clone()), &r.value, input).erased()
                        };
                        let row = Flex::row()
                            .cross_axis_alignment(CrossAxisAlignment::Center)
                            .with_gap(Length::px(look.sp(12.0)))
                            .with_child(NewWidget::new(osis_kit::masonry::widgets::SizedBox::new(label).width(Length::px(220.0))))
                            .with_flex_child(value, 1.0);
                        col = col.with_child(NewWidget::new(row));
                    }
                }
                Block::Form(t, rows) => {
                    for r in rows {
                        let (input, id) = style::input(&look, &r.value, &r.placeholder, Text::Body, false);
                        let field = self.form_input(id, *t, r.act.clone(), &r.value, input);
                        let row = Flex::row()
                            .cross_axis_alignment(CrossAxisAlignment::Center)
                            .with_gap(Length::px(look.sp(12.0)))
                            .with_child(NewWidget::new(osis_kit::masonry::widgets::SizedBox::new(style::label(&look, &r.label, Text::Muted)).width(Length::px(120.0))))
                            .with_flex_child(field, 1.0);
                        col = col.with_child(NewWidget::new(row));
                    }
                }
                Block::Chips(chips) => {
                    let mut wrap = Wrap::new(look.clone());
                    for m in chips {
                        let mark = match m.mark {
                            Mark::Dot => ChipMark::Dot,
                            Mark::Icon(i) => ChipMark::Icon(i),
                        };
                        let w = NewWidget::new(Chip::new(&m.label, m.color.as_deref().and_then(parse), mark, look.clone()).flat(m.flat).removable(m.remove.is_some()));
                        self.acts.insert(w.id(), m.open.clone());
                        if let Some(r) = &m.remove {
                            self.remove_acts.insert(w.id(), r.clone());
                        }
                        wrap = wrap.with_child(w);
                    }
                    col = col.with_child(NewWidget::new(wrap));
                }
            }
        }
        NewWidget::new(col).erased()
    }
}

impl Ui {
    /// A form field: the input in a field panel that reports losing focus; registers what it
    /// saves and its place in the slot being built (for keeping the focus across a rebuild).
    fn form_input(&mut self, id: osis_kit::masonry::core::WidgetId, t: Tid, act: crate::fields::FormAct, value: &str, input: NewWidget<osis_kit::masonry::widgets::TextInput>) -> NewWidget<Panel> {
        let panel = NewWidget::new(Panel::new(input, self.look.clone(), PanelKind::Field, (5.0, 8.0)).report_blur(true));
        self.field_inputs.insert(id, super::FormInput { t, act, saved: value.to_string(), text: value.to_string() });
        self.blur_panels.insert(panel.id(), id);
        self.building_inputs.push(id);
        panel
    }
}

pub fn icon_of(t: &Tile) -> TileIcon {
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
