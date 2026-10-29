//! Building whole screens: home, and an open thing with its rail (wide) or back button (narrow).

use super::content::{Content, icon_of};
use super::{Act, FieldKey, HOME_BODY, META, PANE_EXTRA, RAIL_LIST, RAIL_NEW, Ui, kit_mode};
use crate::data::Kind;
use crate::schema::Mode as ModeChoice;
use osis::Tid;
use osis_kit::icons::Icon;
use osis_kit::masonry::core::{NewWidget, Properties, Widget};
use osis_kit::masonry::properties::Padding;
use osis_kit::masonry::properties::types::{CrossAxisAlignment, Length};
use osis_kit::masonry::widgets::{Flex, Label, Portal, SizedBox};
use osis_kit::theme::Theme;
use osis_kit::widgets::style::{self, Text};
use osis_kit::widgets::{IconButton, Limit, Panel, PanelKind, TileGrid, TileIcon, TileStyle};

impl Ui {
    /// An empty slot named `key`, filled by `slot`.
    pub(super) fn slot_widget(&mut self, key: &'static str) -> NewWidget<SizedBox> {
        let w = NewWidget::new(SizedBox::empty());
        self.slots.insert(key, (w.id(), None::<Content>));
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
        let (input, id) = style::input(&look, &self.query, if big { "Search notes, people, tags, views…" } else { "Search" }, Text::Body, false);
        self.search_ids.push(id);
        let pad = if big { (14.0, 18.0) } else { (8.0, 12.0) };
        NewWidget::new(Panel::new(input, look, PanelKind::Field, pad)).erased()
    }

    pub(super) fn home(&mut self) -> NewWidget<dyn Widget> {
        let look = self.look.clone();
        let col = Flex::column()
            .cross_axis_alignment(CrossAxisAlignment::Fill)
            .with_gap(Length::px(look.sp(18.0)))
            .with_child(style::label(&look, "osis", Text::Brand))
            .with_child(self.search_field(true))
            .with_child(self.slot_widget(HOME_BODY))
            .with_child(self.look_picker())
            .with_child(self.status_widget());
        let col = NewWidget::new_with_props(col, Properties::new().with(Padding::from_vh(look.sp(48.0), look.sp(16.0))));
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
            let tint = osis_kit::theme::mix(th.surface.of(look.dark), th.background.of(!look.dark), 0.7);
            let w = NewWidget::new(osis_kit::widgets::Tile::new(TileStyle::Row, TileIcon::Initials(th.name.chars().take(1).collect()), th.name, "", Some(tint), look.clone()).current(th.id == self.theme.id));
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

    pub(super) fn thing(&mut self, t: Tid) -> osis::Result<NewWidget<dyn Widget>> {
        let look = self.look.clone();
        let sp = |x: f64| look.sp(x);
        let tile = self.data.tile(t)?;
        // the bar: back (narrow), what it is, favorite, delete
        let mut bar = Flex::row().with_gap(Length::px(sp(8.0)));
        if self.narrow {
            let b = NewWidget::new(IconButton::new(Icon::Back, "Home", look.clone()));
            bar = bar.with_child(self.act(b, Act::Home));
        }
        let kind_label = match &tile.kind {
            Kind::Event if !self.data.body(t)?.is_empty() => "Event · Note",
            k => k.label(),
        };
        bar = bar.with_child(style::label(&look, kind_label, Text::Muted)).with_flex_spacer(1.0);
        let fav = self.data.is_favorite(t)?;
        let star = NewWidget::new(IconButton::new(Icon::Star, "Favorite", look.clone()).on(fav));
        self.star = Some(star.id());
        bar = bar.with_child(self.act(star, Act::Favorite(t)));
        if !matches!(tile.kind, Kind::View(_)) {
            let del = NewWidget::new(IconButton::new(Icon::Trash, "Delete", look.clone()));
            bar = bar.with_child(self.act(del, Act::Delete(t)));
        }
        // the body: title, the kind's own fields and content, the text, who and when
        let mut fields = vec![FieldKey::Name];
        if tile.kind == Kind::Event {
            fields.push(FieldKey::Location);
        }
        if matches!(tile.kind, Kind::Note | Kind::Event | Kind::Contact) {
            fields.push(FieldKey::Body);
        }
        self.open_editor(t, &fields)?;
        let extra = self.slot_widget(PANE_EXTRA);
        let meta = self.slot_widget(META);
        let mut body = Flex::column().cross_axis_alignment(CrossAxisAlignment::Fill).with_gap(Length::px(sp(16.0)));
        if let Some(m) = style::title_mark(&look) {
            body = body.with_child(m);
        }
        let contact = tile.kind == Kind::Contact;
        let title = self.field_widget(FieldKey::Name, if contact { "Name" } else { "Untitled" }, Text::Title, false);
        if contact {
            // an avatar in the contact's colour beside the name
            let avatar = NewWidget::new(osis_kit::widgets::Tile::new(TileStyle::Row, icon_of(&tile), "", "", tile.color.as_deref().and_then(osis_kit::theme::parse), look.clone()));
            let row = Flex::row().with_gap(Length::px(sp(4.0))).with_child(NewWidget::new(SizedBox::new(avatar).width(Length::px(46.0)))).with_flex_child(title, 1.0);
            body = body.with_child(NewWidget::new(row));
        } else {
            body = body.with_child(title);
        }
        if fields.contains(&FieldKey::Location) {
            body = body.with_child(self.field_widget(FieldKey::Location, "Where", Text::Muted, false));
        }
        body = body.with_child(extra);
        if fields.contains(&FieldKey::Body) {
            let placeholder = if contact { "Notes about them…" } else { "Write something…" };
            body = body.with_child(self.field_widget(FieldKey::Body, placeholder, Text::Body, true));
        }
        body = body.with_child(meta);
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
        let new = NewWidget::new(osis_kit::widgets::Tile::new(TileStyle::Row, TileIcon::Icon(Icon::Plus), "New", "", None, look.clone()));
        let rail = Flex::column()
            .cross_axis_alignment(CrossAxisAlignment::Fill)
            .with_gap(Length::px(sp(6.0)))
            .with_child(self.act(home, Act::Home))
            .with_child(self.search_field(false))
            .with_child(self.slot_widget(RAIL_LIST))
            .with_child(self.act(new, Act::New))
            .with_child(self.slot_widget(RAIL_NEW))
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

    /// The text input of an open field, its widget id recorded.
    fn field_widget(&mut self, key: FieldKey, placeholder: &str, role: Text, multiline: bool) -> NewWidget<dyn Widget> {
        let look = self.look.clone();
        let Some(f) = self.editor.as_mut().and_then(|e| e.fields.iter_mut().find(|f| f.key == key)) else {
            return NewWidget::new(SizedBox::empty()).erased();
        };
        let (w, id) = style::input(&look, &f.shown, placeholder, role, multiline);
        f.id = Some(id);
        w.erased()
    }
}
