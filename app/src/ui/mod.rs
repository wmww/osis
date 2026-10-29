//! The window (Masonry over kit). Home: search, favorites, new, the look. An open thing: its pane,
//! with a rail (home, search, favorites, new) beside it when the window is wide, else a back
//! button.
//!
//! Everything shown comes from osis through `Data`: watches post into the kit mailbox, the UI
//! thread re-reads and rebuilds what changed. A screen is built whole when the open thing, the
//! width class or the look changes; otherwise only its slots (lists, chips, meta) are rebuilt,
//! and only when their model differs, so the editors keep their caret. Widgets keep only the
//! search text and the text being typed (sent on into osis text sessions); `ViewState` holds the
//! few toggles of the open screen.

mod content;
mod screens;

use crate::data::{Data, NewKind};
use crate::edit::splice;
use crate::schema::Mode as ModeChoice;
use content::Content;
use osis::core::{BODY, NAME};
use osis::{Path, Subscription, TextSession, Tid};
use osis_kit::marshal::{Inbox, Mailbox};
use osis_kit::masonry::core::{ErasedAction, NewWidget, Widget, WidgetId, WidgetTag};
use osis_kit::masonry::widgets::{Label, SizedBox, TextAction, TextArea};
use osis_kit::masonry_winit::app::{AppDriver, DriverCtx, WindowId};
use osis_kit::theme::{Look, Mode, Theme, parse};
use osis_kit::widgets::{Blur, ChipPress, IconButton, Press, Reorder, Root};
use osis_kit::masonry_winit::winit::dpi::PhysicalSize;
use osis_kit::masonry_winit::winit::window::Theme as WinitTheme;
use osis_kit::window::Wakeup;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

pub const ROOT: WidgetTag<Root> = WidgetTag::new("root");

/// Slots: containers whose content is rebuilt when its model changes.
type Slot = (&'static str, WidgetTag<SizedBox>);
const HOME_BODY: Slot = ("home-body", WidgetTag::new("home-body"));
const RAIL_LIST: Slot = ("rail-list", WidgetTag::new("rail-list"));
const RAIL_NEW: Slot = ("rail-new", WidgetTag::new("rail-new"));
const PANE_EXTRA: Slot = ("pane-extra", WidgetTag::new("pane-extra"));
const META: Slot = ("meta", WidgetTag::new("meta"));
/// Holds the status label (a tag cannot be given together with properties).
const STATUS: WidgetTag<SizedBox> = WidgetTag::new("status");
const STAR: WidgetTag<IconButton> = WidgetTag::new("star");

/// Below this width (logical px) an open thing fills the window and home is a back button away.
const NARROW: f64 = 760.0;

/// What a watch says changed; the UI re-reads osis for all of them.
#[derive(Debug)]
pub enum Msg {
    /// Something shown may have changed.
    Changed,
    /// A text session merged a remote edit into the open thing's fields.
    Remote(Tid),
    /// An osis diagnostic (a thing that will not sync, a callback that panicked, ...).
    Diagnostic(String),
}

/// What a press on a widget does.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Act {
    None,
    Theme(&'static str),
    Mode(ModeChoice),
    Open(Tid),
    Home,
    /// Show or hide the kinds to create.
    New,
    Create(NewKind),
    Favorite(Tid),
    Delete(Tid),
    /// Show or hide the tag picker.
    Picker,
    AddTag(Tid, Tid),
    RemoveTag(Tid, Tid),
    Undo(Tid),
    /// Show the week `n` weeks from this one.
    Week(i64),
    /// Move an event (ms) and lengthen it (ms).
    Nudge(Tid, i64, i64),
    /// Show or hide every field (the schema fallback view).
    AllFields,
    Repeat(Tid, Option<crate::event::RepeatFreq>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Screen {
    Home,
    Thing(Tid),
}

/// A form input: what it saves, the value last saved, the text it shows now.
#[derive(Clone, Debug)]
struct FormInput {
    t: Tid,
    act: crate::fields::FormAct,
    saved: String,
    text: String,
}

/// The toggles of the open screen (reset when it changes).
#[derive(Clone, Debug, Default)]
struct ViewState {
    /// The kinds to create are shown.
    creating: bool,
    /// The tag picker is open.
    picker: bool,
    /// The calendar's week, relative to this one.
    week: i64,
    /// The schema fallback view is shown.
    all_fields: bool,
}

/// A text field of the open thing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FieldKey {
    Name,
    Body,
    Location,
}

struct Field {
    key: FieldKey,
    session: TextSession,
    id: Option<WidgetId>,
    /// The text as the widget shows it (a remote merge may be newer).
    shown: String,
}

/// The open thing's text sessions: typing goes there, one commit per pause.
struct Editor {
    tid: Tid,
    fields: Vec<Field>,
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
    view: ViewState,
    /// What each slot of the screen shows now.
    slots: HashMap<&'static str, Content>,
    /// The system's light or dark, for Auto (`None` until first read).
    system_dark: Option<bool>,
    query: String,
    search_ids: Vec<WidgetId>,
    acts: HashMap<WidgetId, Act>,
    /// What the × of a removable chip does.
    remove_acts: HashMap<WidgetId, Act>,
    /// The grids whose `Reorder` reorders the favorites.
    reorder_grids: std::collections::HashSet<WidgetId>,
    /// Form inputs (the fallback view, a contact's fields): what each saves on Enter.
    field_inputs: HashMap<WidgetId, FormInput>,
    /// Form field panels: the input each holds (they report losing focus).
    blur_panels: HashMap<WidgetId, WidgetId>,
    /// Each slot's form inputs in order, and those of the slot being built.
    slot_inputs: HashMap<&'static str, Vec<WidgetId>>,
    building_inputs: Vec<WidgetId>,
    /// Focus the title once the next screen is built (a thing just made).
    focus_title: bool,
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
            view: ViewState::default(),
            slots: HashMap::new(),
            system_dark: None,
            query: String::new(),
            search_ids: Vec::new(),
            acts: HashMap::new(),
            remove_acts: HashMap::new(),
            field_inputs: HashMap::new(),
            blur_panels: HashMap::new(),
            slot_inputs: HashMap::new(),
            building_inputs: Vec::new(),
            reorder_grids: Default::default(),
            focus_title: false,
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

    fn dark(&mut self, ctx: &mut DriverCtx<'_, '_>) -> bool {
        match self.mode {
            Mode::Light => false,
            Mode::Dark => true,
            Mode::Auto => *self.system_dark.get_or_insert_with(|| ctx.window(self.window).handle().theme() == Some(WinitTheme::Dark)),
        }
    }

    /// Whether the window is narrow now (logical width).
    fn is_narrow(&mut self, ctx: &mut DriverCtx<'_, '_>) -> bool {
        let w = ctx.window(self.window);
        let scale = w.handle().scale_factor();
        let size = w.render_root().size();
        f64::from(size.width) / scale.max(0.1) < NARROW
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
        self.narrow = self.is_narrow(ctx);
        let screen = match self.data.opened()? {
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
        if self.built.map(|b| b.0) != Some(screen) {
            self.view = ViewState::default();
        }
        let rebuild = force || self.built != Some((screen, self.narrow)) || look != *self.look;
        if rebuild {
            self.look = Arc::new(look);
            self.build(ctx, screen)?;
        }
        self.fill_slots(ctx, screen)?;
        if rebuild {
            // focus rule: a new screen puts the keyboard in a text field (home's search, a new
            // thing's title) or nowhere, never on a tile the user did not choose by Tab
            let id = match screen {
                Screen::Home => self.search_ids.first().copied(),
                Screen::Thing(_) if std::mem::take(&mut self.focus_title) => self.editor.as_ref().and_then(|e| e.fields.iter().find(|f| f.key == FieldKey::Name)).and_then(|f| f.id),
                Screen::Thing(_) => None,
            };
            ctx.render_root(self.window).focus_on(id);
        }
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
        if root.get_widget_with_tag(STATUS).is_some() {
            root.edit_widget_with_tag(STATUS, |mut b| {
                if let Some(mut l) = SizedBox::child_mut(&mut b) {
                    Label::set_text(&mut l.downcast(), s);
                }
            });
        }
    }

    fn build(&mut self, ctx: &mut DriverCtx<'_, '_>, screen: Screen) -> osis::Result<()> {
        self.acts.clear();
        self.remove_acts.clear();
        self.field_inputs.clear();
        self.blur_panels.clear();
        self.slot_inputs.clear();
        self.reorder_grids.clear();
        self.slots.clear();
        self.search_ids.clear();
        if self.editor.as_ref().map(|e| Screen::Thing(e.tid)) != Some(screen) {
            // dropping the sessions commits pending typing
            self.editor = None;
        }
        let w = match screen {
            Screen::Home => self.home(),
            Screen::Thing(t) => self.thing(t)?,
        };
        // the background's arrangement: from the thing, varied by its kind
        let seed = match screen {
            Screen::Home => 0,
            Screen::Thing(t) => seed_of(&t.to_string()) ^ seed_of(&format!("{:?}", self.data.kind(t)?)).rotate_left(17),
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

    fn fill_slots(&mut self, ctx: &mut DriverCtx<'_, '_>, screen: Screen) -> osis::Result<()> {
        match screen {
            Screen::Home => {
                let c = self.list_content(false)?;
                self.slot(ctx, HOME_BODY, c, None);
            }
            Screen::Thing(t) => {
                if !self.narrow {
                    let c = self.list_content(true)?;
                    self.slot(ctx, RAIL_LIST, c, Some(t));
                    let c = self.rail_new_content();
                    self.slot(ctx, RAIL_NEW, c, None);
                }
                let c = self.extra_content(t)?;
                self.slot(ctx, PANE_EXTRA, c, None);
                let c = self.meta_content(t)?;
                self.slot(ctx, META, c, None);
                let fav = self.data.is_favorite(t)?;
                let root = ctx.render_root(self.window);
                if root.get_widget_with_tag(STAR).is_some() {
                    root.edit_widget_with_tag(STAR, |mut w| IconButton::set_on(&mut w, fav));
                }
            }
        }
        Ok(())
    }

    /// Shows `c` in the slot `tag` (if the screen has it) unless it already does.
    fn slot(&mut self, ctx: &mut DriverCtx<'_, '_>, (key, tag): Slot, c: Content, current: Option<Tid>) {
        if ctx.render_root(self.window).get_widget_with_tag(tag).is_none() || self.slots.get(key) == Some(&c) {
            return;
        }
        // a form input of this slot that has the focus keeps it across the rebuild (by place)
        let focused = ctx.render_root(self.window).focused_widget();
        let place = focused.and_then(|f| self.slot_inputs.get(key).and_then(|v| v.iter().position(|i| *i == f)));
        self.building_inputs.clear();
        let w = self.content_widget(&c, current);
        let inputs = std::mem::take(&mut self.building_inputs);
        let root = ctx.render_root(self.window);
        root.edit_widget_with_tag(tag, |mut b| SizedBox::set_child(&mut b, w));
        if let Some(id) = place.and_then(|p| inputs.get(p).copied())
            && root.focus_on(Some(id))
        {
            root.edit_widget(id, |mut w| {
                let mut a = w.downcast::<TextArea<true>>();
                let end = a.widget.text().to_string().len();
                TextArea::select_byte_range(&mut a, end, end);
            });
        }
        self.slot_inputs.insert(key, inputs);
        self.slots.insert(key, c);
    }

    /// Saves a form input's text unless it is what was saved last.
    fn save_input(&mut self, ctx: &mut DriverCtx<'_, '_>, id: WidgetId) {
        let Some(f) = self.field_inputs.get_mut(&id) else { return };
        if f.text.trim() == f.saved.trim() {
            return;
        }
        let (t, act, text) = (f.t, f.act.clone(), f.text.clone());
        match self.data.form_apply(t, &act, &text) {
            Ok(()) => {
                // only once written: a rejected text is reported again on the next Enter or blur
                if let Some(f) = self.field_inputs.get_mut(&id) {
                    f.saved = text;
                }
                self.refresh(ctx, false)
            }
            Err(e) => self.status(ctx, format!("error: {e}")),
        }
    }

    /// Text sessions on `t`'s fields; kept if `t` is already open with the same fields.
    fn open_editor(&mut self, t: Tid, keys: &[FieldKey]) -> osis::Result<()> {
        if let Some(e) = self.editor.as_mut()
            && e.tid == t
            && e.fields.iter().map(|f| f.key).eq(keys.iter().copied())
        {
            for f in &mut e.fields {
                f.shown = f.session.text();
                f.id = None;
            }
            return Ok(());
        }
        self.editor = None;
        let db = &self.data.db;
        let mut fields = Vec::new();
        for key in keys {
            let session = match key {
                FieldKey::Name => db.edit_text(t, NAME, Path::root())?,
                FieldKey::Body => db.edit_text(t, BODY, Path::root())?,
                FieldKey::Location => db.edit_text(t, crate::event::LOCATION, Path::root())?,
            };
            let mb = self.mb.clone();
            session.on_remote(move |_| {
                mb.post(Msg::Remote(t));
            });
            fields.push(Field { key: *key, shown: session.text(), session, id: None });
        }
        self.editor = Some(Editor { tid: t, fields });
        Ok(())
    }

    // ---- input

    fn press(&mut self, ctx: &mut DriverCtx<'_, '_>, a: Act) {
        let mut force = false;
        let r = match a {
            Act::None => Ok(()),
            Act::Open(t) => {
                self.query.clear();
                self.data.set_open(Some(t))
            }
            Act::Home => self.data.set_open(None),
            Act::New => {
                self.view.creating = !self.view.creating;
                Ok(())
            }
            Act::Create(k) => {
                self.query.clear();
                self.view.creating = false;
                self.focus_title = true;
                self.data.create(k).map(|_| ())
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
            Act::Picker => {
                self.view.picker = !self.view.picker;
                Ok(())
            }
            // tagging places or nests only; sharing through a tag waits on issues/tag-sharing-op.md
            Act::AddTag(t, g) => self.data.add_tag(t, g),
            Act::RemoveTag(t, g) => self.data.remove_tag(t, g),
            Act::Week(n) => {
                self.view.week = n;
                Ok(())
            }
            Act::Nudge(t, by, longer) => self.data.nudge(t, by, longer),
            Act::Repeat(t, f) => self.data.set_repeat(t, f),
            Act::AllFields => {
                self.view.all_fields = !self.view.all_fields;
                // the bar's toggle shows the state
                force = true;
                Ok(())
            }
            Act::Undo(t) => {
                // the sessions hold the text before the undo: reopen them
                self.editor = None;
                force = true;
                self.data.undo(t).map(|_| ())
            }
        };
        if let Err(e) = r {
            self.status(ctx, format!("error: {e}"));
        }
        self.refresh(ctx, force);
    }

    fn typed(&mut self, ctx: &mut DriverCtx<'_, '_>, id: WidgetId, a: TextAction) {
        if self.search_ids.contains(&id) {
            match a {
                TextAction::Changed(q) => {
                    self.query = q;
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
        if let Some(f) = self.field_inputs.get_mut(&id) {
            // saved on Enter and when the focus leaves the field
            match a {
                TextAction::Changed(text) => f.text = text,
                TextAction::Entered(text) => {
                    f.text = text;
                    self.save_input(ctx, id);
                }
            }
            return;
        }
        let TextAction::Changed(text) = a else { return };
        let Some(f) = self.editor.as_mut().and_then(|e| e.fields.iter_mut().find(|f| f.id == Some(id))) else { return };
        let r = splice(&f.session, &std::mem::replace(&mut f.shown, text.clone()), &text);
        if let Err(e) = r {
            self.status(ctx, format!("error: {e}"));
        }
    }

    /// A remote merge into the open thing's sessions: show it.
    fn remote(&mut self, ctx: &mut DriverCtx<'_, '_>, t: Tid) {
        let Some(e) = self.editor.as_mut().filter(|e| e.tid == t) else { return };
        let root = ctx.render_root(self.window);
        for f in &mut e.fields {
            let text = f.session.text();
            f.shown = text.clone();
            if let Some(id) = f.id
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
    /// The window exists now: register the fonts; wakes posted before it were dropped by
    /// masonry_winit, so start the mailbox over and refresh once.
    fn on_start(&mut self, state: &mut osis_kit::masonry_winit::app::MasonryState<'_>) {
        osis_kit::fonts::register(state);
        self.inbox.drain();
        self.mb.post(Msg::Changed);
    }

    /// A new width class rebuilds the screen (`refresh` compares it).
    fn on_resized(&mut self, _w: WindowId, ctx: &mut DriverCtx<'_, '_>, _size: PhysicalSize<u32>) {
        if self.built.is_some() && self.is_narrow(ctx) != self.narrow {
            self.refresh(ctx, false);
        }
    }

    /// Auto follows the system's light or dark.
    fn on_theme_changed(&mut self, _w: WindowId, ctx: &mut DriverCtx<'_, '_>, theme: WinitTheme) {
        self.system_dark = Some(theme == WinitTheme::Dark);
        if self.mode == Mode::Auto {
            self.refresh(ctx, false);
        }
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
        } else if action.is::<Press>() {
            if let Some(a) = self.acts.get(&id).cloned() {
                self.press(ctx, a);
            }
        } else if action.is::<Blur>() {
            if let Some(input) = self.blur_panels.get(&id).copied() {
                self.save_input(ctx, input);
            }
        } else if let Some(Reorder { from, to }) = action.downcast_ref::<Reorder>().copied() {
            if self.reorder_grids.contains(&id) {
                if let Err(e) = self.data.move_favorite(from, to) {
                    self.status(ctx, format!("error: {e}"));
                }
                self.refresh(ctx, false);
            }
        } else if let Some(p) = action.downcast_ref::<ChipPress>().copied() {
            let a = match p {
                ChipPress::Open => self.acts.get(&id).cloned(),
                ChipPress::Remove => self.remove_acts.get(&id).cloned(),
            };
            if let Some(a) = a {
                self.press(ctx, a);
            }
        } else if let Ok(a) = action.downcast::<TextAction>() {
            self.typed(ctx, id, *a);
        }
    }
}

/// The initial widget tree: the root over an empty screen (the first refresh builds it).
pub fn tree(look: Arc<Look>) -> NewWidget<dyn Widget> {
    NewWidget::new_with_tag(Root::new(NewWidget::new(SizedBox::empty()), look), ROOT).erased()
}
