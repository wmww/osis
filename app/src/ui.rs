//! The notes window (Masonry): list of notes on the left, editor on the right. Everything shown
//! comes from osis: watches post into the kit mailbox, the UI thread re-reads and reconciles the
//! widgets. Widgets keep only the text being typed (sent on into osis text sessions).

use crate::notes::Notes;
use crate::schema::SELECTED;
use osis::core::{GROUP, NAME};
use osis::{Osis, Path, Subscription, TextSession, Tid};
use osis_kit::list::{KeyedList, Rows, reconcile};
use osis_kit::marshal::{Inbox, Mailbox};
use osis_kit::masonry::core::{ErasedAction, NewWidget, Properties, Widget, WidgetId, WidgetMut, WidgetTag};
use osis_kit::masonry::properties::Padding;
use osis_kit::masonry::properties::types::{CrossAxisAlignment, Length};
use osis_kit::masonry::widgets::{Button, ButtonPress, Flex, Label, Portal, SizedBox, Split, TextAction, TextArea, TextInput};
use osis_kit::masonry_winit::app::{AppDriver, DriverCtx, WindowId};
use osis_kit::theme::Theme;
use osis_kit::widgets;
use osis_kit::window::Wakeup;
use std::collections::BTreeMap;

const LIST: WidgetTag<Flex> = WidgetTag::new("notes-list");
const NAME_AREA: WidgetTag<TextArea<true>> = WidgetTag::new("note-name");
const BODY_AREA: WidgetTag<TextArea<true>> = WidgetTag::new("note-body");
const STATUS: WidgetTag<Label> = WidgetTag::new("status");

/// What a watch says changed; the UI re-reads osis for all of them.
#[derive(Debug)]
pub enum Msg {
    /// Home's items, a notes group, a note's name or the selection changed.
    Changed,
    /// A text session merged a remote edit into the open note's name or body.
    Remote(Tid),
    /// An osis diagnostic (a thing that will not sync, a callback that panicked, ...).
    Diagnostic(String),
}

/// The open note's text sessions: typing goes there, one commit per pause.
struct Editor {
    note: Tid,
    name: TextSession,
    body: TextSession,
}

/// Widget ids the driver dispatches on.
pub struct Ids {
    pub new: WidgetId,
    pub delete: WidgetId,
    pub name: WidgetId,
    pub body: WidgetId,
}

pub struct Ui {
    notes: Notes,
    window: WindowId,
    mb: Mailbox<Msg>,
    inbox: Inbox<Msg>,
    theme: Theme,
    ids: Ids,
    list: KeyedList<Tid>,
    /// The rows as shown: (note, (name, selected)).
    shown: Vec<(Tid, (String, bool))>,
    /// Home's items and diagnostics.
    _subs: Vec<Subscription>,
    /// The last diagnostic, shown in the status line.
    diag: Option<String>,
    group_subs: BTreeMap<Tid, (Subscription, Subscription)>,
    name_subs: BTreeMap<Tid, Subscription>,
    editor: Option<Editor>,
}

fn sub_changed(db: &Osis, t: Tid, key: impl osis::AspectKey + Clone + Send + 'static, mb: &Mailbox<Msg>) -> Option<Subscription> {
    let mb = mb.clone();
    db.at(t, key)
        .on_change(move |_: &Osis, _| {
            mb.post(Msg::Changed);
        })
        .ok()
}

impl Ui {
    pub fn new(notes: Notes, window: WindowId, mb: Mailbox<Msg>, inbox: Inbox<Msg>, theme: Theme, ids: Ids) -> Ui {
        let mut subs: Vec<Subscription> = sub_changed(&notes.db, notes.db.home(), GROUP, &mb).into_iter().collect();
        let m = mb.clone();
        subs.push(notes.db.on_diagnostic(move |_, d| {
            m.post(Msg::Diagnostic(format!("{:?}: {}", d.kind, d.detail)));
        }));
        Ui { notes, window, mb, inbox, theme, ids, list: KeyedList::default(), shown: Vec::new(), _subs: subs, diag: None, group_subs: BTreeMap::new(), name_subs: BTreeMap::new(), editor: None }
    }

    /// Keeps a subscription per key in `want`, dropping the rest.
    fn keep<S>(subs: &mut BTreeMap<Tid, S>, want: &[Tid], mut make: impl FnMut(Tid) -> Option<S>) {
        subs.retain(|t, _| want.contains(t));
        for t in want {
            if !subs.contains_key(t)
                && let Some(s) = make(*t)
            {
                subs.insert(*t, s);
            }
        }
    }

    /// Re-reads osis and brings the widgets to it.
    fn refresh(&mut self, ctx: &mut DriverCtx<'_, '_>) {
        let r = self.refresh_inner(ctx);
        let status = match r {
            Ok(n) => format!("{n} notes · device {}{}", short(self.notes.db.node()), self.diag.as_deref().map(|d| format!(" · {d}")).unwrap_or_default()),
            Err(e) => format!("error: {e}"),
        };
        ctx.render_root(self.window).edit_widget_with_tag(STATUS, |mut l| Label::set_text(&mut l, status));
    }

    fn refresh_inner(&mut self, ctx: &mut DriverCtx<'_, '_>) -> osis::Result<usize> {
        let db = self.notes.db.clone();
        let groups = self.notes.groups()?;
        let mb = self.mb.clone();
        // a group's items and its selection map
        Self::keep(&mut self.group_subs, &groups, |g| {
            let a = sub_changed(&db, g, GROUP, &mb)?;
            let b = sub_changed(&db, g, SELECTED, &mb)?;
            Some((a, b))
        });
        let list = self.notes.list()?;
        let tids: Vec<Tid> = list.iter().map(|(t, _)| *t).collect();
        Self::keep(&mut self.name_subs, &tids, |t| sub_changed(&db, t, NAME, &mb));
        let selected = self.notes.selected()?;
        let new: Vec<(Tid, (String, bool))> = list.into_iter().map(|(t, n)| (t, (n, Some(t) == selected))).collect();
        let ops = reconcile(&self.shown, &new);
        if !ops.is_empty() {
            let mut rows = RowMaker { rows: &new, theme: &self.theme };
            let list = &mut self.list;
            ctx.render_root(self.window).edit_widget_with_tag(LIST, |mut flex| list.apply(&mut flex, &ops, &mut rows));
        }
        self.shown = new;
        if self.editor.as_ref().map(|e| e.note) != selected {
            self.open(ctx, selected)?;
        }
        Ok(self.shown.len())
    }

    /// Opens `note` in the editor (`None`: empty editor). Dropping the old sessions commits them.
    fn open(&mut self, ctx: &mut DriverCtx<'_, '_>, note: Option<Tid>) -> osis::Result<()> {
        self.editor = None;
        let (name, body) = match note {
            Some(t) => {
                let db = &self.notes.db;
                let name = db.edit_text(t, NAME, Path::root())?;
                let body = db.edit_text(t, osis::core::BODY, Path::root())?;
                let mb = self.mb.clone();
                name.on_remote(move |_| {
                    mb.post(Msg::Remote(t));
                });
                let mb = self.mb.clone();
                body.on_remote(move |_| {
                    mb.post(Msg::Remote(t));
                });
                let texts = (name.text(), body.text());
                self.editor = Some(Editor { note: t, name, body });
                texts
            }
            None => (String::new(), String::new()),
        };
        self.show_text(ctx, &name, &body);
        Ok(())
    }

    fn show_text(&mut self, ctx: &mut DriverCtx<'_, '_>, name: &str, body: &str) {
        let root = ctx.render_root(self.window);
        root.edit_widget_with_tag(NAME_AREA, |mut a| reset_if_differs(&mut a, name));
        root.edit_widget_with_tag(BODY_AREA, |mut a| reset_if_differs(&mut a, body));
    }

    fn report(&mut self, ctx: &mut DriverCtx<'_, '_>, r: osis::Result<()>) {
        if let Err(e) = r {
            ctx.render_root(self.window).edit_widget_with_tag(STATUS, |mut l| Label::set_text(&mut l, format!("error: {e}")));
        }
    }
}

fn reset_if_differs(a: &mut WidgetMut<'_, TextArea<true>>, text: &str) {
    if a.widget.text() != text {
        TextArea::reset_text(a, text);
    }
}

/// The first 8 hex digits of a tid, for the status line.
fn short(t: Tid) -> String {
    t.to_string().chars().take(8).collect()
}

/// Writes the user's change `old -> new` into a session as one splice (common prefix and suffix
/// kept, char indices).
fn splice(s: &TextSession, new: &str) -> osis::Result<()> {
    let old = s.text();
    if old == new {
        return Ok(());
    }
    let o: Vec<char> = old.chars().collect();
    let n: Vec<char> = new.chars().collect();
    let pre = o.iter().zip(&n).take_while(|(a, b)| a == b).count();
    let suf = o.iter().rev().zip(n.iter().rev()).take(o.len().min(n.len()) - pre).take_while(|(a, b)| a == b).count();
    let ins: String = n.get(pre..n.len() - suf).unwrap_or_default().iter().collect();
    s.replace(pre..o.len() - suf, &ins)
}

struct RowMaker<'a> {
    rows: &'a [(Tid, (String, bool))],
    theme: &'a Theme,
}

impl RowMaker<'_> {
    fn of(&self, t: &Tid) -> (String, bool) {
        let (name, sel) = self.rows.iter().find(|(k, _)| k == t).map(|(_, v)| v.clone()).unwrap_or_default();
        (if name.is_empty() { "(untitled)".into() } else { name }, sel)
    }
}

impl Rows<Tid> for RowMaker<'_> {
    fn make(&mut self, key: &Tid) -> NewWidget<dyn Widget> {
        let (name, sel) = self.of(key);
        widgets::row(&name, sel, self.theme).erased()
    }
    fn update(&mut self, key: &Tid, row: WidgetMut<'_, dyn Widget>) {
        let (name, sel) = self.of(key);
        widgets::set_row(row, &name, sel, self.theme);
    }
}

impl AppDriver for Ui {
    /// The window exists now: wakes posted before it were dropped by masonry_winit, so start the
    /// mailbox over and refresh once.
    fn on_start(&mut self, _state: &mut osis_kit::masonry_winit::app::MasonryState<'_>) {
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
                    Msg::Remote(t) => {
                        if let Some(e) = self.editor.as_ref().filter(|e| e.note == t) {
                            let (n, b) = (e.name.text(), e.body.text());
                            self.show_text(ctx, &n, &b);
                        }
                    }
                }
            }
            if changed {
                self.refresh(ctx);
            }
        } else if action.is::<ButtonPress>() {
            let r = if id == self.ids.new {
                self.notes.create("").map(|_| ())
            } else if id == self.ids.delete {
                match self.editor.as_ref().map(|e| e.note) {
                    // close the editor first: its sessions commit pending typing on drop, which
                    // after the delete would recreate the note
                    Some(t) => self.open(ctx, None).and_then(|()| self.notes.delete(t)),
                    None => Ok(()),
                }
            } else if let Some(t) = self.list.key_of(id).copied() {
                self.notes.select(Some(t))
            } else {
                Ok(())
            };
            self.report(ctx, r);
        } else if let Ok(a) = action.downcast::<TextAction>() {
            let TextAction::Changed(text) = *a else { return };
            let r = match &self.editor {
                Some(e) if id == self.ids.name => splice(&e.name, &text),
                Some(e) if id == self.ids.body => splice(&e.body, &text),
                _ => Ok(()),
            };
            self.report(ctx, r);
        }
    }
}

/// The widget tree and the ids the driver needs.
pub fn tree(theme: &Theme) -> (NewWidget<dyn Widget>, Ids) {
    let gap = Length::px(theme.gap);
    let pad = || Properties::new().with(Padding::all(theme.pad));
    let new = NewWidget::new(Button::with_text("New note"));
    let delete = NewWidget::new(Button::with_text("Delete"));
    let name = NewWidget::new_with_tag(TextArea::new_editable(""), NAME_AREA);
    let body = NewWidget::new_with_tag(TextArea::new_editable("").with_insert_newline(osis_kit::masonry::widgets::InsertNewline::OnEnter), BODY_AREA);
    let ids = Ids { new: new.id(), delete: delete.id(), name: name.id(), body: body.id() };
    let list = NewWidget::new_with_tag(Flex::column().with_gap(gap).cross_axis_alignment(CrossAxisAlignment::Fill), LIST);
    let left = Flex::column()
        .cross_axis_alignment(CrossAxisAlignment::Fill)
        .with_gap(gap)
        .with_child(new)
        .with_flex_child(NewWidget::new(Portal::new(list).constrain_horizontal(true).content_must_fill(true)), 1.0);
    let name_input = NewWidget::new(TextInput::from_text_area(name).with_placeholder("Name"));
    let body = NewWidget::new(TextInput::from_text_area(body).with_placeholder("Body"));
    let right = Flex::column()
        .cross_axis_alignment(CrossAxisAlignment::Fill)
        .with_gap(gap)
        .with_child(NewWidget::new(Flex::row().with_gap(gap).with_flex_child(name_input, 1.0).with_child(delete)))
        .with_flex_child(NewWidget::new(SizedBox::new(body).expand()), 1.0)
        .with_child(NewWidget::new_with_tag(Label::new("").with_hint(true), STATUS));
    let split = Split::new(NewWidget::new_with_props(left, pad()), NewWidget::new_with_props(right, pad())).split_point(0.3);
    (NewWidget::new(split).erased(), ids)
}
