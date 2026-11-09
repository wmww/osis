//! The toolkit-free model of what the window shows (notes/app.md Code shape): `Block`, the `Action`
//! and `Facet` traits, `Cx`, and per-window memory. A test reads a whole page as a value.

pub mod arrange;
pub mod db;
pub mod graph;
pub mod registry;
pub mod search;
pub mod sessions;
pub mod source;

use crate::store::{Data, Reader};
use osis::{Result, Tid};
pub use crate::icons::Icon;
pub use db::{At, Db};
pub use graph::{Graph, Local};
use sessions::Sessions;
use std::any::Any;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fmt::Debug;
use std::ops::Deref;
use std::rc::Rc;

// ---- actions

/// What the user did to a widget carrying an action.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Input {
    Press,
    Text(String),
    Reorder { from: usize, to: usize },
}

/// Something a press or a typed value does; compared by value so a model stays comparable.
pub trait Action: Clone + PartialEq + Debug + 'static {
    fn run(&self, act: &Act, input: &Input) -> Result<()>;
}

trait ErasedAction: Debug {
    fn run_erased(&self, act: &Act, input: &Input) -> Result<()>;
    fn eq_erased(&self, other: &dyn ErasedAction) -> bool;
    fn clone_erased(&self) -> Box<dyn ErasedAction>;
    fn as_any(&self) -> &dyn Any;
}

impl<T: Action> ErasedAction for T {
    fn run_erased(&self, act: &Act, input: &Input) -> Result<()> {
        self.run(act, input)
    }
    fn eq_erased(&self, other: &dyn ErasedAction) -> bool {
        other.as_any().downcast_ref::<T>() == Some(self)
    }
    fn clone_erased(&self) -> Box<dyn ErasedAction> {
        Box::new(self.clone())
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// A boxed action.
#[derive(Debug)]
pub struct Do(Box<dyn ErasedAction>);

impl Do {
    pub fn new(a: impl Action) -> Do {
        Do(Box::new(a))
    }
    pub fn run(&self, act: &Act, input: &Input) -> Result<()> {
        self.0.run_erased(act, input)
    }
}

impl Clone for Do {
    fn clone(&self) -> Do {
        Do(self.0.clone_erased())
    }
}

impl PartialEq for Do {
    fn eq(&self, other: &Do) -> bool {
        self.0.eq_erased(other.0.as_ref())
    }
}

/// Opens a thing (`None`: home), leaving any search.
#[derive(Clone, Debug, PartialEq)]
pub struct Open(pub Option<Tid>);

impl Action for Open {
    fn run(&self, act: &Act, _: &Input) -> Result<()> {
        act.set_local(QUERY, String::new());
        act.set_open(self.0)
    }
}

// ---- blocks

/// What stands for a thing beside its name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Mark {
    Icon(Icon),
    Initials(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChipMark {
    Dot,
    Icon(Icon),
}

/// A small pressable label: an action, or a thing in a run of them (`flat`: an action).
#[derive(Clone, Debug, PartialEq)]
pub struct Chip {
    pub label: String,
    pub color: Option<String>,
    pub mark: ChipMark,
    pub flat: bool,
    pub press: Option<Do>,
    pub remove: Option<Do>,
}

impl Chip {
    /// An action chip.
    pub fn action(icon: Icon, label: &str, press: Do) -> Chip {
        Chip { label: label.into(), color: None, mark: ChipMark::Icon(icon), flat: true, press: Some(press), remove: None }
    }
    /// An inert chip that shows a value.
    pub fn info(icon: Icon, label: &str) -> Chip {
        Chip { label: label.into(), color: None, mark: ChipMark::Icon(icon), flat: true, press: None, remove: None }
    }
    /// A choice: filled when current.
    pub fn choice(icon: Icon, label: &str, on: bool, press: Do) -> Chip {
        Chip { label: label.into(), color: None, mark: ChipMark::Icon(icon), flat: !on, press: Some(press), remove: None }
    }
}

/// When an entry happens, in local wall ms.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Span {
    pub start: i64,
    pub end: i64,
    pub all_day: bool,
    pub repeats: bool,
}

/// One item a view shows (notes/app.md Entry).
#[derive(Clone, Debug, PartialEq)]
pub struct Entry {
    pub key: String,
    pub thing: Tid,
    pub title: String,
    pub text: String,
    pub mark: Mark,
    pub color: Option<String>,
    pub author: Option<String>,
    /// UTC ms: orders a stream.
    pub time: Option<u64>,
    pub span: Option<Span>,
    /// What this entry answers.
    pub quote: Option<String>,
    pub raised: bool,
    pub actions: Vec<Chip>,
}

impl Entry {
    /// `t` as one entry from its summary.
    pub fn of(t: Tid, s: &Summary) -> Entry {
        Entry { key: t.to_string(), thing: t, title: s.name.clone(), text: s.sub.clone(), mark: s.mark.clone(), color: s.color.clone(), author: None, time: None, span: None, quote: None, raised: false, actions: Vec::new() }
    }
}

/// Entries one after another.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Run {
    pub entries: Vec<Entry>,
    /// Columns (0: as many as fit).
    pub cols: usize,
    /// A "new" tile at the end.
    pub new: Option<Do>,
    /// Dragging an entry reorders the source.
    pub reorder: Option<Do>,
}

/// One level of an outline: `parent` over its entries (`None`: the top).
#[derive(Clone, Debug, PartialEq)]
pub struct OutlineRun {
    pub parent: Option<String>,
    pub entries: Vec<Entry>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Day {
    pub label: String,
    pub today: bool,
    pub entries: Vec<Entry>,
}

/// A set of entries as an arrangement places them.
#[derive(Clone, Debug, PartialEq)]
pub enum Placed {
    Cards(Run),
    Rows(Run),
    Outline(Vec<OutlineRun>),
    Days(Vec<Day>),
    Stream(Vec<Entry>),
    /// Each element a named child view (an element spec).
    Views { cols: usize, views: Vec<(String, ViewSpec)> },
}

/// A row of a form: a label and an input saved on Enter or leaving it, or a value shown.
#[derive(Clone, Debug, PartialEq)]
pub struct FormRow {
    pub label: String,
    /// Small text under the label.
    pub sub: String,
    pub depth: usize,
    pub value: String,
    pub placeholder: String,
    pub save: Option<Do>,
}

/// A node's identity in the view tree: its path, keying its memory and text sessions.
pub type NodePath = String;

/// A view type's display properties. Unknown properties are ignored.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Config(pub BTreeMap<String, String>);

impl Config {
    pub fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).map(String::as_str)
    }
    pub fn flag(&self, key: &str) -> bool {
        self.get(key) == Some("true")
    }
    pub fn with(mut self, key: &str, value: &str) -> Config {
        self.0.insert(key.into(), value.into());
        self
    }
}

/// The data naming a view: view type, subject, config.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ViewSpec {
    pub view_type: String,
    pub subject: Tid,
    pub config: Config,
}

impl ViewSpec {
    pub fn new(view_type: &str, subject: Tid) -> ViewSpec {
        ViewSpec { view_type: view_type.into(), subject, config: Config::default() }
    }
    /// A collection as the rail shows it: rows in one column, no arrangement chooser.
    pub fn config_rail(mut self) -> ViewSpec {
        self.config = self.config.with("arrange", "rows").with("cols", "1").with("no_chooser", "true").with("title", "none");
        self
    }
}


#[derive(Clone, Debug, PartialEq)]
pub struct ComposerField {
    pub thing: Tid,
    pub ak: String,
    /// The map entry the field's text lives at.
    pub key: String,
    pub placeholder: String,
}

/// Fields written and sent as one. `send` runs on the last field's Enter and on the press; it
/// takes `Input::Text` for text from elsewhere (Android's clipboard).
#[derive(Clone, Debug, PartialEq)]
pub struct Composer {
    pub fields: Vec<ComposerField>,
    pub send: Do,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TextRole {
    Title,
    Body,
    Muted,
}

/// One option of a `Pick`.
#[derive(Clone, Debug, PartialEq)]
pub struct Pick {
    pub label: String,
    pub mark: Mark,
    pub tint: Option<String>,
    pub current: bool,
    pub press: Do,
}

/// A tab between a thing's views.
#[derive(Clone, Debug, PartialEq)]
pub struct Tab {
    pub label: String,
    pub current: bool,
    pub press: Do,
}

/// The vocabulary of what a page holds.
#[derive(Clone, Debug, PartialEq)]
pub enum Block {
    /// A title that cannot be edited here.
    Heading(String),
    /// Secondary text.
    Line(String),
    /// A section heading.
    Label(String),
    Chips(Vec<Chip>),
    Entries(Placed),
    Form { rows: Vec<FormRow>, wide: bool },
    /// A text field bound to `(thing, aspect)` over a text session, or to a map entry of it.
    Editor { thing: Tid, ak: String, key: Option<String>, placeholder: String, role: TextRole, multiline: bool, lead: Option<(Mark, Option<String>)> },
    Composer(Composer),
    /// A child view at `key`, inline.
    View { key: String, spec: ViewSpec },
    /// A child view filling the space: scrolling with what is `below` it (`plain`: no panel behind
    /// it), its foot pinned under the scroll (`has_foot` makes room for it).
    Filled { key: String, spec: ViewSpec, has_foot: bool, plain: bool, below: Vec<Block> },
    /// The thing's bar: back, descriptor, favorite, the context menu's button and open items.
    Bar { back: Option<Do>, descriptor: String, favorite: bool, star: Do, more: Do, menu: Vec<Chip> },
    /// One of several options, each shown as a tile.
    Pick { cols: usize, options: Vec<Pick> },
    /// Tabs between a thing's views.
    Tabs(Vec<Tab>),
}

/// A facet's contribution to a page.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Section {
    pub blocks: Vec<Block>,
    /// Pinned below the page's scroll.
    pub foot: Vec<Block>,
    /// The page's scroll follows its end.
    pub follow_end: bool,
}

impl Section {
    pub fn of(blocks: Vec<Block>) -> Section {
        Section { blocks, ..Section::default() }
    }
}

/// What every list says of a thing.
#[derive(Clone, Debug, PartialEq)]
pub struct Summary {
    pub name: String,
    /// "Event", "Note": descriptor words.
    pub words: Vec<String>,
    pub sub: String,
    pub mark: Mark,
    pub color: Option<String>,
    /// Local wall ms: orders by time.
    pub time: Option<i64>,
    /// The account profile this thing stands for.
    pub profile: Option<Tid>,
}

impl Default for Summary {
    fn default() -> Summary {
        Summary { name: String::new(), words: Vec::new(), sub: String::new(), mark: Mark::Icon(Icon::Note), color: None, time: None, profile: None }
    }
}

/// What a facet offers to add or create.
#[derive(Clone, Copy)]
pub struct Offer {
    pub id: &'static str,
    pub label: &'static str,
    pub icon: Icon,
    /// Writes the starting values on the thing (the app group's `Tid` beside it).
    pub set: fn(&Data, &mut osis::Write<'_>, Tid, Tid) -> Result<()>,
}

/// The range of entries an arrangement wants.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Window {
    /// Those touching local wall ms `[from, to)`.
    Span { from: i64, to: i64 },
    /// The newest this many a source has.
    Newest(usize),
}

/// Everything the app knows about one family of aspects (notes/app.md Facet).
pub trait Facet: Sync {
    fn id(&self) -> &'static str;
    /// Whether `ak` belongs to this family.
    fn claims(&self, ak: &str) -> bool;
    /// The aspects are present.
    fn applies(&self, cx: &Reader, t: Tid) -> Result<bool> {
        Ok(cx.aspects(t)?.iter().any(|a| self.claims(a)))
    }
    /// Part of every thing rather than a thing's own content: never why a view fits well.
    fn universal(&self) -> bool {
        false
    }
    fn summarize(&self, _cx: &Reader, _t: Tid, _s: &mut Summary) -> Result<()> {
        Ok(())
    }
    fn show(&self, cx: &Cx, t: Tid) -> Result<Section>;
    /// Expands `t` into entries; leaving `out` alone means one entry from its summary.
    fn entries(&self, _cx: &Cx, _t: Tid, _win: &Window, _out: &mut Vec<Entry>) -> Result<()> {
        Ok(())
    }
    fn search(&self, _cx: &Reader, _t: Tid) -> Result<Vec<String>> {
        Ok(Vec::new())
    }
    /// What it can add to `t` (`None`: to something new).
    fn offers(&self, _cx: &Reader, _t: Option<Tid>) -> Result<Vec<Offer>> {
        Ok(Vec::new())
    }
}

// ---- per-window state

/// The search field's text.
pub const QUERY: Local<String> = Local::new("query", String::new);
/// The window is dark now.
pub const DARK: Local<bool> = Local::new("dark", || false);
/// Minutes since the epoch: moves what shows an age.
pub const TICK: Local<u64> = Local::new("tick", || 0);
/// Bumped on every keystroke in an editor: what shows pending typing depends on it.
pub const TYPED: Local<u64> = Local::new("typed", || 0);

pub struct WindowInner {
    pub sessions: Sessions,
    pub graph: Rc<Graph>,
}

/// What a window keeps between refreshes beyond osis: its text sessions and its graph.
#[derive(Clone)]
pub struct WindowState(Rc<WindowInner>);

impl Default for WindowState {
    fn default() -> WindowState {
        let inner = Rc::new(WindowInner { sessions: Sessions::default(), graph: Rc::default() });
        inner.sessions.set_graph(inner.graph.clone());
        inner.graph.set_window(Rc::downgrade(&inner));
        WindowState(inner)
    }
}

impl From<Rc<WindowInner>> for WindowState {
    fn from(i: Rc<WindowInner>) -> WindowState {
        WindowState(i)
    }
}

impl Deref for WindowState {
    type Target = WindowInner;
    fn deref(&self) -> &WindowInner {
        &self.0
    }
}

impl WindowState {
    pub fn set_local<T: Clone + PartialEq + 'static>(&self, cell: Local<T>, v: T) {
        self.0.graph.set_local(cell, v);
    }
}

/// A view's context: a tracked `db` and `Reader` methods, what it is rendered with (`dark`, the
/// node's path and config), no writes. An action gets `Act`.
pub struct Cx {
    reader: Reader,
    pub(crate) window: WindowState,
    node: (NodePath, Config),
}

impl Deref for Cx {
    type Target = Reader;
    fn deref(&self) -> &Reader {
        &self.reader
    }
}

impl Cx {
    /// The window's root context, tracked in its graph. `dark` is the window's now.
    pub fn new(data: &Data, window: &WindowState, dark: bool) -> Cx {
        data.db.settle();
        // no root only if the graph lost it, which nothing does: reads are then simply untracked
        let reader = Graph::begin(&window.graph, data).map_or_else(|| (**data).clone(), |(scope, set)| data.scoped(&set, scope));
        let cx = Cx { reader, window: window.clone(), node: Default::default() };
        window.set_local(DARK, dark);
        if cx.local(TICK).unwrap_or(0) == 0
            && let Ok(t) = data.db.now()
        {
            window.set_local(TICK, t.0 / 60_000);
        }
        cx
    }

    /// The context of the node at `path` over `reader`.
    pub(crate) fn node(reader: Reader, window: WindowState, path: NodePath, config: Config) -> Cx {
        Cx { reader, window, node: (path, config) }
    }

    /// Whether the window is dark.
    pub fn dark(&self) -> Result<bool> {
        self.local(DARK)
    }

    /// The path of the node being rendered.
    pub fn path(&self) -> NodePath {
        self.node.0.clone()
    }

    /// The config of the node being rendered.
    pub fn config(&self) -> Config {
        self.node.1.clone()
    }

    /// Everything the registry offers for `t`, as chips (`None`: new things).
    pub fn offer_chips(&self, t: Option<Tid>) -> Result<Vec<Chip>> {
        let mut out = Vec::new();
        for f in self.registry.facets.iter() {
            for o in f.offers(self, t)? {
                out.push(Chip::action(o.icon, o.label, Do::new(UseOffer(o.id, t))));
            }
        }
        Ok(out)
    }
}

/// What an action asks of the shell beyond osis writes and local cells.
#[derive(Clone, Debug, Default)]
pub struct Effects {
    pub focus_title: bool,
    /// Text for the search field (Android's clipboard).
    pub paste: Option<String>,
}

/// An action's context: writes (through `Data`), node state, untracked reads, effects.
pub struct Act<'a> {
    pub data: &'a Data,
    pub window: &'a WindowState,
    pub effects: RefCell<Effects>,
}

impl Deref for Act<'_> {
    type Target = Data;
    fn deref(&self) -> &Data {
        self.data
    }
}

impl<'a> Act<'a> {
    pub fn new(data: &'a Data, window: &'a WindowState) -> Act<'a> {
        Act { data, window, effects: RefCell::default() }
    }

    /// Sets a local cell.
    pub fn set_local<T: Clone + PartialEq + 'static>(&self, cell: Local<T>, v: T) {
        self.window.set_local(cell, v);
    }

    /// Writes node state on this window.
    pub fn set_state<T: osis::Codec>(&self, key: osis::generated::Aspect<BTreeMap<String, T>>, node: &str, v: &T) -> Result<()> {
        let win = self.data.window()?;
        let mut w = self.data.db.write();
        w.at(win, key).path(osis::Path::root().push(node)).set(v)?;
        w.commit()?;
        Ok(())
    }

    /// Clears node state on this window.
    pub fn clear_state<T: osis::Codec>(&self, key: osis::generated::Aspect<BTreeMap<String, T>>, node: &str) -> Result<()> {
        let win = self.data.window()?;
        let mut w = self.data.db.write();
        w.at(win, key).path(osis::Path::root().push(node)).remove()?;
        w.commit()?;
        Ok(())
    }
}

/// Runs an offer on `t`, or makes a new thing with it.
#[derive(Clone, Debug, PartialEq)]
pub struct UseOffer(pub &'static str, pub Option<Tid>);

impl Action for UseOffer {
    fn run(&self, act: &Act, _: &Input) -> Result<()> {
        let Some(o) = crate::facets::offer(act, self.0)? else { return Ok(()) };
        match self.1 {
            None => {
                act.create_with(o.set)?;
                act.set_local(QUERY, String::new());
                act.effects.borrow_mut().focus_title = true;
            }
            Some(t) => {
                let g = act.main_group()?;
                let mut w = act.data.db.write();
                (o.set)(act.data, &mut w, t, g)?;
                w.commit()?;
            }
        }
        Ok(())
    }
}
