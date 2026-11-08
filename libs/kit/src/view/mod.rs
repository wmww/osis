//! The toolkit-free model of what the window shows (notes/app.md Code shape): `Block`, the `Action`
//! and `Facet` traits, `Cx`, and per-window memory. A test reads a whole page as a value.

pub mod arrange;
pub mod registry;
pub mod search;
pub mod sessions;
pub mod source;

use crate::store::Data;
use osis::{Result, Subscription, Tid};
pub use crate::icons::Icon;
use sessions::Sessions;
use std::any::Any;
use std::cell::{OnceCell, RefCell};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Debug;
use std::sync::Arc;

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
    fn run(&self, cx: &Cx<'_>, input: &Input) -> Result<()>;
}

trait ErasedAction: Debug {
    fn run_erased(&self, cx: &Cx<'_>, input: &Input) -> Result<()>;
    fn eq_erased(&self, other: &dyn ErasedAction) -> bool;
    fn clone_erased(&self) -> Box<dyn ErasedAction>;
    fn as_any(&self) -> &dyn Any;
}

impl<T: Action> ErasedAction for T {
    fn run_erased(&self, cx: &Cx<'_>, input: &Input) -> Result<()> {
        self.run(cx, input)
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
    pub fn run(&self, cx: &Cx<'_>, input: &Input) -> Result<()> {
        self.0.run_erased(cx, input)
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
    fn run(&self, cx: &Cx<'_>, _: &Input) -> Result<()> {
        cx.effects.borrow_mut().clear_search = true;
        cx.data.set_open(self.0)
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
#[derive(Clone, Debug, Default, PartialEq, Eq)]
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
#[derive(Clone, Debug, PartialEq, Eq)]
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

/// How a facet tells the shell its subscription fired.
#[derive(Clone)]
pub struct Notify {
    pub changed: Arc<dyn Fn() + Send + Sync>,
    pub ended: Arc<dyn Fn() + Send + Sync>,
}

/// Everything the app knows about one family of aspects (notes/app.md Facet).
pub trait Facet: Sync {
    fn id(&self) -> &'static str;
    /// Whether `ak` belongs to this family.
    fn claims(&self, ak: &str) -> bool;
    /// The aspects are present.
    fn applies(&self, cx: &Cx<'_>, t: Tid) -> Result<bool> {
        Ok(cx.aspects(t)?.iter().any(|a| self.claims(a)))
    }
    /// Part of every thing rather than a thing's own content: never why a view fits well.
    fn universal(&self) -> bool {
        false
    }
    fn summarize(&self, _cx: &Cx<'_>, _t: Tid, _s: &mut Summary) -> Result<()> {
        Ok(())
    }
    fn show(&self, cx: &Cx<'_>, t: Tid) -> Result<Section>;
    /// Expands `t` into entries; leaving `out` alone means one entry from its summary.
    fn entries(&self, _cx: &Cx<'_>, _t: Tid, _win: &Window, _out: &mut Vec<Entry>) -> Result<()> {
        Ok(())
    }
    fn search(&self, _cx: &Cx<'_>, _t: Tid) -> Result<Vec<String>> {
        Ok(Vec::new())
    }
    /// What it can add to `t` (`None`: to something new).
    fn offers(&self, _cx: &Cx<'_>, _t: Option<Tid>) -> Result<Vec<Offer>> {
        Ok(Vec::new())
    }
    /// A subscription for a thing being shown that a thing watch does not cover.
    fn live(&self, _cx: &Cx<'_>, _t: Tid, _n: Notify) -> Result<Option<Subscription>> {
        Ok(None)
    }
}

// ---- per-window state

/// What a window keeps between refreshes beyond osis: its text sessions.
#[derive(Default)]
pub struct WindowState {
    pub sessions: Sessions,
}

/// What an action asks of the shell beyond osis writes.
#[derive(Clone, Debug, Default)]
pub struct Effects {
    pub clear_search: bool,
    pub focus_title: bool,
    /// Rebuild the page (the sessions show their text again).
    pub rebuild: bool,
    /// Text for the search field (Android's clipboard).
    pub paste: Option<String>,
}

/// The context of building a model or running an action.
pub struct Cx<'a> {
    pub data: &'a Data,
    pub window: &'a WindowState,
    /// The window is dark now.
    pub dark: bool,
    pub effects: RefCell<Effects>,
    things: OnceCell<BTreeSet<Tid>>,
    aspects: RefCell<BTreeMap<Tid, Arc<Vec<String>>>>,
    summaries: RefCell<BTreeMap<Tid, Summary>>,
    /// The node being rendered.
    node: RefCell<(NodePath, Config)>,
}

impl<'a> Cx<'a> {
    pub fn new(data: &'a Data, window: &'a WindowState, dark: bool) -> Cx<'a> {
        Cx { data, window, dark, effects: RefCell::default(), things: OnceCell::new(), aspects: RefCell::default(), summaries: RefCell::default(), node: RefCell::default() }
    }

    /// The path of the node being rendered.
    pub fn path(&self) -> NodePath {
        self.node.borrow().0.clone()
    }

    /// The config of the node being rendered.
    pub fn config(&self) -> Config {
        self.node.borrow().1.clone()
    }

    /// Runs `f` as the node at `path` with `config`.
    pub fn at_node<T>(&self, path: &str, config: Config, f: impl FnOnce() -> T) -> T {
        let saved = std::mem::replace(&mut *self.node.borrow_mut(), (path.to_string(), config));
        let out = f();
        *self.node.borrow_mut() = saved;
        out
    }

    /// Node state on this window: the value of `key` at `node`.
    pub fn state<T: osis::Codec>(&self, key: osis::generated::Aspect<BTreeMap<String, T>>, node: &str) -> Result<Option<T>> {
        let Some(w) = self.data.window_opt()? else { return Ok(None) };
        self.data.db.at(w, key).path(osis::Path::root().push(node)).get()
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

    /// Everything held.
    pub fn things(&self) -> Result<&BTreeSet<Tid>> {
        if let Some(t) = self.things.get() {
            return Ok(t);
        }
        let v = self.data.things()?;
        Ok(self.things.get_or_init(|| v))
    }

    /// The aspect names `t` carries, the system's left out.
    pub fn aspects(&self, t: Tid) -> Result<Arc<Vec<String>>> {
        if let Some(a) = self.aspects.borrow().get(&t) {
            return Ok(a.clone());
        }
        let v: Vec<String> = self.data.db.aspects(t)?.into_iter().map(|a| a.as_str().to_string()).filter(|a| !crate::store::SYSTEM.contains(&a.as_str())).collect();
        let v = Arc::new(v);
        self.aspects.borrow_mut().insert(t, v.clone());
        Ok(v)
    }

    /// Whether the facet `id` applies to `t`.
    pub fn applies(&self, id: &str, t: Tid) -> Result<bool> {
        match self.data.registry.facet(id) {
            Some(f) => f.applies(self, t),
            None => Ok(false),
        }
    }

    pub fn has(&self, t: Tid, prefix: &str) -> Result<bool> {
        Ok(self.aspects(t)?.iter().any(|a| a.starts_with(prefix)))
    }

    /// `t`'s summary through every applying facet.
    pub fn summary(&self, t: Tid) -> Result<Summary> {
        if let Some(s) = self.summaries.borrow().get(&t) {
            return Ok(s.clone());
        }
        let mut s = Summary { color: self.data.color(t)?, ..Summary::default() };
        for f in self.data.registry.facets.iter() {
            if f.applies(self, t)? {
                f.summarize(self, t, &mut s)?;
            }
        }
        if s.name.is_empty() {
            s.name = self.data.name(t)?;
        }
        if s.name.is_empty() && self.data.db.profile_of(self.data.db.me())? == Some(t) {
            s.name = "You".into();
        }
        self.summaries.borrow_mut().insert(t, s.clone());
        Ok(s)
    }

    /// Everything the registry offers for `t`, as chips (`None`: new things).
    pub fn offer_chips(&self, t: Option<Tid>) -> Result<Vec<Chip>> {
        let mut out = Vec::new();
        for f in self.data.registry.facets.iter() {
            for o in f.offers(self, t)? {
                out.push(Chip::action(o.icon, o.label, Do::new(UseOffer(o.id, t))));
            }
        }
        Ok(out)
    }
}

/// Runs an offer on `t`, or makes a new thing with it.
#[derive(Clone, Debug, PartialEq)]
pub struct UseOffer(pub &'static str, pub Option<Tid>);

impl Action for UseOffer {
    fn run(&self, cx: &Cx<'_>, _: &Input) -> Result<()> {
        let Some(o) = crate::facets::offer(cx, self.0)? else { return Ok(()) };
        match self.1 {
            None => {
                cx.data.create_with(o.set)?;
                let mut e = cx.effects.borrow_mut();
                e.clear_search = true;
                e.focus_title = true;
            }
            Some(t) => {
                let g = cx.data.main_group()?;
                let mut w = cx.data.db.write();
                (o.set)(cx.data, &mut w, t, g)?;
                w.commit()?;
            }
        }
        Ok(())
    }
}
