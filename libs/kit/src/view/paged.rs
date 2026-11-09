//! The one list block (notes/fast-design.md): `cx.list(page, row)`. `page` returns keys of a window
//! of the list, `row` runs only for those. Where the window is lives in a local cell per list, set
//! by the list widget as it scrolls, so a render asks only for what is shown and scrolling is a
//! re-render of one node.

use super::{Cx, Do, Entry, Local, ViewSpec};
use osis::{Result, Tid};

/// Rows a list holds before the widget has said how much it wants, and the window's unit for
/// everything the harness bounds (Minor: past the shown rows a little extra is built, or a tall
/// list loads once more; 0 would show nothing, infinity builds the whole list).
pub const WINDOW: usize = 64;
/// The most rows on one side of a window a list ever asks for (Resource bound: a viewport cannot
/// use more; 0 would never scroll, infinity lets a widget ask for a whole history).
pub const MAX_SIDE: usize = 512;

/// A place in a list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum At {
    /// The first rows.
    Start,
    /// The last rows.
    End,
    /// This key and the rows after it, in list order.
    From(String),
    /// The rows just before this key, in list order.
    Before(String),
}

/// A window of a list, in list order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Page<T> {
    pub rows: Vec<T>,
    /// More rows lie past this window, in the direction it was asked for.
    pub more: bool,
    /// The index of `rows[0]` in the whole list, when the source knows it (a reorderable or
    /// column-aligned list needs it).
    pub first: Option<usize>,
}

impl<T> Default for Page<T> {
    fn default() -> Page<T> {
        Page { rows: Vec::new(), more: false, first: None }
    }
}

/// What a row of a page is called.
pub trait Row {
    fn key(&self) -> String;
}

impl Row for Tid {
    fn key(&self) -> String {
        self.to_string()
    }
}

impl Row for Entry {
    fn key(&self) -> String {
        self.key.clone()
    }
}

/// A window of a list held whole, in order: what a set source pages over. `pos` is the index of a
/// key (`None`: the key left the list, so the page starts over from the top).
pub fn page_of<T: Clone>(all: &[T], pos: impl Fn(&str) -> Option<usize>, at: &At, n: usize) -> Page<T> {
    let (from, to) = match at {
        At::Start => (0, n.min(all.len())),
        At::End => (all.len().saturating_sub(n), all.len()),
        At::From(k) => match pos(k) {
            Some(i) => (i, (i + n).min(all.len())),
            None => (0, n.min(all.len())),
        },
        At::Before(k) => {
            let i = pos(k).unwrap_or(0);
            (i.saturating_sub(n), i)
        }
    };
    let more = match at {
        At::Start | At::From(_) => to < all.len(),
        At::End | At::Before(_) => from > 0,
    };
    Page { rows: all.get(from..to).unwrap_or_default().to_vec(), more, first: Some(from) }
}

/// Where a list looks: the row at its top (or its first or last rows, while none has been chosen),
/// and how many rows it wants on each side of it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListWindow {
    /// `None`: the start of the list, or the end of one that follows its end.
    pub anchor: Option<String>,
    pub before: usize,
    pub after: usize,
}

impl Default for ListWindow {
    fn default() -> ListWindow {
        ListWindow { anchor: None, before: 0, after: WINDOW }
    }
}

/// Each list's window, by its path.
pub const LIST_WINDOW: Local<ListWindow> = Local::new("list window", ListWindow::default);

/// How rows are drawn.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Style {
    /// One after another, each as tall as it needs.
    Stream,
    Card,
    Row,
}

/// A list's shape, the same whatever is shown.
#[derive(Clone, Debug, PartialEq)]
pub struct Shape {
    pub style: Style,
    /// Columns (0: as many as fit).
    pub cols: usize,
    /// Dragging a row reorders the source.
    pub reorder: Option<Do>,
    /// A "new" tile at the end.
    pub new: Option<Do>,
    /// Opens at the end, and stays at the end while scrolled there.
    pub follow_end: bool,
}

impl Shape {
    pub fn new(style: Style) -> Shape {
        Shape { style, cols: 0, reorder: None, new: None, follow_end: false }
    }
}

/// One row as shown.
#[derive(Clone, Debug, PartialEq)]
pub enum Item {
    Entry(Entry),
    /// A label across the list, naming what follows.
    Label(String),
    /// A child view of this list, at the row's key.
    View(ViewSpec),
    /// The "new" tile.
    New(Do),
}

impl From<Entry> for Item {
    fn from(e: Entry) -> Item {
        Item::Entry(e)
    }
}

impl From<ViewSpec> for Item {
    fn from(v: ViewSpec) -> Item {
        Item::View(v)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ListRow {
    pub key: String,
    pub item: Item,
}

/// A window of a list, as a block. Only `Cx::list` makes one.
#[derive(Clone, Debug, PartialEq)]
pub struct List {
    pub(crate) id: String,
    pub(crate) shape: Shape,
    pub(crate) rows: Vec<ListRow>,
    pub(crate) more_before: bool,
    pub(crate) more_after: bool,
    pub(crate) first: Option<usize>,
    /// The row at the top when built, for a widget made fresh (a rebuild keeps the place).
    pub(crate) anchor: Option<usize>,
}

impl List {
    /// The rows shown.
    pub fn rows(&self) -> &[ListRow] {
        &self.rows
    }
    /// The entries shown.
    pub fn entries(&self) -> impl Iterator<Item = &Entry> {
        self.rows.iter().filter_map(|r| match &r.item {
            Item::Entry(e) => Some(e),
            _ => None,
        })
    }
    /// The index in the whole list of the first row shown, when known.
    pub fn first(&self) -> Option<usize> {
        self.first
    }
    /// Nothing to show.
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }
    /// The keys of child views shown.
    pub(crate) fn views(&self) -> impl Iterator<Item = (&str, &ViewSpec)> {
        self.rows.iter().filter_map(|r| match &r.item {
            Item::View(v) => Some((r.key.as_str(), v)),
            _ => None,
        })
    }
    pub(crate) fn frame_eq(&self, other: &List) -> bool {
        self.id == other.id && self.shape == other.shape
    }
}

impl Cx {
    /// The list block. `page` gives keys of a window of the list; `row` makes a row for each of
    /// those, and is not asked for any other (`None` leaves it out). `id` tells a node's lists
    /// apart. There is no other way to make a list.
    pub fn list<T: Row, I: Into<Item>>(&self, id: &str, shape: Shape, page: impl Fn(&At, usize) -> Result<Page<T>>, row: impl Fn(&Cx, &T) -> Result<Option<I>>) -> Result<super::Block> {
        let path = format!("{}#{id}", self.path());
        let w = self.local_at(LIST_WINDOW, &path)?;
        let (rows, more_before, more_after, first) = match &w.anchor {
            None if shape.follow_end => {
                let p = page(&At::End, WINDOW)?;
                (p.rows, p.more, false, p.first)
            }
            None => {
                let p = page(&At::Start, WINDOW)?;
                (p.rows, false, p.more, p.first)
            }
            Some(k) => {
                let after = page(&At::From(k.clone()), w.after.clamp(1, MAX_SIDE))?;
                let before = page(&At::Before(k.clone()), w.before.min(MAX_SIDE))?;
                let first = after.first.map(|f| f.saturating_sub(before.rows.len())).or(before.first);
                let mut rows = before.rows;
                let (more_after, ab) = (after.more, after.rows);
                rows.extend(ab);
                (rows, before.more, more_after, first)
            }
        };
        let anchor = w.anchor.as_ref().and_then(|k| rows.iter().position(|t| t.key() == *k));
        let mut out = Vec::with_capacity(rows.len() + 1);
        for t in &rows {
            if let Some(i) = row(self, t)? {
                out.push(ListRow { key: t.key(), item: i.into() });
            }
        }
        if let Some(n) = shape.new.clone().filter(|_| !more_after) {
            out.push(ListRow { key: "new".into(), item: Item::New(n) });
        }
        Ok(super::Block::List(List { id: path, shape, rows: out, more_before, more_after, first, anchor }))
    }
}
