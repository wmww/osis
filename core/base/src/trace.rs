//! Debug builds: a per-thread line sink for decisions that leave no frame or store change (a
//! body's verdict moving, lost access firing, a transaction refused). Off until a harness turns it
//! on for its thread (osis-sync's `OSIS_SYNC_TRACE`), so a line costs one thread-local read; the
//! harness takes the lines after each step and prints them under the node it stepped.

use std::cell::{Cell, RefCell};

thread_local! {
    static ON: Cell<bool> = const { Cell::new(false) };
    static LINES: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
}

/// Lines kept untaken at most: a sink nobody takes forgets its oldest half.
const KEPT: usize = 10_000;

/// Turns this thread's sink on or off (off drops what it holds).
pub fn set(on: bool) {
    ON.with(|o| o.set(on));
    if !on {
        LINES.with(|l| l.borrow_mut().clear());
    }
}

/// Whether this thread's sink is on.
pub fn on() -> bool {
    ON.with(Cell::get)
}

/// Adds `line()` while the sink is on.
pub fn note(line: impl FnOnce() -> String) {
    if !on() {
        return;
    }
    let s = line();
    LINES.with(|l| {
        let mut l = l.borrow_mut();
        if l.len() >= KEPT {
            l.drain(..KEPT / 2);
        }
        l.push(s);
    });
}

/// How many lines are held: a mark for `mark_since`.
pub fn len() -> usize {
    LINES.with(|l| l.borrow().len())
}

/// Appends `tag` to every line added since `mark` (a transaction rolled back: what it noted did not
/// happen).
pub fn mark_since(mark: usize, tag: &str) {
    LINES.with(|l| {
        for x in l.borrow_mut().iter_mut().skip(mark) {
            x.push_str(tag);
        }
    });
}

/// The lines held, taken.
pub fn take() -> Vec<String> {
    LINES.with(|l| std::mem::take(&mut *l.borrow_mut()))
}

/// Which engine copy this thread runs, as a harness names it: copies of one node (a world played
/// twice, a shrink's candidates, the differential's reference twins) share its tid and session,
/// so a hand probe prints `trace::copy()` to tell their lines apart. Shown as `w<world>.<kind><index>`
/// (`w3.n1`: node 1 of the thread's third world; `w3.r0`: its reference twin of account 0);
/// `w0` before a harness names one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Copy {
    pub world: u32,
    pub kind: char,
    pub index: u32,
}

impl std::fmt::Display for Copy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "w{}.{}{}", self.world, self.kind, self.index)
    }
}

thread_local! {
    static COPY: Cell<Copy> = const { Cell::new(Copy { world: 0, kind: '?', index: 0 }) };
}

/// Names the engine copy this thread runs from now on (`Copy`).
pub fn set_copy(c: Copy) {
    COPY.with(|x| x.set(c));
}

/// The engine copy this thread runs, as its harness last named it.
pub fn copy() -> Copy {
    COPY.with(Cell::get)
}
