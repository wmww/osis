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

/// By hand (`OSIS_TRACE_CALLERS`: `all`, or texts joined by `,` of which a line must hold one):
/// prints `<copy> <what> at <frames>` straight to stderr, past libtest's capture: the backtrace's
/// frames in the repo's sources, innermost first and this module's left out, each as
/// `<crate dir>/<path>:<line> <fn>` with generics stripped (`store/src/store.rs:412 transaction <
/// engine/src/engine/mod.rs:3421 run`). Called where work is begun or counted whose caller a
/// by-hand chase needs: each store transaction begun (`Store::transaction`) and each counted
/// stamp write (`memo`). Unset: one cached read per call.
pub fn caller(what: impl FnOnce() -> String) {
    static ONLY: std::sync::OnceLock<Option<Vec<String>>> = std::sync::OnceLock::new();
    let Some(only) = ONLY.get_or_init(|| {
        let v = crate::testenv::str_var("OSIS_TRACE_CALLERS")?;
        Some(if v == "all" { Vec::new() } else { v.split(',').map(str::to_string).collect() })
    }) else {
        return;
    };
    let bt = std::backtrace::Backtrace::force_capture().to_string();
    let cwd = std::env::current_dir().unwrap_or_default();
    let line = format!("{} {} at {}", copy(), what(), frames(&bt, &cwd.to_string_lossy()));
    if only.is_empty() || only.iter().any(|t| line.contains(t.as_str())) {
        crate::testenv::visible(true, &line);
    }
}

/// A backtrace's frames in the repo's sources as `caller` prints them (`cwd` resolves `./`).
fn frames(bt: &str, cwd: &str) -> String {
    let mut out: Vec<String> = Vec::new();
    let mut func: Option<String> = None;
    for l in bt.lines() {
        let l = l.trim_start();
        if let Some(at) = l.strip_prefix("at ") {
            let f = func.take().unwrap_or_default();
            let path = at.strip_prefix("./").map_or(at.to_string(), |p| format!("{cwd}/{p}"));
            if path.contains("/rustc/") || path.contains("/.cargo/") || path.contains("base/src/trace.rs:") {
                continue;
            }
            // `<crate dir>/src/..` or `<crate dir>/tests/..`, the line kept, the column dropped
            let Some(i) = path.find("/src/").or_else(|| path.find("/tests/")) else { continue };
            let start = path[..i].rfind('/').map_or(0, |j| j + 1);
            let at = path[start..].rsplit_once(':').map_or(&path[start..], |(p, _)| p);
            out.push(if f.is_empty() { at.to_string() } else { format!("{at} {f}") });
        } else if let Some((n, sym)) = l.split_once(": ")
            && n.parse::<u32>().is_ok()
        {
            // the function's last segment, generics stripped; a closure is named by its line
            let name = ungeneric(sym);
            let last = name.rsplit("::").next().unwrap_or_default();
            func = Some(if last.starts_with('{') { String::new() } else { last.to_string() });
        }
    }
    out.join(" < ")
}

/// `sym` with every `<..>` dropped, a `<T as Trait>::f` taken as `T::f`.
fn ungeneric(sym: &str) -> String {
    let sym = match sym.strip_prefix('<').and_then(|s| s.split_once(" as ")) {
        Some((ty, rest)) => format!("{ty}{}", rest.split_once(">::").map_or(String::new(), |(_, f)| format!("::{f}"))),
        None => sym.to_string(),
    };
    let mut out = String::new();
    let mut depth = 0u32;
    for c in sym.chars() {
        match c {
            '<' => depth += 1,
            '>' => depth = depth.saturating_sub(1),
            _ if depth == 0 => out.push(c),
            _ => {}
        }
    }
    out
}

#[cfg(test)]
mod tests {
    // spec: none (test support): `caller`'s frames are the repo's, short.
    #[test]
    fn frames_keep_the_repos_frames_short() {
        let bt = "   0: force_capture
             at /rustc/x/library/std/src/backtrace.rs:312:9
   1: caller<osis_base::memo::Table::log::{closure_env#0}>
             at /w/core/base/src/trace.rs:120:14
   2: <osis_store::mem::MemoryBackend<osis_base::Tid> as osis_store::backend::Backend>::begin
             at /w/core/store/src/mem.rs:40:9
   3: {closure#0}<alloc::vec::Vec<u8>>
             at /w/core/engine/src/engine/mod.rs:3421:20
   4: call_once<F>
             at /home/u/.cargo/registry/src/x/lib.rs:1:1
   5: deliver
             at ./tests/it/harness/mod.rs:1050:5
";
        assert_eq!(super::frames(bt, "/w/core/sync"), "store/src/mem.rs:40 begin < engine/src/engine/mod.rs:3421 < sync/tests/it/harness/mod.rs:1050 deliver");
    }
}
