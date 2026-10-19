//! Text editing sessions (notes/api.md Text editing sessions; spec/requirements.md, Generality:
//! one commit per editing pause, never per keystroke): a buffer the UI edits; `commit` writes
//! what changed since the last commit as one edit (a sequence edit rebased onto the current text
//! for a `text` position, a register write otherwise); remote changes are merged into the buffer
//! (local edits are committed first) and reported through `on_remote`. A session commits on
//! `commit`, on the first edit after `Config::idle_commit` of inactivity, and on drop.
//! Not built: cut/paste with remembered ranges (issues/api-deferred.md).

use crate::error::{Error, Result};
use crate::handle::Osis;
use crate::read::ak_of;
use crate::watch::{Source, Subscription, lock};
use crate::write::Committed;
use osis_core::{Tid, Value};
use osis_crdt::{Op, PathOp};
use osis_schema::{AspectKey, Path, Type};
use std::ops::Range;
use std::sync::{Arc, Mutex};
use std::time::Instant;

type OnRemote = Box<dyn FnMut(&str) + Send>;

struct State {
    /// The text as last committed or merged.
    base: String,
    buf: String,
    last_edit: Option<Instant>,
    on_remote: Option<OnRemote>,
}

/// A text buffer bound to a string position of an aspect.
pub struct TextSession {
    db: Osis,
    tid: Tid,
    key: crate::Key,
    path: Path,
    seq: bool,
    st: Arc<Mutex<State>>,
    _sub: Option<Subscription>,
}

impl std::fmt::Debug for TextSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TextSession({} {})", self.tid, self.key.ak)
    }
}

fn char_range(s: &str, r: &Range<usize>) -> Result<Range<usize>> {
    let byte = |i: usize| s.char_indices().map(|(b, _)| b).chain([s.len()]).nth(i).ok_or(Error::Invalid(format!("char index {i} past the end")));
    Ok(byte(r.start)?..byte(r.end.max(r.start))?)
}

/// Commits `base -> buf` of a session; `None` when nothing changed.
fn flush(db: &Osis, tid: Tid, key: &crate::Key, path: &Path, seq: bool, st: &mut State) -> Result<Option<Committed>> {
    if st.buf == st.base {
        return Ok(None);
    }
    let op = if seq { Op::Edit { base: Value::Str(st.base.clone()), new: Value::Str(st.buf.clone()) } } else { Op::Set(Value::Str(st.buf.clone())) };
    let mut w = db.write();
    w.raw_op(tid, key, PathOp { path: crate::write::segs(path)?, op })?;
    let c = w.commit()?;
    st.base = st.buf.clone();
    Ok(c)
}

impl Osis {
    /// Opens a text session on the string at `path` of an aspect (`Path::root()` for the whole
    /// aspect). An absent position starts empty.
    pub fn edit_text<K: AspectKey>(&self, tid: Tid, key: K, path: Path) -> Result<TextSession> {
        let seq = matches!(crate::large::type_of(&key, &path)?, Some(Type::Text));
        let key = crate::Key { ak: ak_of(&key)?, schema: key.schema().map(|s| Arc::new(s.clone())) };
        let tid = self.read(|r| r.resolve(tid));
        let now = match self.read(|r| r.get_path(tid, &key, &path))? {
            Some(Value::Str(s)) => s,
            None => String::new(),
            Some(_) => return Err(Error::Invalid("not a string".into())),
        };
        let st = Arc::new(Mutex::new(State { base: now.clone(), buf: now, last_edit: None, on_remote: None }));
        let (st2, key2, path2) = (st.clone(), key.clone(), path.clone());
        let sub = self.at(tid, key.clone()).on_change(move |db, c| {
            if !matches!(c.source, Source::Remote(_) | Source::Derived(_)) {
                return;
            }
            let mut s = lock(&st2);
            // local edits first, rebased by the crdt; then the merged text
            let _ = flush(db, tid, &key2, &path2, seq, &mut s);
            let merged = match db.read(|r| r.get_path(tid, &key2, &path2)) {
                Ok(Some(Value::Str(x))) => x,
                _ => return,
            };
            if merged != s.buf {
                s.base = merged.clone();
                s.buf = merged.clone();
                if let Some(f) = s.on_remote.as_mut() {
                    f(&merged);
                }
            }
        })?;
        Ok(TextSession { db: self.clone(), tid, key, path, seq, st, _sub: Some(sub) })
    }
}

impl TextSession {
    /// The buffer now.
    pub fn text(&self) -> String {
        lock(&self.st).buf.clone()
    }

    /// Calls `f` with the merged text after a remote change (on the dispatcher thread).
    pub fn on_remote(&self, f: impl FnMut(&str) + Send + 'static) {
        lock(&self.st).on_remote = Some(Box::new(f));
    }

    /// Commits after an idle pause, then runs `f` on the buffer.
    fn edit(&self, f: impl FnOnce(&mut String) -> Result<()>) -> Result<()> {
        let mut s = lock(&self.st);
        if s.last_edit.is_some_and(|t| t.elapsed() >= self.db.inner.idle_commit) {
            flush(&self.db, self.tid, &self.key, &self.path, self.seq, &mut s)?;
        }
        f(&mut s.buf)?;
        s.last_edit = Some(Instant::now());
        Ok(())
    }

    /// Inserts `text` before char `at`.
    pub fn insert(&self, at: usize, text: &str) -> Result<()> {
        self.edit(|b| {
            let r = char_range(b, &(at..at))?;
            b.insert_str(r.start, text);
            Ok(())
        })
    }

    /// Deletes the chars in `range`.
    pub fn delete(&self, range: Range<usize>) -> Result<()> {
        self.replace(range, "")
    }

    /// Replaces the chars in `range` with `text`.
    pub fn replace(&self, range: Range<usize>, text: &str) -> Result<()> {
        self.edit(|b| {
            let r = char_range(b, &range)?;
            b.replace_range(r, text);
            Ok(())
        })
    }

    /// Commits what changed since the last commit as one commit.
    pub fn commit(&self) -> Result<Option<Committed>> {
        let mut s = lock(&self.st);
        let c = flush(&self.db, self.tid, &self.key, &self.path, self.seq, &mut s)?;
        s.last_edit = None;
        Ok(c)
    }
}

impl Drop for TextSession {
    fn drop(&mut self) {
        self._sub = None;
        let _ = self.commit();
    }
}
