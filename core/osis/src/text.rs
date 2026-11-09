//! Text editing sessions (notes/api.md Text editing sessions; spec/requirements.md, Generality:
//! one commit per editing pause, never per keystroke): a buffer the UI edits; `commit` writes
//! what changed since the last commit as one edit (a sequence edit rebased onto the current text
//! for a `text` position, a register write otherwise). A session follows its field, whoever
//! writes it: a value other than the text it last committed or merged (another session, a
//! `remove`, an undo, another node) has pending typing committed first, then the merged text
//! replaces the buffer, reported through `on_merge` as `Splice`s; its own commit's echo changes
//! nothing. A session commits on `commit`, after `Config::idle_commit` without edits (a timer on
//! the node's runtime; without one, at the next edit), and on drop. At most one save of a
//! session is in flight, and none holds the buffer's lock across a node call: a keystroke never
//! waits for a save. A session whose thing was deleted since it was known keeps its pending
//! text uncommitted instead (`UnknownThing`, reported as `Uncommitted` where no caller sees the
//! error; dropped with the session): it never recreates the thing, and commits if the thing
//! comes back.
//! Not built: cut/paste with remembered ranges (issues/api-deferred.md).

use crate::error::{Error, Result};
use crate::handle::Osis;
use crate::read::{PathRef, ak_of};
use crate::watch::{Delivery, Filter, Subscription, lock};
use crate::commits::Commit;
use osis_base::{Tid, Value};
use osis_crdt::{Op, PathOp};
use osis_schema::ValueKey;
use osis_schema::{Path, Type};
use std::ops::Range;
use std::sync::{Arc, Mutex, Weak};
use std::time::Instant;

/// One edit of a session's text by another node's commit, in chars: `del` chars at `at` replaced by
/// `text`, at the text as it was before this edit (a list applies in order).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Splice {
    /// Where the edit is.
    pub at: usize,
    /// How many chars it replaces.
    pub del: usize,
    /// What it puts there.
    pub text: String,
}

impl Splice {
    /// Where char position `pos` of the text before this edit is after it: one up to `at`
    /// stays (an insert there goes after it), one past the replaced chars shifts, one inside
    /// them moves to the end of the inserted text.
    pub fn map(&self, pos: usize) -> usize {
        let ins = self.text.chars().count();
        if pos <= self.at {
            pos
        } else if pos >= self.at + self.del {
            pos - self.del + ins
        } else {
            self.at + ins
        }
    }
}

/// `old → new` as splices (a char diff).
fn splices(old: &str, new: &str) -> Vec<Splice> {
    let (a, b): (Vec<char>, Vec<char>) = (old.chars().collect(), new.chars().collect());
    osis_crdt::changes(&a, &b).into_iter().map(|(o, n)| Splice { at: n.start, del: o.len(), text: b.get(n).unwrap_or_default().iter().collect() }).collect()
}

struct State {
    /// The text as last committed or merged.
    base: String,
    buf: String,
    last_edit: Option<Instant>,
    /// An idle-commit timer is pending.
    armed: bool,
    /// The `on_merge` subscriptions, by id (a dropped one is simply gone).
    on_merge: Vec<u64>,
    /// The thing was known at open or at a commit here: its absence now means it was deleted.
    known: bool,
}

/// What a session is bound to.
struct Bind {
    tid: Tid,
    key: crate::DynamicAspectKey,
    path: Path,
    seq: bool,
}

struct Session {
    b: Bind,
    /// Taken briefly, by keystrokes too; never held across a node call.
    st: Mutex<State>,
    /// Held across a save or a merge: at most one in flight, so no edit is committed twice and
    /// `base` changes only here.
    save: Mutex<()>,
}

/// Reports edits a session could not commit.
fn uncommitted(db: &Osis, tid: Tid, e: &Error) {
    let d = osis_node::Diagnostic { kind: osis_node::DiagnosticKind::Uncommitted, tids: vec![tid], commit: None, peer: None, detail: format!("text session edits not committed: {e}") };
    db.engine(|en| en.report(d));
}

/// Arms the idle-commit timer: when it fires, the edits are committed if the session has been
/// idle for `idle_commit`, else it re-arms for the rest.
fn arm(db: &Osis, s: Weak<Session>, d: std::time::Duration) -> bool {
    let w = db.downgrade();
    db.inner.net.after(
        d,
        Box::new(move || {
            let (Some(db), Some(s)) = (w.hold(), s.upgrade()) else { return };
            let idle = db.inner.idle_commit;
            {
                let mut st = lock(&s.st);
                match st.last_edit.map(|t| t.elapsed()) {
                    Some(e) if e < idle => {
                        st.armed = arm(&db, Arc::downgrade(&s), idle - e);
                        return;
                    }
                    // a keystroke during the save starts the next pause
                    Some(_) => (st.armed, st.last_edit) = (false, None),
                    None => {
                        st.armed = false;
                        return;
                    }
                }
            }
            // on failure the edits stay in the buffer; the next edit arms a retry
            if let Err(e) = save(&db, &s) {
                uncommitted(&db, s.b.tid, &e);
            }
        }),
    )
}

/// A text buffer bound to a string position of an aspect.
pub struct TextSession {
    db: Osis,
    s: Arc<Session>,
    _sub: Option<Subscription>,
}

impl std::fmt::Debug for TextSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TextSession({} {})", self.s.b.tid, self.s.b.key.ak)
    }
}

fn char_range(s: &str, r: &Range<usize>) -> Result<Range<usize>> {
    let byte = |i: usize| s.char_indices().map(|(b, _)| b).chain([s.len()]).nth(i).ok_or(Error::Invalid(format!("char index {i} past the end")));
    Ok(byte(r.start)?..byte(r.end.max(r.start))?)
}

/// Commits `base -> buf` of a session; `None` when nothing changed.
fn save(db: &Osis, s: &Session) -> Result<Option<Commit>> {
    let _g = lock(&s.save);
    save_held(db, s).map(|(c, _)| c)
}

/// `save` with `s.save` held; also the text the field was told (the new `base`). The buffer is
/// snapshotted, committed unlocked, and the snapshot becomes `base`: typing meanwhile stays pending.
fn save_held(db: &Osis, s: &Session) -> Result<(Option<Commit>, String)> {
    let (base, buf, known) = {
        let st = lock(&s.st);
        (st.base.clone(), st.buf.clone(), st.known)
    };
    if buf == base {
        return Ok((None, buf));
    }
    if let Some(h) = &db.inner.text_save {
        h();
    }
    let b = &s.b;
    let op = if b.seq { Op::Edit { base: Value::Str(base), new: Value::Str(buf.clone()) } } else { Op::Set(Value::Str(buf.clone())) };
    let mut w = db.write();
    // known here before: committing after a delete would recreate it (`UnknownThing`, the
    // edits kept: they commit if the thing comes back)
    w.alive = known.then_some(b.tid);
    w.raw_op(b.tid, &b.key, PathOp { path: crate::write::segs(&b.path)?, op })?;
    let c = w.commit()?;
    let mut st = lock(&s.st);
    st.base = buf.clone();
    st.known = true;
    Ok((c, buf))
}

/// The field's text: an absent one reads empty; `None` for another type or a failed read.
fn read(db: &Osis, b: &Bind) -> Option<String> {
    match db.read_local(|r| r.get_path(b.tid, &b.key, &b.path)) {
        Ok(Some(Value::Str(x))) => Some(x),
        Ok(None) => Some(String::new()),
        _ => None,
    }
}

/// Called on every change of the field. Unless it reads `base` (an echo of this session's
/// commit, a write elsewhere in the aspect), pending typing is committed (the crdt rebases it)
/// and the merged text replaces the buffer, reported to `on_merge`. The field is read here, under
/// `save`, never taken from the call: a value read before this session's last save would look
/// like another writer's. Typing that comes in meanwhile is committed and merged by another
/// round. Edits that cannot be committed are reported and dropped from the buffer (the merged
/// text wins), except on a deleted thing, where they stay pending.
fn merge(db: &Osis, s: &Session) {
    let g = lock(&s.save);
    let b = &s.b;
    match read(db, b) {
        Some(now) if now != lock(&s.st).base => {}
        _ => return,
    }
    let (merged, edits, subs) = loop {
        let told = match save_held(db, s) {
            Ok((_, told)) => Some(told),
            Err(e) => {
                uncommitted(db, b.tid, &e);
                if matches!(e, Error::UnknownThing { .. }) {
                    return;
                }
                None
            }
        };
        let Some(merged) = read(db, b) else { return };
        let mut st = lock(&s.st);
        if told.is_some_and(|t| t != st.buf) {
            continue;
        }
        let edits = splices(&st.buf, &merged);
        st.base = merged.clone();
        st.buf = merged.clone();
        break (merged, edits, st.on_merge.clone());
    };
    // no callback under a lock: it may ask this session anything
    drop(g);
    if edits.is_empty() {
        return;
    }
    for id in subs {
        db.inner.dispatch.call_now(db, id, Delivery::Text { text: merged.clone(), edits: edits.clone() });
    }
}

impl<K: ValueKey> PathRef<'_, '_, K> {
    /// Opens a text session on the string here. An absent position starts empty. `Unsupported`
    /// through a connected node.
    pub fn edit_text(&self) -> Result<TextSession> {
        let (db, tid, key, path) = self.parts();
        if let crate::sources::Source::Node(_) = db.source(tid) {
            return Err(Error::Unsupported("edit_text through a connected node".into()));
        }
        let seq = matches!(crate::large::type_of(key, path)?, Some(Type::Text));
        let key = crate::DynamicAspectKey { ak: ak_of(key)?, schema: key.schema().map(|s| Arc::new(s.clone())) };
        let now = match db.read_local(|r| r.get_path(tid, &key, path))? {
            Some(Value::Str(s)) => s,
            None => String::new(),
            Some(_) => return Err(Error::Invalid("not a string".into())),
        };
        let st = State { base: now.clone(), buf: now, last_edit: None, armed: false, on_merge: Vec::new(), known: db.has_content(tid)? };
        let s = Arc::new(Session { b: Bind { tid, key: key.clone(), path: path.clone(), seq }, st: Mutex::new(st), save: Mutex::new(()) });
        let s2 = s.clone();
        // every change of the aspect, undeduplicated: a watch's last value is not what this
        // session last committed or merged (its own commit, then a `remove`, would read as no
        // change); `merge` reads the field itself. The text is read again as the watch begins,
        // so no write falls between.
        let read = crate::watch::ReadAt::new(|_| Ok(None));
        let sub = db.subscribe(Filter::Aspect(tid, key.ak.clone(), read), false, move |r| {
            let now = match r.get_path(tid, &key, path) {
                Ok(Some(Value::Str(x))) => Some(x),
                Ok(None) => Some(String::new()),
                _ => None,
            };
            if let Some(x) = now {
                let mut st = lock(&s2.st);
                st.base = x.clone();
                st.buf = x;
            }
            Box::new(move |db, d| {
                if let Delivery::Aspect { .. } = d {
                    merge(db, &s2);
                }
            })
        });
        Ok(TextSession { db: db.clone(), s, _sub: Some(sub) })
    }
}

impl TextSession {
    /// The buffer now.
    pub fn text(&self) -> String {
        lock(&self.s.st).buf.clone()
    }

    /// Calls `f` with the merged text and the edits from the buffer before, each time the
    /// field's value is merged into the buffer (any write but this session's own).
    pub fn on_merge(&self, mut f: impl FnMut(&Osis, &str, &[Splice]) + Send + 'static) -> Result<Subscription> {
        let cb: crate::watch::Callback = Box::new(move |db, d| {
            if let Delivery::Text { text, edits } = d {
                f(db, &text, &edits);
            }
        });
        let sub = self.db.locked(|l| self.db.inner.dispatch.register(l.seq + 1, Filter::Text, cb));
        lock(&self.s.st).on_merge.extend(sub.id());
        Ok(sub)
    }

    /// Commits after an idle pause no timer took, then runs `f` on the buffer.
    fn edit(&self, f: impl FnOnce(&mut String) -> Result<()>) -> Result<()> {
        let idle = self.db.inner.idle_commit;
        let paused = {
            let st = lock(&self.s.st);
            !st.armed && st.last_edit.is_some_and(|t| t.elapsed() >= idle)
        };
        if paused {
            save(&self.db, &self.s)?;
        }
        let mut st = lock(&self.s.st);
        f(&mut st.buf)?;
        st.last_edit = Some(Instant::now());
        if !st.armed {
            st.armed = arm(&self.db, Arc::downgrade(&self.s), idle);
        }
        Ok(())
    }

    /// Replaces the chars in `range` with `text`: an empty range inserts, empty text deletes.
    pub fn splice(&self, range: Range<usize>, text: &str) -> Result<()> {
        self.edit(|b| {
            let r = char_range(b, &range)?;
            b.replace_range(r, text);
            Ok(())
        })
    }

    /// Commits what changed since the last commit as one commit; `UnknownThing` (the edits
    /// kept) when the thing was deleted since it was known here.
    pub fn commit(&self) -> Result<Option<Commit>> {
        save(&self.db, &self.s)
    }
}

impl Drop for TextSession {
    fn drop(&mut self) {
        self._sub = None;
        if let Err(e) = self.commit() {
            uncommitted(&self.db, self.s.b.tid, &e);
        }
    }
}
