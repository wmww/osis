//! Text sessions behind editors. A session is per field `(thing, aspect, map entry)`, shared by
//! every node editing that field (so each editor sees the others' typing before it is committed);
//! each node tracks what its own widget shows. One session per editor is
//! notes/listener-design.md build step 7.
//! Typing goes here, one commit per pause; dropping a session commits what is pending.

use crate::store::Data;
use osis::{Result, Splice, Subscription, TextSession, Tid};
use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// An editor: its node, its thing, its aspect, the map entry within it (`None`: the whole aspect).
pub type Key = (super::NodePath, Tid, String, Option<String>);

type Field = (Tid, String, Option<String>);

/// Remote edits waiting for one editor.
type Inbox = Arc<Mutex<Vec<Splice>>>;

/// How the shell hears of a merge into a thing's sessions it does not show yet.
pub type NotifyRemote = Arc<dyn Fn(Tid) + Send + Sync>;

/// What one node's widget shows of a field.
struct Editor {
    shown: String,
    /// The edits of remote merges since `shown` (reported on the session's thread).
    reported: Inbox,
}

struct Shared {
    /// Kept for its life: every editor's `reported` fills through it.
    _remote: Subscription,
    session: TextSession,
    reporters: Arc<Mutex<Vec<Inbox>>>,
    editors: HashMap<super::NodePath, Editor>,
}

/// The sessions a window's editors are bound to.
#[derive(Default)]
pub struct Sessions {
    fields: RefCell<HashMap<Field, Shared>>,
    notify: RefCell<Option<NotifyRemote>>,
}

fn field(key: &Key) -> Field {
    (key.1, key.2.clone(), key.3.clone())
}

impl Sessions {
    pub fn set_notify(&self, n: NotifyRemote) {
        *self.notify.borrow_mut() = Some(n);
    }

    /// Opens the session of `key`'s field if needed; what the widget should show.
    pub fn show(&self, d: &Data, key: &Key) -> Result<String> {
        let mut fields = self.fields.borrow_mut();
        let f = field(key);
        if !fields.contains_key(&f) {
            let t = key.1;
            let ak = d.db.aspect_key(&key.2)?;
            let path = key.3.as_ref().map_or_else(osis::Path::root, |k| osis::Path::root().push(k.as_str()));
            let session = d.db.at(t, ak).path(path).edit_text()?;
            let reporters: Arc<Mutex<Vec<Inbox>>> = Arc::default();
            let r = reporters.clone();
            let notify = self.notify.borrow().clone();
            let remote = session.on_merge(move |_, _, edits| {
                for x in r.lock().unwrap_or_else(|e| e.into_inner()).iter() {
                    x.lock().unwrap_or_else(|e| e.into_inner()).extend_from_slice(edits);
                }
                if let Some(n) = &notify {
                    n(t);
                }
            })?;
            fields.insert(f.clone(), Shared { _remote: remote, session, reporters, editors: HashMap::new() });
        }
        let Some(s) = fields.get_mut(&f) else { return Ok(String::new()) };
        let text = s.session.text();
        match s.editors.get_mut(&key.0) {
            Some(e) => {
                e.shown = text.clone();
                e.reported.lock().unwrap_or_else(|e| e.into_inner()).clear();
            }
            None => {
                let reported: Inbox = Arc::default();
                s.reporters.lock().unwrap_or_else(|e| e.into_inner()).push(reported.clone());
                s.editors.insert(key.0.clone(), Editor { shown: text.clone(), reported });
            }
        }
        Ok(text)
    }

    /// The widget's whole new text, as one splice of the field's session. Any other editor of the
    /// field hears of it as a merge.
    pub fn typed(&self, key: &Key, text: &str) -> Result<()> {
        let mut fields = self.fields.borrow_mut();
        let Some(s) = fields.get_mut(&field(key)) else { return Ok(()) };
        let Some(e) = s.editors.get_mut(&key.0) else { return Ok(()) };
        let shown = std::mem::replace(&mut e.shown, text.to_string());
        crate::edit::splice(&s.session, &shown, text)?;
        if s.editors.len() > 1
            && let Some(n) = self.notify.borrow().as_ref()
        {
            n(key.1);
        }
        Ok(())
    }

    /// Takes what a merge changed for this editor: the session's text, what the widget showed,
    /// the edits.
    pub fn merged(&self, key: &Key) -> Option<(String, String, Vec<Splice>)> {
        let mut fields = self.fields.borrow_mut();
        let s = fields.get_mut(&field(key))?;
        let text = s.session.text();
        let e = s.editors.get_mut(&key.0)?;
        let reported = std::mem::take(&mut *e.reported.lock().unwrap_or_else(|e| e.into_inner()));
        let shown = std::mem::replace(&mut e.shown, text.clone());
        Some((text, shown, reported))
    }

    /// The editors open on `t`.
    pub fn keys_of(&self, t: Tid) -> Vec<Key> {
        let fields = self.fields.borrow();
        fields.iter().filter(|(f, _)| f.0 == t).flat_map(|(f, s)| s.editors.keys().map(|n| (n.clone(), f.0, f.1.clone(), f.2.clone()))).collect()
    }

    /// Closes `t`'s sessions, committing pending typing.
    pub fn close(&self, t: Tid) {
        self.fields.borrow_mut().retain(|f, _| f.0 != t);
    }

    /// Closes one editor; the field's session, committing pending typing, with its last editor.
    pub fn close_key(&self, key: &Key) {
        self.retain_where(|k| k != key);
    }

    /// Keeps only the editors still shown.
    pub fn retain(&self, keep: impl Fn(&Key) -> bool) {
        self.retain_where(keep);
    }

    fn retain_where(&self, keep: impl Fn(&Key) -> bool) {
        self.fields.borrow_mut().retain(|f, s| {
            s.editors.retain(|n, e| {
                let k = keep(&(n.clone(), f.0, f.1.clone(), f.2.clone()));
                if !k {
                    let mut r = s.reporters.lock().unwrap_or_else(|p| p.into_inner());
                    r.retain(|x| !Arc::ptr_eq(x, &e.reported));
                }
                k
            });
            !s.editors.is_empty()
        });
    }
}
