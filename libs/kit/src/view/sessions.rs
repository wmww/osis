//! Text sessions bound to a node's `(thing, aspect)`, kept while an editor shows them. Typing goes here, one
//! commit per pause; dropping a session commits what is pending.

use crate::store::Data;
use osis::{Result, Splice, Subscription, TextSession, Tid};
use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// A session: the editor's node, its thing, its aspect, the map entry within it (`None`: the
/// whole aspect).
pub type Key = (super::NodePath, Tid, String, Option<String>);

/// How the shell hears of a remote merge into a thing's sessions.
pub type NotifyRemote = Arc<dyn Fn(Tid) + Send + Sync>;

struct Field {
    /// Kept for its life: `reported` fills through it.
    _remote: Subscription,
    session: TextSession,
    /// The text as the widget shows it (a remote merge may be newer).
    shown: String,
    /// The edits of remote merges since `shown` (reported on the session's thread).
    reported: Arc<Mutex<Vec<Splice>>>,
}

/// The sessions a window's editors are bound to.
#[derive(Default)]
pub struct Sessions {
    fields: RefCell<HashMap<Key, Field>>,
    notify: RefCell<Option<NotifyRemote>>,
}

impl Sessions {
    pub fn set_notify(&self, n: NotifyRemote) {
        *self.notify.borrow_mut() = Some(n);
    }

    /// Opens the session of `key` if needed; what the widget should show.
    pub fn show(&self, d: &Data, key: &Key) -> Result<String> {
        let mut fields = self.fields.borrow_mut();
        if let Some(f) = fields.get_mut(key) {
            f.shown = f.session.text();
            f.reported.lock().unwrap_or_else(|e| e.into_inner()).clear();
            return Ok(f.shown.clone());
        }
        let t = key.1;
        let ak = d.db.aspect_key(&key.2)?;
        let path = key.3.as_ref().map_or_else(osis::Path::root, |k| osis::Path::root().push(k.as_str()));
        let session = d.db.at(t, ak).path(path).edit_text()?;
        let reported = Arc::new(Mutex::new(Vec::new()));
        let r = reported.clone();
        let notify = self.notify.borrow().clone();
        let remote = session.on_remote(move |_, _, edits| {
            r.lock().unwrap_or_else(|e| e.into_inner()).extend_from_slice(edits);
            if let Some(n) = &notify {
                n(t);
            }
        })?;
        let shown = session.text();
        fields.insert(key.clone(), Field { _remote: remote, session, shown: shown.clone(), reported });
        Ok(shown)
    }

    /// The widget's whole new text, as one splice of its session.
    pub fn typed(&self, key: &Key, text: &str) -> Result<()> {
        let mut fields = self.fields.borrow_mut();
        let Some(f) = fields.get_mut(key) else { return Ok(()) };
        let shown = std::mem::replace(&mut f.shown, text.to_string());
        crate::edit::splice(&f.session, &shown, text)
    }

    /// Takes what a remote merge changed: the session's text, what the widget showed, the edits.
    pub fn merged(&self, key: &Key) -> Option<(String, String, Vec<Splice>)> {
        let mut fields = self.fields.borrow_mut();
        let f = fields.get_mut(key)?;
        let reported = std::mem::take(&mut *f.reported.lock().unwrap_or_else(|e| e.into_inner()));
        let text = f.session.text();
        let shown = std::mem::replace(&mut f.shown, text.clone());
        Some((text, shown, reported))
    }

    /// The keys open on `t`.
    pub fn keys_of(&self, t: Tid) -> Vec<Key> {
        self.fields.borrow().keys().filter(|k| k.1 == t).cloned().collect()
    }

    /// Closes `t`'s sessions, committing pending typing.
    pub fn close(&self, t: Tid) {
        self.fields.borrow_mut().retain(|k, _| k.1 != t);
    }

    /// Closes one session, committing pending typing.
    pub fn close_key(&self, key: &Key) {
        self.fields.borrow_mut().remove(key);
    }

    /// Keeps only the sessions still bound to an editor.
    pub fn retain(&self, keep: impl Fn(&Key) -> bool) {
        self.fields.borrow_mut().retain(|k, _| keep(k));
    }
}
