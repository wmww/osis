//! Text sessions behind editors: one per editor `(node, thing, aspect, map entry)`. A session
//! follows its field whoever writes it, so editors of one field each see the others' typing once
//! it is committed, and a cleared field or an undo shows in every open editor.
//! Typing goes here, one commit per pause; dropping a session commits what is pending.

use crate::store::Data;
use osis::{Result, Splice, Subscription, TextSession, Tid};
use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// An editor: its node, its thing, its aspect, the map entry within it (`None`: the whole aspect).
pub type Key = (super::NodePath, Tid, String, Option<String>);

/// How the shell hears that an editor's session merged a write its widget does not show yet.
pub type NotifyMerge = Arc<dyn Fn(Key) + Send + Sync>;

struct Editor {
    /// Kept for its life: `merged` fills through it.
    _merge: Subscription,
    session: TextSession,
    /// The field it edits, read to tell pending typing.
    field: (osis::DynamicAspectKey, osis::Path),
    /// What the widget shows. A merge reaches the session before the widget does, so the
    /// widget's typing is a change of this, not of the session's text.
    shown: String,
    /// The edits of merges since `shown` (filled on the dispatcher).
    merged: Arc<Mutex<Vec<Splice>>>,
}

/// The sessions a window's editors are bound to.
#[derive(Default)]
pub struct Sessions {
    editors: RefCell<HashMap<Key, Editor>>,
    notify: RefCell<Option<NotifyMerge>>,
}

impl Sessions {
    pub fn set_notify(&self, n: NotifyMerge) {
        *self.notify.borrow_mut() = Some(n);
    }

    /// Opens `key`'s session if needed; what the widget should show.
    pub fn show(&self, d: &Data, key: &Key) -> Result<String> {
        let mut editors = self.editors.borrow_mut();
        if let Some(e) = editors.get_mut(key) {
            e.shown = e.session.text();
            e.merged.lock().unwrap_or_else(|p| p.into_inner()).clear();
            return Ok(e.shown.clone());
        }
        let ak = d.db.aspect_key(&key.2)?;
        let path = key.3.as_ref().map_or_else(osis::Path::root, |k| osis::Path::root().push(k.as_str()));
        let session = d.db.at(key.1, ak.clone()).path(path.clone()).edit_text()?;
        let merged: Arc<Mutex<Vec<Splice>>> = Arc::default();
        let (m, k, notify) = (merged.clone(), key.clone(), self.notify.borrow().clone());
        let sub = session.on_merge(move |_, _, edits| {
            m.lock().unwrap_or_else(|p| p.into_inner()).extend_from_slice(edits);
            if let Some(n) = &notify {
                n(k.clone());
            }
        })?;
        let shown = session.text();
        editors.insert(key.clone(), Editor { _merge: sub, session, field: (ak, path), shown: shown.clone(), merged });
        Ok(shown)
    }

    /// The widget's whole new text: its change of what it showed, into its session.
    pub fn typed(&self, key: &Key, text: &str) -> Result<()> {
        let mut editors = self.editors.borrow_mut();
        let Some(e) = editors.get_mut(key) else { return Ok(()) };
        let shown = std::mem::replace(&mut e.shown, text.to_string());
        e.session.edit(&shown, text)
    }

    /// Whether an editor of `t` holds typing not committed yet: its session's text is not the
    /// field's.
    pub fn pending(&self, d: &Data, t: Tid) -> Result<bool> {
        for (_, e) in self.editors.borrow().iter().filter(|(k, _)| k.1 == t) {
            let field: Option<String> = d.db.at(t, e.field.0.clone()).path(e.field.1.clone()).get()?;
            if e.session.text() != field.unwrap_or_default() {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Takes what merges changed for this editor: the session's text, what the widget showed,
    /// the edits.
    pub fn merged(&self, key: &Key) -> Option<(String, String, Vec<Splice>)> {
        let mut editors = self.editors.borrow_mut();
        let e = editors.get_mut(key)?;
        let text = e.session.text();
        let edits = std::mem::take(&mut *e.merged.lock().unwrap_or_else(|p| p.into_inner()));
        let shown = std::mem::replace(&mut e.shown, text.clone());
        Some((text, shown, edits))
    }

    /// Commits the pending typing of `t`'s editors, which stay open.
    pub fn commit(&self, t: Tid) -> Result<()> {
        for (_, e) in self.editors.borrow().iter().filter(|(k, _)| k.1 == t) {
            e.session.commit()?;
        }
        Ok(())
    }

    /// Keeps only the editors still shown; a closed one's session commits what is pending.
    pub fn retain(&self, keep: impl Fn(&Key) -> bool) {
        self.editors.borrow_mut().retain(|k, _| keep(k));
    }
}
