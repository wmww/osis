//! Chat's shared rules (notes/chat.md): a chat is one actor C, participants hold write on it, a
//! message is one fire of C's `chat:msg~0`, its sender the commit's verified actor, an edit its
//! sender's `replace` of it. Reading and writing are plain `osis` calls on the keys in `schema`;
//! this crate holds what every chat writer must do alike: create a chat under its retention rules,
//! edit as the chat's settings say, and read by arrival (no osis listing orders by it).

#![forbid(unsafe_code)]

use osis::core::{RETENTION, RetentionEntry, RetentionSetting};
use osis::{Body, Commit, CommitFrom, CommitId, CommitKind, CommitPos, CommitQuery, Error, History, Osis, Purge, PurgeBy, ReadOnly, Result, Retention, Tid, Time};
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

/// Typed keys of schema/chat.osis.
#[allow(dead_code, clippy::all)]
pub mod schema {
    use osis::generated as osis_schema;
    include!(concat!(env!("OUT_DIR"), "/chat.rs"));
}

use schema::{EditMode, MSG, SETTINGS};

impl schema::Message {
    /// The message it answers, when that names a commit: another writer's id that does not is no
    /// reply.
    pub fn reply(&self) -> Option<CommitId> {
        self.reply_to.as_deref().and_then(|r| r.parse().ok())
    }
}

/// How a chat starts. Default: author or admin deletes, edits purge the old text, nothing
/// disappears, a kicked participant retains a read-only copy.
#[derive(Clone, Debug)]
pub struct Options {
    pub name: String,
    /// Who may delete a message besides admins: `AuthorOrAdmin`, `Admin` or `Writer` (admins
    /// may always purge; `create` refuses another).
    pub purge: PurgeBy,
    /// What an edit does to the old text; `None`: messages cannot be edited (the message rule
    /// refuses replacements).
    pub edit: Option<EditMode>,
    /// Messages disappear this long after they are sent.
    pub disappear: Option<Duration>,
    /// A kicked participant retains a read-only copy, unless the kick says otherwise.
    pub retain_copies: bool,
    /// Whom the chat syncs with; empty: this node's saved peers. A serving node that reads it serves
    /// it; another must admit it by its sync ID or admit anyone.
    pub peers: Vec<osis::Address>,
}

impl Default for Options {
    fn default() -> Options {
        Options { name: String::new(), purge: PurgeBy::AuthorOrAdmin, edit: Some(EditMode::Purge), disappear: None, retain_copies: true, peers: Vec::new() }
    }
}

/// A new chat, this account its first admin, its settings written before anyone is granted:
/// every message kept for good (expiry ends a disappearing one), replacements refused when
/// editing is off, who may delete a message. `sync`, then one commit: a crash between leaves a
/// synced chat of one with no settings; make another. Changing a setting later writes
/// `retention^.0` whole; a participant who has not seen it writes as before (its messages keep
/// the expiry they were written with).
pub fn create(db: &Osis, o: &Options) -> Result<Tid> {
    let purge = match o.purge {
        PurgeBy::AuthorOrAdmin => None,
        PurgeBy::Admin => Some(schema::Deletes::Admins),
        PurgeBy::Writer => Some(schema::Deletes::Anyone),
        _ => return Err(Error::Invalid("a chat's messages are purgeable by the author or admins, admins, or any writer".into())),
    };
    // the record alone first (`create()` alone is a role commit), then the settings: a joiner
    // reads C's record among the role commits, not from a content commit it waits on
    // (notes/chat.md As built)
    let mut w = db.write();
    let c = w.create()?;
    w.commit()?;
    db.sync(c, &o.peers)?;
    let msg = RetentionEntry { history: Some(History::FOREVER), expires: o.disappear, refuse_replace: o.edit.is_none() };
    let setting = RetentionSetting { rules: BTreeMap::from([(MSG.name(), msg)]), default: None, retain_copies: o.retain_copies };
    let mut w = db.write();
    w.at(c, RETENTION).set(&setting)?;
    w.at(c, SETTINGS).set(&schema::Settings { name: o.name.clone(), edit: o.edit.clone().unwrap_or(EditMode::Purge), purge })?;
    w.commit()?;
    Ok(c)
}

/// The retention a message on chat `c` carries: who may delete it, as the chat's settings say.
pub fn message_retention(db: &Osis, c: Tid) -> Result<Retention> {
    let by = match db.at(c, SETTINGS).get()?.and_then(|s| s.purge) {
        None | Some(schema::Deletes::SenderOrAdmins) => PurgeBy::AuthorOrAdmin,
        Some(schema::Deletes::Admins) => PurgeBy::Admin,
        Some(schema::Deletes::Anyone) => PurgeBy::Writer,
    };
    Ok(Retention { by })
}

/// Sends `m` on chat `c`, purgeable as the chat's settings say: its id.
pub fn send(db: &Osis, c: Tid, m: &schema::Message) -> Result<CommitId> {
    let r = message_retention(db, c)?;
    let mut w = db.write();
    w.at(c, MSG).retention(r).fire(m)?;
    Ok(w.commit()?.ok_or_else(|| Error::Invalid("nothing written".into()))?.stamp.id)
}

/// Replaces one's own message `id` (the original's id) with `text`, keeping its name and reply.
/// Under `EditMode::Purge` the same commit purges the old text, where the chat's purge set lets
/// this account (under `admin` it stays). `Invalid` from osis for another's message,
/// a version's id, or a chat with editing off.
pub fn edit(db: &Osis, c: Tid, id: CommitId, text: &str) -> Result<()> {
    let k = db.at(c, MSG).commit(id)?.ok_or_else(|| Error::Invalid(format!("no message {id}")))?;
    let (name, reply_to) = match k.at(c, MSG).map(|p| p.body) {
        Some(Body::Held(Some(m))) => (m.name, m.reply_to),
        _ => (None, None),
    };
    let new = schema::Message { text: text.into(), name, reply_to };
    let purge = db.at(c, SETTINGS).get()?.is_none_or(|s| s.edit == EditMode::Purge);
    let r = message_retention(db, c)?;
    let write = |purge: bool| -> Result<()> {
        let mut w = db.write();
        w.at(c, MSG).retention(r).replace(id, &new)?;
        if purge {
            w.at(c, MSG).purge(Purge::Commit(id))?;
        }
        w.commit().map(drop)
    };
    // a purge this account may not make refuses the whole commit: the edit goes alone
    match write(purge) {
        Err(Error::Permission { .. }) if purge => write(false),
        r => r,
    }
}

/// A place in this node's arrival order: when an entry got here, then its place. A stamp says
/// nothing of when a post arrived, so a post made offline comes after what was read before it
/// arrived. Text form `RECEIVED/PLACE`; this node's, not to be carried to another.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Cursor(Time, CommitPos);

impl std::fmt::Display for Cursor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.0.0, self.1)
    }
}

impl std::str::FromStr for Cursor {
    type Err = Error;
    fn from_str(s: &str) -> Result<Cursor> {
        let bad = || Error::Invalid(format!("not a cursor: {s:?}"));
        let (t, p) = s.split_once('/').ok_or_else(bad)?;
        Ok(Cursor(Time(t.parse().map_err(|_| bad())?), p.parse().map_err(|_| bad())?))
    }
}

fn arrival(k: &Commit) -> Cursor {
    Cursor(k.stamp.received, k.pos())
}

/// Messages that reached this node after a cursor, oldest place first.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Since {
    /// Each as `fired` lists it, under its id with its newest text: an edit of an older message
    /// comes as that message again, a late post (a participant was offline) as what it is. A
    /// deletion of an older message moves no cursor: watch `chat:msg~0`.
    pub messages: Vec<Commit>,
    /// Where to go on from: the entry that arrived last of those read (`None`: nothing read).
    pub cursor: Option<Cursor>,
    pub more: bool,
    /// `false`: messages may yet arrive anywhere, older ones too (`CommitPage::complete`).
    pub complete: bool,
}

fn content(from: CommitFrom) -> CommitQuery {
    CommitQuery { from, kinds: vec![CommitKind::Content], ..Default::default() }
}

/// Every page of `page`, from the newest; and whether all were complete.
fn all(page: impl Fn(CommitFrom) -> Result<osis::CommitPage>) -> Result<(Vec<Commit>, bool)> {
    let (mut out, mut complete, mut from) = (Vec::new(), true, CommitFrom::Newest);
    loop {
        let p = page(from)?;
        complete &= p.complete;
        let Some(last) = p.commits.last().map(Commit::pos) else { break };
        out.extend(p.commits);
        if !p.more {
            break;
        }
        from = CommitFrom::Before(last);
    }
    Ok((out, complete))
}

/// Every message here, and each entry's arrival with the message it is of: a message's own and,
/// for an edited one, each version's.
struct Arrivals {
    messages: BTreeMap<CommitId, Commit>,
    entries: Vec<(Cursor, CommitId)>,
    complete: bool,
}

fn arrivals(db: &ReadOnly, c: Tid) -> Result<Arrivals> {
    let (fires, mut complete) = all(|f| db.at(c, MSG).fired(&content(f)))?;
    let mut entries = Vec::new();
    for k in &fires {
        let id = k.stamp.id;
        if k.at(c, MSG).is_some_and(|p| p.edited.is_some()) {
            let (versions, done) = all(|f| db.at(c, MSG).versions(id, &content(f)))?;
            complete &= done;
            entries.extend(versions.iter().map(|v| (arrival(v), id)));
        } else {
            entries.push((arrival(k), id));
        }
    }
    Ok(Arrivals { messages: fires.into_iter().map(|k| (k.stamp.id, k)).collect(), entries, complete })
}

/// What arrived after `after` (`None`: from the start), `n` entries at most, read in arrival
/// order. Reads the whole history (no arrival index): for a reader that comes and goes; one that
/// stays watches `chat:msg~0` (`on_fire`).
/// Limit: an entry arriving in the cursor's millisecond with a lesser place, or after this node's
/// clock jumped back past the cursor, is not returned.
pub fn since(db: &ReadOnly, c: Tid, after: Option<&Cursor>, n: usize) -> Result<Since> {
    let Arrivals { messages, mut entries, complete } = arrivals(db, c)?;
    entries.retain(|e| after.is_none_or(|a| e.0 > *a));
    entries.sort();
    let more = entries.len() > n;
    entries.truncate(n);
    let touched: BTreeSet<CommitId> = entries.iter().map(|e| e.1).collect();
    let mut shown: Vec<Commit> = messages.into_iter().filter(|(id, _)| touched.contains(id)).map(|x| x.1).collect();
    shown.sort_by_key(Commit::pos);
    Ok(Since { messages: shown, cursor: entries.last().map(|e| e.0), more, complete })
}

/// The cursor of everything here: the entry that arrived last.
pub fn cursor(db: &ReadOnly, c: Tid) -> Result<Option<Cursor>> {
    Ok(arrivals(db, c)?.entries.into_iter().map(|e| e.0).max())
}
