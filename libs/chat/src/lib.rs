//! Chat's shared rules (notes/chat.md): a chat is one actor C, participants hold write on it, a
//! message is one fire of C's `chat:msg~0`, its sender the commit's verified actor. Reading and
//! writing are plain `osis` calls on the keys in `schema`; this crate holds what every chat reader
//! and writer must do alike: create a chat under its retention rules, and the edit model (an edit
//! is a new message naming the one it changes, honored only from the same sender).

#![forbid(unsafe_code)]

use osis::core::{REQUIRED, Required, RequiredRules};
use osis::{Body, Commit, CommitFrom, CommitKind, CommitPos, CommitQuery, Error, History, Osis, PurgeBy, ReadOnly, Result, Retention, Tid, Time};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::time::Duration;

/// Typed keys of schema/chat.osis.
#[allow(dead_code, clippy::all)]
pub mod schema {
    use osis::generated as osis_schema;
    include!(concat!(env!("OUT_DIR"), "/chat.rs"));
}

use schema::EditMode;

/// How a chat starts. Default: author or admin deletes, edits purge the old text, nothing
/// disappears, a kicked participant retains a read-only copy.
#[derive(Clone, Debug)]
pub struct Options {
    pub name: String,
    /// Who may delete a message (`Nobody`: a permanent chat).
    pub purge: PurgeBy,
    pub edit: EditMode,
    /// Messages disappear this long after they are sent.
    pub disappear: Option<Duration>,
    /// A kicked participant retains a read-only copy, unless the kick says otherwise.
    pub retain_copies: bool,
    /// Whom the chat syncs with; empty: this node's saved peers. The maker's serving nodes take it
    /// by `admit own`; another serving node must admit it by its sync ID or admit anyone.
    pub peers: Vec<osis::Address>,
}

impl Default for Options {
    fn default() -> Options {
        Options { name: String::new(), purge: PurgeBy::AuthorOrAdmin, edit: EditMode::Purge, disappear: None, retain_copies: true, peers: Vec::new() }
    }
}

/// A new chat, this account its first admin, its retention rules set before anyone is granted:
/// every message kept for good under `o.purge` (expiry ends a disappearing one), and the plain
/// default for every other aspect, so junk nobody could erase is invalid. A participant could
/// otherwise write under an earlier rule. `sync`, then one commit: a crash between leaves a
/// synced chat of one with no rules; make another. Changing a rule later writes
/// `required^.0` whole; a participant who has not seen it writes under the old one and its node hears
/// `OwnWriteInvalid`.
pub fn create(db: &Osis, o: &Options) -> Result<Tid> {
    // the record alone first (`create()` alone is a role commit), then the rules and settings: a
    // joiner reads C's record among the role commits, not from a content commit it waits on
    // (notes/chat.md As built)
    let mut w = db.write();
    let c = w.create()?;
    w.commit()?;
    db.sync(c, &o.peers)?;
    let msg = Required { retention: Retention { by: o.purge, history: Some(History::FOREVER) }, expires: o.disappear, refuse_replace: false };
    let rules = RequiredRules { rules: BTreeMap::from([(schema::MSG.name(), msg)]), default: Some(Required::default()), retain_copies: o.retain_copies };
    let mut w = db.write();
    w.at(c, REQUIRED).set(&rules)?;
    w.at(c, schema::SETTINGS).set(&schema::Settings { name: o.name.clone(), edit: o.edit.clone() })?;
    w.commit()?;
    Ok(c)
}

/// What one write says it replaces: the original, and every earlier version it knew, whose
/// tombstones it answers for.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Claim {
    original: CommitPos,
    prior: Vec<CommitPos>,
}

/// One message commit as the edit model reads it.
#[derive(Clone, Debug, PartialEq)]
struct Entry {
    id: CommitPos,
    sender: Tid,
    time: Time,
    valid: bool,
    /// `Held(None)` too for a message whose edit claim names no place.
    body: Body<schema::Message>,
    claim: Option<Claim>,
}

fn entry_of(c: Tid, k: &Commit) -> Option<Entry> {
    if k.kind != CommitKind::Content {
        return None;
    }
    let part = k.at(c, schema::MSG)?;
    let mut claim = None;
    let body = match part.body {
        Body::Held(Some(m)) => match m.edit.as_ref().map(claim_of) {
            Some(None) => Body::Held(None),
            Some(Some(x)) => {
                claim = Some(x);
                Body::Held(Some(m))
            }
            None => Body::Held(Some(m)),
        },
        b => b,
    };
    Some(Entry { id: k.pos(), sender: k.stamp.actor, time: k.stamp.shown(), valid: part.valid, body, claim })
}

/// Another writer's claim: `None` when an id in it names no place.
fn claim_of(e: &schema::Edit) -> Option<Claim> {
    let mut prior = e.prior.iter().map(|x| x.parse().ok()).collect::<Option<Vec<CommitPos>>>()?;
    prior.sort();
    Some(Claim { original: e.original.parse().ok()?, prior })
}

/// Messages' commits, `limit` at a time.
fn query(from: CommitFrom, limit: usize) -> CommitQuery {
    CommitQuery { from, limit: Some(limit), kinds: vec![CommitKind::Content], ..Default::default() }
}

/// The entry at `id`, if it is here: a walk from `id`'s time (no lookup by id, issues/api-deferred.md).
fn entry_at(db: &ReadOnly, c: Tid, id: &CommitPos) -> Result<Option<Entry>> {
    let mut from = CommitFrom::After(CommitPos::time(id.at()));
    loop {
        let page = db.at(c, schema::MSG).fired(&query(from, 16))?;
        let Some(last) = page.commits.last().map(Commit::pos) else { return Ok(None) };
        if let Some(k) = page.commits.iter().find(|k| k.pos() == *id) {
            return Ok(entry_of(c, k));
        }
        if !page.more || last > *id {
            return Ok(None);
        }
        from = CommitFrom::After(last);
    }
}

/// The chat's edit mode (`Purge` before its settings are here).
fn edit_mode(db: &ReadOnly, c: Tid) -> Result<EditMode> {
    Ok(db.at(c, schema::SETTINGS).get()?.map_or(EditMode::Purge, |s| s.edit))
}

/// What `e` honestly replaces: its claim, if the original is here, is no edit itself and has the
/// same verified sender. Edits off, or anything else: `None`, and it is a message of its own.
fn checked(db: &ReadOnly, c: Tid, e: &Entry, mode: &EditMode) -> Result<Option<Claim>> {
    let Some(r) = e.claim.as_ref().filter(|_| *mode != EditMode::Off && e.valid) else { return Ok(None) };
    let Some(o) = entry_at(db, c, &r.original)? else { return Ok(None) };
    Ok((o.valid && o.sender == e.sender && o.claim.is_none() && o.id < e.id).then(|| r.clone()))
}

/// The message commit `k` honestly edits (its original's place), as the chat's edit rules judge
/// it here: what a watch of `chat:msg~0` shows a commit as. `None`: a message of its own.
pub fn edit_of(db: &ReadOnly, c: Tid, k: &Commit) -> Result<Option<CommitPos>> {
    let Some(e) = entry_of(c, k) else { return Ok(None) };
    Ok(checked(db, c, &e, &edit_mode(db, c)?)?.map(|r| r.original))
}

/// A message as a reader sees it: the original's place, the newest version's body.
#[derive(Clone, Debug, PartialEq)]
pub struct Message {
    /// The original's place: what replies and edits name.
    pub id: CommitPos,
    pub sender: Tid,
    pub time: Time,
    /// Valid. `false` only for this account's own write, turned invalid (a stale writer's, a kicked
    /// participant's): others' invalid writes are not listed. Sending it again is a new message.
    pub valid: bool,
    /// The newest version's.
    pub body: Body<schema::Message>,
    /// The newest version, when it is an edit.
    pub edited: Option<CommitPos>,
    /// Earlier versions whose text is here (the chat keeps edit history), newest first.
    pub earlier: Vec<(CommitPos, schema::Message)>,
    /// Every earlier version an edit named: its tombstones are this message's.
    pub prior: Vec<CommitPos>,
}

impl Message {
    /// The newest version's place.
    pub fn latest(&self) -> CommitPos {
        self.edited.unwrap_or(self.id)
    }

    /// The message it answers, when that names a place.
    pub fn reply_to(&self) -> Option<CommitPos> {
        match &self.body {
            Body::Held(Some(m)) => m.reply_to.as_deref().and_then(|r| r.parse().ok()),
            _ => None,
        }
    }
}

/// One page of messages.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Page {
    pub messages: Vec<Message>,
    pub more: bool,
    /// `false`: messages may yet arrive anywhere, older ones too (`CommitPage::complete`).
    pub complete: bool,
}

/// Entries a timeline asks for at a time. 1: a read per entry; more than a page holds: what it holds.
const FETCH: usize = 64;

/// The timeline, read from the newest back. Reading from the newest, it has seen every edit of an
/// older message when it reaches that message; an edit whose original is further back waits for it.
#[derive(Clone, Debug, PartialEq)]
pub struct Timeline {
    chat: Tid,
    me: Tid,
    mode: EditMode,
    cursor: CommitFrom,
    /// Fetched, not yet taken.
    fetched: VecDeque<Entry>,
    /// Nothing older to fetch.
    done: bool,
    complete: bool,
    /// Verified edits by original.
    edits: BTreeMap<CommitPos, Vec<(Entry, Claim)>>,
    /// Versions an edit answers for: their tombstones are not shown (by their sender's edit alone).
    answered: BTreeSet<(CommitPos, Tid)>,
}

impl Timeline {
    pub fn new(db: &ReadOnly, c: Tid) -> Result<Timeline> {
        Ok(Timeline::with_mode(db, c, edit_mode(db, c)?))
    }

    fn with_mode(db: &ReadOnly, c: Tid, mode: EditMode) -> Timeline {
        Timeline { chat: c, me: db.me(), mode, cursor: CommitFrom::Newest, fetched: VecDeque::new(), done: false, complete: true, edits: BTreeMap::new(), answered: BTreeSet::new() }
    }

    /// `find_all`, under the edit rules this timeline already read: one read of the settings for
    /// a page and its quotes.
    pub fn find_all(&self, db: &ReadOnly, ids: &[CommitPos]) -> Result<BTreeMap<CommitPos, Message>> {
        find_all_under(db, self.chat, &self.mode, ids)
    }

    /// The next `n` messages going back, newest first. `more`: there may be older ones.
    pub fn older(&mut self, db: &ReadOnly, n: usize) -> Result<Page> {
        let mut messages = Vec::new();
        while messages.len() < n {
            let Some(e) = self.next(db)? else { break };
            messages.extend(self.take(db, e)?);
        }
        Ok(Page { messages, more: !self.done || !self.fetched.is_empty(), complete: self.complete })
    }

    fn next(&mut self, db: &ReadOnly) -> Result<Option<Entry>> {
        if self.fetched.is_empty() && !self.done {
            let page = db.at(self.chat, schema::MSG).fired(&query(self.cursor, FETCH))?;
            self.complete &= page.complete;
            self.done = !page.more;
            if let Some(last) = page.commits.last() {
                self.cursor = CommitFrom::Before(last.pos());
            }
            self.fetched = page.commits.iter().filter_map(|k| entry_of(self.chat, k)).collect();
        }
        Ok(self.fetched.pop_front())
    }

    /// `e` reached going back: a message to show, or something that waits or hides.
    fn take(&mut self, db: &ReadOnly, e: Entry) -> Result<Option<Message>> {
        if !e.valid && e.sender != self.me {
            return Ok(None);
        }
        if let Some(r) = checked(db, self.chat, &e, &self.mode)? {
            for p in &r.prior {
                self.answered.insert((*p, e.sender));
            }
            self.edits.entry(r.original).or_default().push((e, r));
            return Ok(None);
        }
        let odd = matches!(e.body, Body::Held(None) | Body::TooLarge { .. });
        let answered = matches!(e.body, Body::Purged { .. }) && self.answered.contains(&(e.id, e.sender));
        if !self.edits.contains_key(&e.id) && (odd || answered) {
            return Ok(None);
        }
        let mut versions = self.edits.remove(&e.id).unwrap_or_default();
        // newest by (time, commit ID)
        versions.sort_by_key(|v| std::cmp::Reverse(v.0.id));
        let mut it = versions.into_iter();
        let newest = it.next();
        let prior = newest.as_ref().map_or_else(Vec::new, |(_, r)| r.prior.clone());
        let mut earlier: Vec<Entry> = it.map(|(v, _)| v).collect();
        let (body, edited) = match newest {
            Some((v, _)) => {
                earlier.push(e.clone());
                (v.body, Some(v.id))
            }
            None => (e.body.clone(), None),
        };
        // versions that are tombstones an edit answers for are no history to show
        let earlier = earlier
            .into_iter()
            .filter_map(|v| match v.body {
                Body::Held(Some(m)) => Some((v.id, m)),
                _ => None,
            })
            .collect();
        Ok(Some(Message { id: e.id, sender: e.sender, time: e.time, valid: e.valid, body, edited, earlier, prior }))
    }
}

/// The message `id` is a version of, reading back to its original.
pub fn find(db: &ReadOnly, c: Tid, id: &CommitPos) -> Result<Option<Message>> {
    Ok(find_all(db, c, &[*id])?.remove(id))
}

/// `find` of each of `ids` (those not here left out), in one walk back to the oldest: a reader
/// quoting many messages costs the messages since the oldest, not that once per quote.
pub fn find_all(db: &ReadOnly, c: Tid, ids: &[CommitPos]) -> Result<BTreeMap<CommitPos, Message>> {
    find_all_under(db, c, &edit_mode(db, c)?, ids)
}

fn find_all_under(db: &ReadOnly, c: Tid, mode: &EditMode, ids: &[CommitPos]) -> Result<BTreeMap<CommitPos, Message>> {
    // the ids asked for, by the original they are versions of
    let mut want: BTreeMap<CommitPos, Vec<CommitPos>> = BTreeMap::new();
    for id in ids.iter().collect::<BTreeSet<_>>() {
        let Some(e) = entry_at(db, c, id)? else { continue };
        let target = checked(db, c, &e, mode)?.map_or(*id, |r| r.original);
        want.entry(target).or_default().push(*id);
    }
    let mut out = BTreeMap::new();
    let Some(oldest) = want.keys().next().copied() else { return Ok(out) };
    let mut t = Timeline::with_mode(db, c, mode.clone());
    while !want.is_empty() {
        let page = t.older(db, FETCH)?;
        for m in &page.messages {
            for id in want.remove(&m.id).unwrap_or_default() {
                out.insert(id, m.clone());
            }
        }
        if !page.more || page.messages.last().is_some_and(|m| m.id < oldest) {
            break;
        }
    }
    Ok(out)
}

/// Edits one's own message: a new message naming the original and every earlier version, with the
/// newest version's name and reply; the newest wins everywhere, in any arrival order. Under
/// `EditMode::Purge` the old text is then purged by a commit of its own (a commit with a purge
/// request carries no expiry, and a disappearing chat's message must).
pub fn edit(db: &Osis, c: Tid, m: &Message, text: &str) -> Result<CommitPos> {
    let mode = edit_mode(db, c)?;
    if mode == EditMode::Off {
        return Err(Error::Invalid("editing is off in this chat".into()));
    }
    if m.sender != db.me() {
        return Err(Error::Invalid("only its sender edits a message".into()));
    }
    let held = versions_held(m);
    let mut prior: BTreeSet<CommitPos> = m.prior.iter().copied().collect();
    prior.extend(held.iter().copied());
    let (name, reply_to) = match &m.body {
        Body::Held(Some(x)) => (x.name.clone(), x.reply_to.clone()),
        _ => (None, None),
    };
    let edit = schema::Edit { original: m.id.to_string(), prior: prior.iter().map(CommitPos::to_string).collect() };
    let mut w = db.write();
    w.at(c, schema::MSG).fire(&schema::Message { text: text.into(), name, reply_to, edit: Some(edit) })?;
    let new = w.commit()?.ok_or_else(|| Error::Invalid("nothing written".into()))?.pos();
    // the old text stays where this account may not purge it (the chat's purge set)
    if mode == EditMode::Purge {
        match purge(db, c, &held) {
            Ok(()) | Err(Error::Permission { .. }) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(new)
}

/// The versions of `m` whose bodies are here.
fn versions_held(m: &Message) -> Vec<CommitPos> {
    let mut v: Vec<CommitPos> = m.earlier.iter().map(|e| e.0).collect();
    if matches!(m.body, Body::Held(Some(_))) {
        v.push(m.latest());
    }
    v
}

fn purge(db: &Osis, c: Tid, ids: &[CommitPos]) -> Result<()> {
    if ids.is_empty() {
        return Ok(());
    }
    let mut w = db.write();
    for i in ids {
        let id = i.commit().ok_or_else(|| Error::Invalid(format!("{i} names no message")))?;
        w.at(c, schema::MSG).purge(osis::Purge::Commit(id))?;
    }
    w.commit().map(drop)
}

/// Deletes a message for everyone, every version here, by its author or a moderator as the chat's
/// purge set says (`Permission` otherwise). Its tombstone stays and reaches new nodes.
pub fn delete(db: &Osis, c: Tid, m: &Message) -> Result<()> {
    purge(db, c, &versions_held(m))
}

/// Messages that reached this node after a cursor, oldest stamp first.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Since {
    /// Each under the original's id, in its newest version: an edit of an older message comes as
    /// that message again, a late post (a participant was offline) as what it is. A deletion of an
    /// older message moves no cursor: watch `chat:msg~0`.
    pub messages: Vec<Message>,
    /// Where to go on from: the entry that arrived last of those read (`None`: nothing read).
    pub cursor: Option<CommitPos>,
    pub more: bool,
    pub complete: bool,
}

/// An entry's place in this node's arrival order: a stamp says nothing of when a post got here.
fn arrival(k: &Commit) -> (Time, CommitPos) {
    (k.stamp.received, k.pos())
}

/// Every message commit here, and whether the listing is complete.
fn all_entries(db: &Osis, c: Tid) -> Result<(Vec<Commit>, bool)> {
    let (mut out, mut complete, mut from) = (Vec::new(), true, CommitFrom::Newest);
    loop {
        let page = db.at(c, schema::MSG).fired(&CommitQuery { from, kinds: vec![CommitKind::Content], ..Default::default() })?;
        complete &= page.complete;
        let Some(last) = page.commits.last().map(Commit::pos) else { break };
        out.extend(page.commits);
        if !page.more {
            break;
        }
        from = CommitFrom::Before(last);
    }
    Ok((out, complete))
}

/// Every message, newest first.
fn all_messages(db: &Osis, c: Tid) -> Result<Vec<Message>> {
    let (mut t, mut out) = (Timeline::new(db, c)?, Vec::new());
    loop {
        let p = t.older(db, FETCH)?;
        out.extend(p.messages);
        if !p.more {
            return Ok(out);
        }
    }
}

/// What arrived after `after` (`None`: from the start), `n` entries at most, read in arrival order.
/// A cursor is this node's: any entry's id, meaning the arrival of that entry. Reads the whole
/// history (no arrival index): for a reader that comes and goes; one that stays watches
/// `chat:msg~0` (`on_fire`).
/// Limits: an entry arriving in the cursor's millisecond with a lesser ID, or after this node's
/// clock jumped back past the cursor, is not returned.
pub fn since(db: &Osis, c: Tid, after: Option<&CommitPos>, n: usize) -> Result<Since> {
    let (all, complete) = all_entries(db, c)?;
    let from = after.map(|a| all.iter().find(|k| k.pos() == *a).map_or((a.at(), *a), arrival));
    let mut new: Vec<&Commit> = all.iter().filter(|k| from.is_none_or(|f| arrival(k) > f)).collect();
    new.sort_by_key(|k| arrival(k));
    let more = new.len() > n;
    new.truncate(n);
    let mut touched = BTreeSet::new();
    for k in &new {
        touched.insert(edit_of(db, c, k)?.unwrap_or(k.pos()));
    }
    let mut messages = if touched.is_empty() { Vec::new() } else { all_messages(db, c)? };
    messages.retain(|m| touched.contains(&m.id));
    messages.sort_by_key(|m| m.id);
    Ok(Since { messages, cursor: new.last().map(|k| k.pos()), more, complete })
}

/// The entry that arrived last here: the cursor of everything read so far.
pub fn cursor(db: &Osis, c: Tid) -> Result<Option<CommitPos>> {
    Ok(all_entries(db, c)?.0.iter().max_by_key(|k| arrival(k)).map(Commit::pos))
}
