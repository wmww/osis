//! Group chat on osis primitives alone (notes/chat.md): a chat is one
//! actor C; participants hold write on it; a message is one kept write on C's `chat:msgs.0`, its
//! sender the commit's verified actor. No participant actor, participant list or per-message thing.

#![forbid(unsafe_code)]

use osis::core::{REQUIRED, Required, RequiredRules};
use osis::{CommitId, CommitKind, Error, GrantOpts, History, HistoryBody, HistoryEntry, HistoryEvent, HistoryFrom, HistoryPos, Osis, Result, Retention, Role, SetRoleOpts, Subscription, Tid};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::time::Duration;

pub use osis::PurgeBy;

/// Typed keys of schema/chat.osis.
#[allow(dead_code, clippy::all)]
pub mod schema {
    use osis::generated as osis_schema;
    include!(concat!(env!("OUT_DIR"), "/chat.rs"));
}

/// What happens to the old text at an edit (design E, Edit). A chat setting.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum EditMode {
    /// The old text is purged.
    #[default]
    Purge,
    /// The old text stays, as visible edit history.
    Keep,
    /// No editing: `replaces` is ignored.
    Off,
}

impl EditMode {
    fn name(self) -> &'static str {
        match self {
            EditMode::Purge => "purge",
            EditMode::Keep => "keep",
            EditMode::Off => "off",
        }
    }
}

impl From<EditMode> for schema::EditMode {
    fn from(m: EditMode) -> schema::EditMode {
        match m {
            EditMode::Purge => schema::EditMode::Purge,
            EditMode::Keep => schema::EditMode::Keep,
            EditMode::Off => schema::EditMode::Off,
        }
    }
}

impl From<schema::EditMode> for EditMode {
    fn from(m: schema::EditMode) -> EditMode {
        match m {
            schema::EditMode::Purge => EditMode::Purge,
            schema::EditMode::Keep => EditMode::Keep,
            schema::EditMode::Off => EditMode::Off,
        }
    }
}

impl std::str::FromStr for EditMode {
    type Err = Error;
    fn from_str(s: &str) -> Result<EditMode> {
        [EditMode::Purge, EditMode::Keep, EditMode::Off].into_iter().find(|m| m.name() == s).ok_or_else(|| Error::Invalid(format!("no edit mode {s:?}")))
    }
}

/// How a chat starts. Default: Signal-like: author or admin deletes, edits purge, nothing
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

/// The retention rules of a chat: the message rule, and the plain default for every other aspect, so
/// junk that nobody could erase is invalid.
fn rules(purge: PurgeBy, disappear: Option<Duration>, retain_copies: bool) -> RequiredRules {
    // disappearing messages promise no history, but `nobody` keeps it forever (expiry still ends it)
    let history = if disappear.is_some() && purge != PurgeBy::Nobody { None } else { Some(History::FOREVER) };
    let msgs = Required { retention: Retention { by: purge, history }, expires: disappear };
    RequiredRules { rules: BTreeMap::from([(schema::MSGS.name(), msgs)]), default: Some(Required::default()), retain_copies }
}

/// A new chat, this account its first admin: required retention set before anyone is granted, so no
/// participant can write under an earlier key. `sync`, then one commit: a crash between leaves a
/// synced chat of one with no rules; make another.
pub fn create(db: &Osis, o: &Options) -> Result<Tid> {
    // the record alone first (`create()` alone is a role commit), then the rules and
    // settings: a joiner reads C's record among the role commits, not from a content commit it
    // waits on (notes/chat.md As built)
    let mut w = db.write();
    let c = w.create()?;
    w.commit()?;
    db.sync(c, &o.peers)?;
    let mut w = db.write();
    w.at(c, REQUIRED).set(&rules(o.purge, o.disappear, o.retain_copies))?;
    w.at(c, schema::SETTINGS).set(&schema::Settings { name: o.name.clone(), edit: o.edit.into() })?;
    w.commit()?;
    Ok(c)
}

/// A chat's settings, as this node reads them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Settings {
    pub name: String,
    pub edit: EditMode,
    pub purge: PurgeBy,
    pub disappear: Option<Duration>,
    pub retain_copies: bool,
}

/// What this node knows of a chat's settings.
pub fn settings(db: &Osis, c: Tid) -> Result<Settings> {
    let mut s = Settings::default();
    if let Some(x) = db.at(c, schema::SETTINGS).get()? {
        (s.name, s.edit) = (x.name, x.edit.into());
    }
    let r = db.at(c, REQUIRED).get()?.unwrap_or_default();
    s.retain_copies = r.retain_copies;
    if let Some(m) = r.rules.get(&schema::MSGS.name()) {
        s.purge = m.retention.by;
        s.disappear = m.expires;
    }
    Ok(s)
}

/// The chats this node syncs: its synced groups (`Osis::status`) with chat settings, in tid order;
/// not one this account is leaving, nor a joined one before its settings arrive. A copy retained after
/// a kick or leave is not synced: `Osis::retained_copies`. Re-list on `Osis::on_status_change`.
pub fn chats(db: &Osis) -> Result<Vec<Tid>> {
    // a value of another shape is someone's junk: not a chat
    Ok(db.status()?.groups.into_iter().filter(|(t, g)| !g.leaving && matches!(db.at(*t, schema::SETTINGS).get(), Ok(Some(_)))).map(|(t, _)| t).collect())
}

/// Sets the disappearing timer: later messages take it, earlier ones keep what they have. A participant
/// who has not seen the change writes under the old rule, and its node hears `on_rejected`.
pub fn set_disappearing(db: &Osis, c: Tid, d: Option<Duration>) -> Result<()> {
    let s = settings(db, c)?;
    let mut w = db.write();
    w.at(c, REQUIRED).set(&rules(s.purge, d, s.retain_copies))?;
    w.commit()?;
    Ok(())
}

/// Adds a participant (an admin's call): `Write` to post, `Admin` to moderate, `Read` for a channel.
/// A chat is synced from `create`, so this only grants. Below a role the account lost by leaving
/// or an ending grant it is `Invalid`: `Osis::set_role` keeps what they wrote.
pub fn add(db: &Osis, c: Tid, account: Tid, role: Role) -> Result<()> {
    db.grant(c, account, role, GrantOpts::default())
}

/// Removes a participant, a read-only copy left to them or not by `retain_copy` (`None`: the chat's
/// default). What they sent stays where any participant had received it; to keep more, sync first
/// (`Osis::set_role`).
pub fn kick(db: &Osis, c: Tid, account: Tid, retain_copy: Option<bool>) -> Result<()> {
    db.set_role(c, account, None, SetRoleOpts { retain_copy })
}

/// A link anyone holding it can join by, as `role`.
pub fn link(db: &Osis, c: Tid, role: Role, single_use: bool) -> Result<osis::ShareLink> {
    db.make_link(c, role, osis::LinkOpts { until: None, single_use, direct: false })
}

/// Joins by link: the chat, once it is here. Kicks reach a joiner like any participant (`kick`). A chat
/// already held (`chats`) is returned as is, also when redeeming failed because it is: the link
/// may be used up, or its maker or a participant pasted it. So a link never raises a participant's role, and
/// one whose target names a held chat opens that chat and joins nothing, whatever its key is. One
/// naming a chat not held joins only if its key is on that chat (`Osis::redeem`).
pub async fn join(db: &Osis, l: &osis::ShareLink) -> Result<Tid> {
    let c = l.target()?;
    let held = || chats(db).is_ok_and(|x| x.contains(&c));
    if held() {
        return Ok(c);
    }
    db.redeem(l).await.or_else(|e| if held() { Ok(c) } else { Err(e) })
}

/// Removes this account: every grant it holds the chat through (a link joiner's is on the link's
/// actor).
pub fn leave(db: &Osis, c: Tid) -> Result<()> {
    let me = db.me();
    for way in db.holders(c)?.into_iter().filter(|h| h.actor == me) {
        db.leave(me, way.through.last().copied().unwrap_or(c))?;
    }
    Ok(())
}

/// Whether `h` is an actor accounts hold the chat through, as a link's actor K (spec/permissions.md
/// §7) or a team: some holder of `h` has holders itself. An account's holders are its nodes and its
/// recovery key, key actors that nobody holds; a team's and K's include accounts.
fn held_through(db: &Osis, h: Tid) -> Result<bool> {
    for m in db.grants(h)?.into_keys() {
        if !db.grants(m)?.is_empty() {
            return Ok(true);
        }
    }
    Ok(false)
}

/// A link's key on K: a key actor (nobody holds it) with `may_grant`. Never an account.
fn link_key(db: &Osis, m: Tid, e: &osis::Grant) -> Result<bool> {
    Ok(e.may_grant.is_some() && db.grants(m)?.is_empty())
}

/// Who holds the chat, with the role they have: its direct holders and those holding it through an
/// actor (`held_through`), link joiners so, at the lesser of the two roles. As this node knows them:
/// a direct participant learns a link joiner from its first post, and lists K until then if nobody else
/// of K is known (`kick` of K ends everyone behind it).
pub fn participants(db: &Osis, c: Tid) -> Result<BTreeMap<Tid, Role>> {
    let mut out = BTreeMap::new();
    let mut put = |m: Tid, r: Role| {
        let e = out.entry(m).or_insert(r);
        *e = r.max(*e);
    };
    for (h, e) in db.grants(c)? {
        if !held_through(db, h)? {
            put(h, e.role);
            continue;
        }
        let behind = db.grants(h)?;
        if behind.is_empty() {
            put(h, e.role);
        }
        for (m, x) in &behind {
            if !link_key(db, *m, x)? {
                put(*m, x.role.min(e.role));
            }
        }
    }
    Ok(out)
}

/// The links that work on the chat, as this node knows them: each link's actor K and its role. Not
/// participants; `osis::Osis::links` has what its maker alone knows.
pub fn links(db: &Osis, c: Tid) -> Result<BTreeMap<Tid, Role>> {
    let mut out = BTreeMap::new();
    for (h, e) in db.grants(c)? {
        if !held_through(db, h)? {
            continue;
        }
        for (m, x) in db.grants(h)? {
            if link_key(db, m, &x)? {
                out.insert(h, e.role);
                break;
            }
        }
    }
    Ok(out)
}

/// Where a message is: its place in the chat's history (`TS/COMMIT`).
pub type Id = HistoryPos;

fn id_read(s: &str) -> Option<Id> {
    s.parse().ok()
}

/// What one write says it replaces: the original, and every earlier version it knew, whose
/// tombstones it answers for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Replaces {
    pub original: Id,
    pub prior: Vec<Id>,
}

/// A message to send.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Draft {
    pub text: String,
    /// The name to show for its sender. In the signed body, so nobody can name another's messages;
    /// the sender's own word, as the tid beside it is not (no name registry).
    pub name: Option<String>,
    /// The message it answers.
    pub reply_to: Option<Id>,
}

impl Draft {
    pub fn text(t: &str) -> Draft {
        Draft { text: t.into(), ..Draft::default() }
    }
}

fn message_of(d: &Draft, r: Option<&Replaces>) -> schema::Message {
    let edit = r.map(|r| schema::Edit { original: r.original.to_string(), prior: r.prior.iter().map(Id::to_string).collect() });
    schema::Message { text: d.text.clone(), name: d.name.clone(), reply_to: d.reply_to.as_ref().map(Id::to_string), edit }
}

/// Another writer's input: an edit naming no message reads as `None`, a reply to none as no reply.
fn read_message(m: schema::Message) -> Option<(Draft, Option<Replaces>)> {
    let r = match m.edit {
        None => None,
        Some(e) => {
            let mut prior = e.prior.iter().map(|x| id_read(x)).collect::<Option<Vec<_>>>()?;
            prior.sort();
            Some(Replaces { original: id_read(&e.original)?, prior })
        }
    };
    let reply_to = m.reply_to.as_deref().and_then(id_read);
    Some((Draft { text: m.text, name: m.name, reply_to }, r))
}

/// Sends a message: one commit, one delta. Retention and expiry come from the chat's rule, filled
/// by the node. `overwrite`, not `set`: a set equal to the last message would write nothing.
pub fn send(db: &Osis, c: Tid, d: &Draft) -> Result<Id> {
    write_body(db, c, d, None)
}

/// `send` of plain text.
pub fn post(db: &Osis, c: Tid, text: &str) -> Result<Id> {
    send(db, c, &Draft::text(text))
}

/// Sends again one's own message that turned invalid (`Message::valid`, `on_rejected`): the same
/// text, name and reply, as a new message. The old one stays, to this account alone.
pub fn resend(db: &Osis, c: Tid, m: &Message) -> Result<Id> {
    let Body::Text(text) = &m.body else { return Err(Error::Invalid("its text is not here".into())) };
    if m.valid || m.sender != db.me() {
        return Err(Error::Invalid("only one's own undelivered message is sent again".into()));
    }
    send(db, c, &Draft { text: text.clone(), name: m.name.clone(), reply_to: m.reply_to })
}

fn write_body(db: &Osis, c: Tid, d: &Draft, r: Option<&Replaces>) -> Result<Id> {
    let mut w = db.write();
    w.at(c, schema::MSGS).overwrite(&message_of(d, r))?;
    let done = w.commit()?.ok_or_else(|| Error::Invalid("nothing written".into()))?;
    Ok(done.pos())
}

/// A write claiming to replace `original`, past `edit`'s checks: what a hostile participant can do. Tests.
#[doc(hidden)]
pub fn write_raw_edit(db: &Osis, c: Tid, text: &str, original: Id) -> Id {
    write_raw_replaces(db, c, text, &Replaces { original, prior: vec![original] })
}

/// A write with any claim at all. Tests.
#[doc(hidden)]
pub fn write_raw_replaces(db: &Osis, c: Tid, text: &str, r: &Replaces) -> Id {
    write_body(db, c, &Draft::text(text), Some(r)).unwrap_or(r.original)
}

/// What is here of a message's text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Body {
    Text(String),
    /// Deleted for everyone: a tombstone that new nodes get too. `who`: verified, as a sender is
    /// (`None`: the request's header is not here).
    Deleted { by: CommitId, who: Option<Tid> },
    /// Expired, or dropped by a keep bound: leaves the timeline.
    Gone,
    /// Its header came, its body not yet.
    NotFetched,
    /// Not a message (another version's, or junk).
    Odd,
}

/// One write on a message aspect, as its signed header and this node say.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub id: Id,
    /// The verified sender, when `valid`.
    pub sender: Tid,
    pub node: Tid,
    /// The time to show: `min(ts, received)`.
    pub time: u64,
    /// When it reached this node: what a cursor goes by.
    pub received: u64,
    pub valid: bool,
    pub body: Body,
    /// The name its sender gave.
    pub name: Option<String>,
    pub reply_to: Option<Id>,
    /// What it claims to replace, unchecked (`replaces_of` checks).
    pub replaces: Option<Replaces>,
}

fn entry_of(e: HistoryEntry<schema::Message>) -> Option<Entry> {
    if e.kind != CommitKind::Content {
        return None;
    }
    let pos = e.pos();
    let (mut name, mut reply_to) = (None, None);
    let (body, replaces) = match e.body {
        HistoryBody::Held(v) => match v.and_then(read_message) {
            Some((d, r)) => {
                (name, reply_to) = (d.name, d.reply_to);
                (Body::Text(d.text), r)
            }
            None => (Body::Odd, None),
        },
        HistoryBody::TooLarge { .. } => (Body::Odd, None),
        HistoryBody::Purged { by, actor } => (Body::Deleted { by, who: actor }, None),
        HistoryBody::Gone => (Body::Gone, None),
        HistoryBody::NotFetched => (Body::NotFetched, None),
    };
    Some(Entry { id: pos, sender: e.commit.actor, node: e.commit.node, time: e.commit.shown().0, received: e.commit.received.0, valid: e.valid, body, name, reply_to, replaces })
}

/// One page of raw entries.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Entries {
    pub entries: Vec<Entry>,
    pub more: bool,
    /// `false`: entries may yet arrive anywhere, older ones too: not fetched, not absent.
    pub complete: bool,
}

/// Raw entries by `(ts, ID)`, in `from`'s direction (`Newest`, `Before`: towards older).
pub fn entries(db: &Osis, c: Tid, from: HistoryFrom, limit: usize) -> Result<Entries> {
    let page = db.at(c, schema::MSGS).history(from, limit)?;
    Ok(Entries { entries: page.entries.into_iter().filter_map(entry_of).collect(), more: page.more, complete: page.complete })
}

/// The entry at `id`, if it is here.
pub fn entry_at(db: &Osis, c: Tid, id: &Id) -> Result<Option<Entry>> {
    let mut from = HistoryFrom::After(HistoryPos::time(id.at()));
    loop {
        let page = db.at(c, schema::MSGS).history(from, 16)?;
        let Some(last) = page.entries.last().map(|e| e.pos()) else { return Ok(None) };
        if let Some(e) = page.entries.into_iter().find(|e| e.pos() == *id) {
            return Ok(entry_of(e));
        }
        if !page.more || last > *id {
            return Ok(None);
        }
        from = HistoryFrom::After(last);
    }
}

/// What `e` honestly replaces: its claim, if the original is here, is no edit itself and has the
/// same verified sender. Edits off, or anything else: `None`, and it is a message of its own.
pub fn replaces_of(db: &Osis, c: Tid, e: &Entry, mode: EditMode) -> Result<Option<Replaces>> {
    let Some(r) = e.replaces.as_ref().filter(|_| mode != EditMode::Off && e.valid) else { return Ok(None) };
    let Some(o) = entry_at(db, c, &r.original)? else { return Ok(None) };
    Ok((o.valid && o.sender == e.sender && o.replaces.is_none() && o.id < e.id).then(|| r.clone()))
}

/// A message as a reader sees it: the original's place, the newest version's text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    /// The original's id: what replies, reactions and edits name.
    pub id: Id,
    pub sender: Tid,
    pub time: u64,
    /// Valid. `false` only for this account's own write, turned invalid (a stale writer's, a kicked
    /// participant's): others' invalid writes are not shown.
    pub valid: bool,
    pub body: Body,
    /// The name and reply of the version shown.
    pub name: Option<String>,
    pub reply_to: Option<Id>,
    /// The version shown, when it is an edit: its id.
    pub edited: Option<Id>,
    /// Earlier versions still known, newest first. Their text, when the chat keeps edit history.
    pub earlier: Vec<Entry>,
    /// Every earlier version an edit named: its tombstones are this message's.
    pub prior: Vec<Id>,
}

impl Message {
    /// The newest version's id.
    pub fn latest(&self) -> Id {
        self.edited.unwrap_or(self.id)
    }
}

/// One page of messages.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Page {
    pub messages: Vec<Message>,
    pub more: bool,
    pub complete: bool,
}

/// Entries a timeline asks for at a time. 1: a read per entry; more than a page holds: what it holds.
const FETCH: usize = 64;

/// The timeline, read from the newest back. Reading from the newest, it has seen every edit of an
/// older message when it reaches that message; an edit whose original is further back waits for it.
pub struct Timeline {
    chat: Tid,
    me: Tid,
    mode: EditMode,
    cursor: HistoryFrom,
    /// Fetched, not yet taken.
    fetched: VecDeque<Entry>,
    /// Nothing older to fetch.
    done: bool,
    complete: bool,
    /// Verified edits by original.
    edits: BTreeMap<Id, Vec<(Entry, Replaces)>>,
    /// Versions an edit answers for: their tombstones are not shown (by their sender's edit alone).
    answered: BTreeSet<(Id, Tid)>,
}

impl Timeline {
    pub fn new(db: &Osis, c: Tid) -> Result<Timeline> {
        Ok(Timeline { chat: c, me: db.me(), mode: settings(db, c)?.edit, cursor: HistoryFrom::Newest, fetched: VecDeque::new(), done: false, complete: true, edits: BTreeMap::new(), answered: BTreeSet::new() })
    }

    /// The next `n` messages going back, newest first. `more`: there may be older ones.
    pub fn older(&mut self, db: &Osis, n: usize) -> Result<Page> {
        let mut messages = Vec::new();
        while messages.len() < n {
            let Some(e) = self.next(db)? else { break };
            messages.extend(self.take(db, e)?);
        }
        Ok(Page { messages, more: !self.done || !self.fetched.is_empty(), complete: self.complete })
    }

    fn next(&mut self, db: &Osis) -> Result<Option<Entry>> {
        if self.fetched.is_empty() && !self.done {
            let got = entries(db, self.chat, self.cursor, FETCH)?;
            self.complete &= got.complete;
            self.done = !got.more;
            if let Some(last) = got.entries.last() {
                self.cursor = HistoryFrom::Before(last.id);
            }
            self.fetched = got.entries.into();
        }
        Ok(self.fetched.pop_front())
    }

    /// `e` reached going back: a message to show, or something that waits or hides.
    fn take(&mut self, db: &Osis, e: Entry) -> Result<Option<Message>> {
        if !e.valid && e.sender != self.me {
            return Ok(None);
        }
        if let Some(r) = replaces_of(db, self.chat, &e, self.mode)? {
            for p in &r.prior {
                self.answered.insert((*p, e.sender));
            }
            self.edits.entry(r.original).or_default().push((e, r));
            return Ok(None);
        }
        if !self.edits.contains_key(&e.id) && (matches!(e.body, Body::Gone | Body::Odd) || (matches!(e.body, Body::Deleted { .. }) && self.answered.contains(&(e.id, e.sender)))) {
            return Ok(None);
        }
        let mut versions = self.edits.remove(&e.id).unwrap_or_default();
        // newest by (time, commit ID)
        versions.sort_by_key(|v| std::cmp::Reverse(v.0.id));
        let mut it = versions.into_iter();
        let newest = it.next();
        let prior = newest.as_ref().map_or_else(Vec::new, |(_, r)| r.prior.clone());
        let mut earlier: Vec<Entry> = it.map(|(v, _)| v).collect();
        let (body, name, reply_to, edited) = match newest {
            Some((v, _)) => {
                earlier.push(e.clone());
                (v.body, v.name, v.reply_to, Some(v.id))
            }
            None => (e.body.clone(), e.name.clone(), e.reply_to, None),
        };
        // versions that are tombstones an edit answers for are no history to show
        earlier.retain(|v| matches!(v.body, Body::Text(_)));
        Ok(Some(Message { id: e.id, sender: e.sender, time: e.time, valid: e.valid, body, name, reply_to, edited, earlier, prior }))
    }
}

/// Messages that reached this node after a cursor, oldest stamp first.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Since {
    /// Each under the original's id, in its newest version: an edit of an older message comes as
    /// that message again, a late post (a participant was offline) as what it is. A deletion of an older
    /// message moves no cursor: `on_event`.
    pub messages: Vec<Message>,
    /// Where to go on from: the entry that arrived last of those read (`None`: nothing read, the
    /// same cursor).
    pub cursor: Option<Id>,
    pub more: bool,
    pub complete: bool,
}

/// An entry's place in this node's arrival order: a stamp says nothing of when a post got here.
fn arrival(e: &Entry) -> (u64, HistoryPos) {
    (e.received, e.id)
}

/// What arrived after `after` (`None`: from the start), `n` entries at most, read in arrival order.
/// A cursor is this node's: any entry's id does, and it means the arrival of that entry. Reads the
/// whole history (no arrival index): an app showing a timeline uses `on_event`.
/// Limits: an entry arriving in the cursor's millisecond with a lesser ID, or after this node's
/// clock jumped back past the cursor, is not returned.
pub fn since(db: &Osis, c: Tid, after: Option<&Id>, n: usize) -> Result<Since> {
    let from = match after {
        Some(a) => Some(entry_at(db, c, a)?.map_or((a.at().0, *a), |e| arrival(&e))),
        None => None,
    };
    let mut t = Timeline::new(db, c)?;
    let (mut new, mut shown) = (Vec::new(), Vec::new());
    while let Some(e) = t.next(db)? {
        if from.is_none_or(|f| arrival(&e) > f) {
            new.push(e.clone());
        }
        shown.extend(t.take(db, e)?);
    }
    new.sort_by_key(arrival);
    let more = new.len() > n;
    new.truncate(n);
    let mut touched = BTreeSet::new();
    for e in &new {
        touched.insert(replaces_of(db, c, e, t.mode)?.map_or(e.id, |r| r.original));
    }
    shown.retain(|m| touched.contains(&m.id));
    shown.sort_by_key(|m| m.id);
    Ok(Since { messages: shown, cursor: new.last().map(|e| e.id), more, complete: t.complete })
}

/// The entry that arrived last here: the cursor of everything read so far. Reads the whole history.
pub fn cursor(db: &Osis, c: Tid) -> Result<Option<Id>> {
    let mut t = Timeline::new(db, c)?;
    let mut last: Option<Entry> = None;
    while let Some(e) = t.next(db)? {
        if last.as_ref().is_none_or(|l| arrival(&e) > arrival(l)) {
            last = Some(e);
        }
    }
    Ok(last.map(|e| e.id))
}

/// The message `id` is a version of, reading back to its original.
pub fn find(db: &Osis, c: Tid, id: &Id) -> Result<Option<Message>> {
    let mode = settings(db, c)?.edit;
    let Some(e) = entry_at(db, c, id)? else { return Ok(None) };
    let target = replaces_of(db, c, &e, mode)?.map_or(*id, |r| r.original);
    let mut t = Timeline::new(db, c)?;
    loop {
        let page = t.older(db, FETCH)?;
        if let Some(m) = page.messages.iter().find(|m| m.id == target) {
            return Ok(Some(m.clone()));
        }
        if !page.more || page.messages.last().is_some_and(|m| m.id < target) {
            return Ok(None);
        }
    }
}

/// Edits one's own message: a new message naming the original; the newest wins everywhere, in any
/// arrival order. Under `Purge` the old text is then purged by its own commit (a commit with a
/// purge request carries no expiry, and a disappearing chat's message must).
pub fn edit(db: &Osis, c: Tid, m: &Message, text: &str) -> Result<Id> {
    let s = settings(db, c)?;
    if s.edit == EditMode::Off {
        return Err(Error::Invalid("editing is off in this chat".into()));
    }
    if m.sender != db.me() {
        return Err(Error::Invalid("only its sender edits a message".into()));
    }
    let held = versions_held(m);
    let mut prior = m.prior.clone();
    prior.extend(held.iter().copied());
    prior.sort();
    prior.dedup();
    let draft = Draft { text: text.into(), name: m.name.clone(), reply_to: m.reply_to };
    let new = write_body(db, c, &draft, Some(&Replaces { original: m.id, prior }))?;
    if s.edit == EditMode::Purge && may_delete(db, c, m.sender)? {
        purge(db, c, &held)?;
    }
    Ok(new)
}

/// The versions of `m` whose bodies are here.
fn versions_held(m: &Message) -> Vec<Id> {
    let mut v: Vec<Id> = m.earlier.iter().map(|e| e.id).collect();
    if matches!(m.body, Body::Text(_)) {
        v.push(m.latest());
    }
    v
}

fn purge(db: &Osis, c: Tid, ids: &[Id]) -> Result<()> {
    if ids.is_empty() {
        return Ok(());
    }
    let mut w = db.write();
    for i in ids {
        let id = i.commit().ok_or_else(|| Error::Invalid(format!("{i} names no message")))?;
        w.at(c, schema::MSGS).purge(osis::Purge::Commit(id))?;
    }
    w.commit().map(drop)
}

/// Whether this account's request would drop a body of `sender`'s, by the chat's purge set: a request
/// without the right drops nothing anywhere, so it is refused here.
pub fn may_delete(db: &Osis, c: Tid, sender: Tid) -> Result<bool> {
    let role = db.role_on(c)?;
    let admin = role == Some(Role::Admin);
    let writer = matches!(role, Some(Role::Admin | Role::Write));
    let own = sender == db.me() && writer;
    Ok(match settings(db, c)?.purge {
        PurgeBy::Nobody => false,
        PurgeBy::Admin => admin,
        PurgeBy::AuthorOrAdmin => admin || own,
        PurgeBy::Writer => writer,
        PurgeBy::Author => own,
    })
}

/// Deletes a message for everyone, every version known, by its author or a moderator as the chat's
/// purge set says. Its tombstone stays and reaches new nodes.
pub fn delete(db: &Osis, c: Tid, m: &Message) -> Result<()> {
    if !may_delete(db, c, m.sender)? {
        return Err(Error::Permission { tid: c, needs: Role::Admin });
    }
    purge(db, c, &versions_held(m))
}

/// Erases everything `actor` sent, within each write's purge rights; later writes stay, so kick too.
/// One header actor: an account's nodes share theirs, each of its thin clients has its own.
pub fn purge_participant(db: &Osis, c: Tid, actor: Tid) -> Result<()> {
    let mut w = db.write();
    w.at(c, schema::MSGS).purge(osis::Purge::Author(actor))?;
    w.commit().map(drop)
}

/// What a chat's watch hears.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// An entry reads otherwise now: a new message, an edit (`Entry::replaces`, checked), a
    /// deletion, a late older one, turned invalid. An edit under `EditMode::Purge` is also a
    /// deletion of the version it replaced: a timeline read tells the two apart.
    Entry(Box<Entry>),
    /// Events may have been missed: read again.
    Reread,
    /// Over: subscribe again.
    Ended(String),
}

/// Calls `f` per commit. Subscribe, then read: nothing after the subscription is missed.
pub fn on_event(db: &Osis, c: Tid, mut f: impl FnMut(&Osis, Event) + Send + 'static) -> Result<Subscription> {
    let mode = settings(db, c)?.edit;
    db.at(c, schema::MSGS).on_history(move |db, ev| {
        let ev = match ev {
            HistoryEvent::Commit { entry, .. } => match entry.and_then(entry_of) {
                Some(mut e) => {
                    e.replaces = replaces_of(db, c, &e, mode).unwrap_or(None);
                    Event::Entry(Box::new(e))
                }
                None => return,
            },
            HistoryEvent::Reread => Event::Reread,
            HistoryEvent::Ended(e) => Event::Ended(e.to_string()),
        };
        f(db, ev);
    })
}

/// Tells of this account's own writes on the chat turned invalid: a participant who had not seen a
/// retention change or its own kick. Its message is the commit named: `resend` it.
pub fn on_rejected(db: &Osis, c: Tid, mut f: impl FnMut(CommitId) + Send + 'static) -> Result<Subscription> {
    db.on_diagnostic(move |_, d| {
        if let osis::Diagnostic::OwnWriteInvalid { commit, things, .. } = d
            && things.contains(&c)
        {
            f(commit);
        }
    })
}
