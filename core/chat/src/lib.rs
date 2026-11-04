//! Group chat on osis primitives alone (notes/chat.md, design notes/chat-designs/e.md): a chat is one
//! ownerless actor C; members hold write on it; a message is one kept write on a per-year aspect of
//! C, its sender the commit's verified actor. No member actor, member list or per-message thing.

#![forbid(unsafe_code)]

use osis::schema::osis_base::cbor;
use osis::schema::{Bound, core_types as ct};
use osis::{Ak, ChangeId, CommitKind, Demotion, EdgeOpts, Error, HistoryBody, HistoryEntry, HistoryEvent, HistoryFrom, HistoryPos, Lower, Osis, Result, Retention, Role, Subscription, Tid, Ts, Value, WaitForSync};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::time::Duration;

pub use osis::schema::PurgeBy;

/// Message aspects, one per year: the name bounds only a re-merge (design E).
pub const MSGS: &str = "chat:msgs:";
/// The chat's settings, admins only.
pub const SETTINGS: &str = "chat:settings.0^";

fn year_ak(year: u32) -> Result<Ak> {
    Ak::new(format!("{MSGS}y{year}.0")).map_err(|e| Error::Invalid(e.to_string()))
}

fn settings_ak() -> Result<Ak> {
    Ak::new(SETTINGS).map_err(|e| Error::Invalid(e.to_string()))
}

/// The civil year of a time (Gregorian, UTC).
fn year_of(wall_ms: u64) -> u32 {
    // Hinnant's days-to-civil, for the year alone
    let z = (wall_ms / 86_400_000).saturating_add(719_468);
    let (era, doe) = (z / 146_097, z % 146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let march_based_month = (5 * doy + 2) / 153;
    let y = yoe + era * 400 + u64::from(march_based_month >= 10);
    u32::try_from(y).unwrap_or(u32::MAX)
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

impl std::str::FromStr for EditMode {
    type Err = Error;
    fn from_str(s: &str) -> Result<EditMode> {
        [EditMode::Purge, EditMode::Keep, EditMode::Off].into_iter().find(|m| m.name() == s).ok_or_else(|| Error::Invalid(format!("no edit mode {s:?}")))
    }
}

/// How a chat starts. Default: Signal-like: author or admin deletes, edits purge, nothing
/// disappears, a kicked member keeps a read-only copy.
#[derive(Clone, Debug)]
pub struct Options {
    pub name: String,
    /// Who may delete a message (`Nobody`: a permanent chat).
    pub purge: PurgeBy,
    pub edit: EditMode,
    /// Messages disappear this long after they are sent.
    pub disappear: Option<Duration>,
    /// A kicked member keeps a read-only copy, unless the kick says otherwise.
    pub keep: bool,
    /// Where the chat syncs; empty: the database's hosts. A host must admit an ownerless thing by
    /// its label or admit anyone: `admit own` does not take it.
    pub hosts: Vec<osis::HostAddr>,
}

impl Default for Options {
    fn default() -> Options {
        Options { name: String::new(), purge: PurgeBy::AuthorOrAdmin, edit: EditMode::Purge, disappear: None, keep: true, hosts: Vec::new() }
    }
}

/// The retention rules of a chat: the message rule, and the plain default for every other aspect, so
/// junk that nobody could erase is invalid (design E, Hostile member).
fn rules(purge: PurgeBy, disappear: Option<Duration>, keep: bool) -> Result<ct::RequiredRules> {
    let ms = disappear.map(|d| u64::try_from(d.as_millis()).map_err(|_| Error::Invalid("too long".into()))).transpose()?;
    let at_least = if ms.is_some() { Bound::default() } else { Bound { abs: Some(osis::FOREVER), rel: None } };
    let msgs = ct::Required::new(Retention { by: purge, at_least, at_most: Bound::default() }, ms);
    let rest = ct::Required::new(Retention::default(), None);
    Ok(ct::RequiredRules { rules: BTreeMap::from([(MSGS.to_string(), msgs), (String::new(), rest)]), keep })
}

/// A new chat, this person its first admin: required retention set before anyone is granted, so no
/// member can write under an earlier key. One flow, several commits: a crash leaves a chat of one.
pub fn create(db: &Osis, o: &Options) -> Result<Tid> {
    let c = db.create_ownerless(db.me())?;
    db.write_with(|w| {
        w.at(c, ct::REQUIRED).set(&rules(o.purge, o.disappear, o.keep)?)?;
        w.at(c, settings_ak()?).set(&settings_value(&o.name, o.edit))?;
        w.make_group(c)
    })?;
    db.sync(c, &o.hosts)?;
    Ok(c)
}

fn settings_value(name: &str, edit: EditMode) -> Value {
    Value::Map(BTreeMap::from([(Value::Int(0), Value::Str(name.into())), (Value::Int(1), Value::Str(edit.name().into()))]))
}

/// A chat's settings, as this node reads them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Settings {
    pub name: String,
    pub edit: EditMode,
    pub purge: PurgeBy,
    pub disappear: Option<Duration>,
    pub keep: bool,
}

/// What this node knows of a chat's settings.
pub fn settings(db: &Osis, c: Tid) -> Result<Settings> {
    let mut s = Settings::default();
    if let Some(Value::Map(m)) = db.get(c, settings_ak()?)? {
        if let Some(Value::Str(n)) = m.get(&Value::Int(0)) {
            s.name.clone_from(n);
        }
        if let Some(Value::Str(e)) = m.get(&Value::Int(1)) {
            s.edit = e.parse().unwrap_or_default();
        }
    }
    let r = db.get(c, ct::REQUIRED)?.unwrap_or_default();
    s.keep = r.keep;
    if let Some(m) = r.rules.get(MSGS) {
        s.purge = m.by;
        s.disappear = m.expires.map(Duration::from_millis);
    }
    Ok(s)
}

/// The chats this node syncs: its synced groups (`Osis::status`) with chat settings, in tid order;
/// not one this person is leaving, nor a joined one before its settings arrive. A copy kept after
/// a kick or leave is not synced: `Osis::kept_copies`. Re-list on `Osis::watch_status`.
pub fn chats(db: &Osis) -> Result<Vec<Tid>> {
    let ak = settings_ak()?;
    // a value of another shape is someone's junk: not a chat
    Ok(db.status()?.groups.into_iter().filter(|(t, g)| !g.leaving && matches!(db.get(*t, ak.clone()), Ok(Some(_)))).map(|(t, _)| t).collect())
}

/// Sets the disappearing timer: later messages take it, earlier ones keep what they have. A member
/// who has not seen the change writes under the old rule, and its node hears `on_rejected`.
pub fn set_disappearing(db: &Osis, c: Tid, d: Option<Duration>) -> Result<()> {
    let s = settings(db, c)?;
    db.write_with(|w| w.at(c, ct::REQUIRED).set(&rules(s.purge, d, s.keep)?))
}

/// Adds a member (an admin's call): `Write` to post, `Admin` to moderate, `Read` for a channel.
pub fn add(db: &Osis, c: Tid, person: Tid, role: Role) -> Result<()> {
    db.share(c, person, role, EdgeOpts::default())
}

/// Removes a member, a read-only copy left to them or not by `keep` (`None`: the chat's default).
pub async fn kick(db: &Osis, c: Tid, person: Tid, keep: Option<bool>, sync: WaitForSync) -> Result<()> {
    db.demote(c, person, Lower::Remove, Demotion { sync, backdate: None, repudiate: false, keep }).await
}

/// A link anyone holding it can join by, as `role`.
pub fn link(db: &Osis, c: Tid, role: Role, single_use: bool) -> Result<osis::ShareLink> {
    db.make_link(c, role, osis::LinkOpts { until: None, single_use, direct: false })
}

/// Joins by link: the chat, once it is here. Kicks reach a joiner like any member (`kick`). A chat
/// already held (`chats`) is returned as is, also when redeeming failed because it is: the link
/// may be used up, or its maker or a member pasted it. So a link never raises a member's role, and
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

/// Removes this person: every edge it holds the chat through (a link joiner's is on the link's key).
pub fn leave(db: &Osis, c: Tid) -> Result<()> {
    let mut last = Vec::new();
    loop {
        let path = db.holder_path(c, db.me());
        let Some((t, _)) = path.last() else { return if last.is_empty() { db.leave(c) } else { Ok(()) } };
        if path == last {
            return Ok(());
        }
        db.leave(*t)?;
        last = path;
    }
}

/// Whether `h` is an actor people hold the chat through, as a link's actor K (spec/permissions.md
/// §9) or a team: owned by an actor that has an owner itself. A person's owner is a key, and the
/// holders of a person are its devices.
fn held_through(db: &Osis, h: Tid) -> bool {
    db.owner_of(h).and_then(|o| db.owner_of(o)).is_some()
}

/// A link's key on K: a key actor with invite. Never a person.
fn link_key(db: &Osis, m: Tid, e: &osis::Edge) -> bool {
    e.invite.is_some() && db.owner_of(m).is_none()
}

/// Who holds the chat, with the role they have: its direct holders and those holding it through an
/// actor (`held_through`), link joiners so, at the lesser of the two roles. As this node knows them:
/// a direct member learns a link joiner from its first post, and lists K until then if nobody else
/// of K is known (`kick` of K ends everyone behind it).
pub fn members(db: &Osis, c: Tid) -> BTreeMap<Tid, Role> {
    let mut out = BTreeMap::new();
    let mut put = |m: Tid, r: Role| {
        let e = out.entry(m).or_insert(r);
        *e = r.max(*e);
    };
    for (h, e) in db.roster(c) {
        if !held_through(db, h) {
            put(h, e.role);
            continue;
        }
        let behind = db.roster(h);
        if behind.is_empty() {
            put(h, e.role);
        }
        for (m, x) in behind.iter().filter(|(m, x)| !link_key(db, **m, x)) {
            put(*m, x.role.min(e.role));
        }
    }
    out
}

/// The links that work on the chat, as this node knows them: each link's actor K and its role. Not
/// members; `osis::Osis::links` has what its maker alone knows.
pub fn member_links(db: &Osis, c: Tid) -> BTreeMap<Tid, Role> {
    db.roster(c).into_iter().filter(|(h, _)| held_through(db, *h) && db.roster(*h).iter().any(|(m, x)| link_key(db, *m, x))).map(|(h, e)| (h, e.role)).collect()
}

/// Where a message is: its year's aspect and its place there.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Id {
    pub pos: HistoryPos,
    pub year: u32,
}

impl std::fmt::Display for Id {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}/{}", self.year, self.pos.ts.to_u64(), commit_of(&self.pos.id).map_or_else(String::new, |c| osis::schema::osis_base::hex::encode(&c.0)))
    }
}

impl std::str::FromStr for Id {
    type Err = Error;
    fn from_str(s: &str) -> Result<Id> {
        let bad = || Error::Invalid(format!("a message id is YEAR/TS/COMMIT, not {s:?}"));
        let mut p = s.split('/');
        let (Some(y), Some(t), Some(c), None) = (p.next(), p.next(), p.next(), p.next()) else { return Err(bad()) };
        let ts = t.parse().ok().and_then(Ts::from_u64).ok_or_else(bad)?;
        let c = osis::schema::osis_base::hex::decode(c).and_then(|b| <[u8; 32]>::try_from(b).ok()).ok_or_else(bad)?;
        Ok(Id { year: y.parse().map_err(|_| bad())?, pos: HistoryPos { ts, id: ChangeId::Commit(osis::CommitId(c)) } })
    }
}

fn commit_of(c: &ChangeId) -> Option<osis::CommitId> {
    match c {
        ChangeId::Commit(c) => Some(*c),
        ChangeId::Ephemeral(_) => None,
    }
}

fn id_value(i: &Id) -> Option<Value> {
    Some(Value::List(vec![Value::Int(i64::from(i.year)), Value::Int(i64::try_from(i.pos.ts.to_u64()).ok()?), Value::Bytes(commit_of(&i.pos.id)?.0.to_vec())]))
}

fn id_read(v: &Value) -> Option<Id> {
    let Value::List(l) = v else { return None };
    let [Value::Int(y), Value::Int(t), Value::Bytes(c)] = l.as_slice() else { return None };
    let ts = Ts::from_u64(u64::try_from(*t).ok()?)?;
    Some(Id { year: u32::try_from(*y).ok()?, pos: HistoryPos { ts, id: ChangeId::Commit(osis::CommitId(<[u8; 32]>::try_from(c.as_slice()).ok()?)) } })
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

fn body_value(d: &Draft, r: Option<&Replaces>) -> Result<Value> {
    let bad = || Error::Invalid("a message id without a commit".into());
    let mut m = BTreeMap::from([(Value::Int(0), Value::Str(d.text.clone()))]);
    if let Some(n) = &d.name {
        m.insert(Value::Int(3), Value::Str(n.clone()));
    }
    if let Some(t) = &d.reply_to {
        m.insert(Value::Int(4), id_value(t).ok_or_else(bad)?);
    }
    if let Some(r) = r {
        m.insert(Value::Int(1), id_value(&r.original).ok_or_else(bad)?);
        m.insert(Value::Int(2), Value::List(r.prior.iter().map(|p| id_value(p).ok_or_else(bad)).collect::<Result<_>>()?));
    }
    // one scalar: a `replace` of a map leaves state per entry, and a long aspect's write grows with it
    Ok(Value::Bytes(cbor::encode(&Value::Map(m))))
}

/// Another writer's input: anything not reading as a message reads as `None`.
fn body_read(v: &Value) -> Option<(Draft, Option<Replaces>)> {
    let Value::Bytes(b) = v else { return None };
    let Value::Map(m) = cbor::decode(b, &cbor::Limits::default()).ok()? else { return None };
    let Some(Value::Str(text)) = m.get(&Value::Int(0)) else { return None };
    let name = match m.get(&Value::Int(3)) {
        Some(Value::Str(n)) => Some(n.clone()),
        _ => None,
    };
    let reply_to = m.get(&Value::Int(4)).and_then(id_read);
    let r = match m.get(&Value::Int(1)) {
        None => None,
        Some(o) => {
            let prior = match m.get(&Value::Int(2)) {
                Some(Value::List(l)) => l.iter().map(id_read).collect::<Option<Vec<_>>>()?,
                _ => Vec::new(),
            };
            Some(Replaces { original: id_read(o)?, prior })
        }
    };
    Some((Draft { text: text.clone(), name, reply_to }, r))
}

/// Sends a message: one commit, one delta. Retention and expiry come from the chat's rule, filled
/// by the node. `replace`, not `set`: a set equal to the last message would write nothing.
pub fn send(db: &Osis, c: Tid, d: &Draft) -> Result<Id> {
    write_body(db, c, d, None)
}

/// `send` of plain text.
pub fn post(db: &Osis, c: Tid, text: &str) -> Result<Id> {
    send(db, c, &Draft::text(text))
}

/// Sends again one's own message that turned invalid (`Message::valid`, `on_rejected`): the same
/// text, name and reply, as a new message. The old one stays, to this person alone.
pub fn resend(db: &Osis, c: Tid, m: &Message) -> Result<Id> {
    let Body::Text(text) = &m.body else { return Err(Error::Invalid("its text is not here".into())) };
    if m.valid || m.sender != db.me() {
        return Err(Error::Invalid("only one's own undelivered message is sent again".into()));
    }
    send(db, c, &Draft { text: text.clone(), name: m.name.clone(), reply_to: m.reply_to })
}

fn write_body(db: &Osis, c: Tid, d: &Draft, r: Option<&Replaces>) -> Result<Id> {
    let year = year_of(db.now().0);
    let mut w = db.write();
    w.at(c, year_ak(year)?).replace(&body_value(d, r)?)?;
    let done = w.commit()?.ok_or_else(|| Error::Invalid("nothing written".into()))?;
    Ok(Id { year, pos: HistoryPos { ts: done.ts, id: done.id } })
}

/// A write claiming to replace `original`, past `edit`'s checks: what a hostile member can do. Tests.
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
    /// Deleted for everyone: a tombstone that new devices get too. `who`: verified, as a sender is
    /// (`None`: the request's header is not here).
    Deleted { by: ChangeId, who: Option<Tid> },
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

fn entry_of(year: u32, e: HistoryEntry<Value>) -> Option<Entry> {
    if e.kind != CommitKind::Change {
        return None;
    }
    let pos = e.pos();
    let (mut name, mut reply_to) = (None, None);
    let (body, replaces) = match e.body {
        HistoryBody::Held(v) => match v.as_ref().and_then(body_read) {
            Some((d, r)) => {
                (name, reply_to) = (d.name, d.reply_to);
                (Body::Text(d.text), r)
            }
            None => (Body::Odd, None),
        },
        HistoryBody::TooLarge { .. } => (Body::Odd, None),
        HistoryBody::Purged { by, actor } => (Body::Deleted { by, who: actor }, None),
        HistoryBody::Dropped => (Body::Gone, None),
        HistoryBody::NotFetched => (Body::NotFetched, None),
    };
    Some(Entry { id: Id { year, pos }, sender: e.commit.actor, node: e.commit.node, time: e.commit.ts.wall_ms().0.min(e.commit.received.0), received: e.commit.received.0, valid: e.valid, body, name, reply_to, replaces })
}

/// The years a chat's messages may be under: its creation's to next year's (a clock ahead).
fn years(db: &Osis, c: Tid) -> Result<Vec<u32>> {
    let now = year_of(db.now().0);
    let first = db.created(c).map_or(now, |s| year_of(s.ts.wall_ms().0));
    Ok((first.min(now)..=now.saturating_add(1)).collect())
}

/// One page of raw entries.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Entries {
    pub entries: Vec<Entry>,
    pub more: bool,
    /// `false`: entries may yet arrive anywhere, older ones too: not fetched, not absent.
    pub complete: bool,
}

/// Raw entries across the years, by `(ts, ID)`, in `from`'s direction (`Newest`, `Before`: towards
/// older). No assumption ties a year's aspect to its stamps: a backdated write sorts by its stamp.
pub fn entries(db: &Osis, c: Tid, from: HistoryFrom, limit: usize) -> Result<Entries> {
    let limit = limit.min(osis::HISTORY_PAGE);
    let mut out = Entries { entries: Vec::new(), more: false, complete: true };
    for y in years(db, c)? {
        let page = db.at(c, year_ak(y)?).history(from, limit)?;
        out.more |= page.more;
        out.complete &= page.complete;
        out.entries.extend(page.entries.into_iter().filter_map(|e| entry_of(y, e)));
    }
    out.entries.sort_by_key(|e| e.id.pos);
    if matches!(from, HistoryFrom::Newest | HistoryFrom::Before(_)) {
        out.entries.reverse();
    }
    if out.entries.len() > limit {
        out.entries.truncate(limit);
        out.more = true;
    }
    Ok(out)
}

/// The entry at `id`, if it is here.
pub fn entry_at(db: &Osis, c: Tid, id: &Id) -> Result<Option<Entry>> {
    let k = year_ak(id.year)?;
    let mut from = HistoryFrom::After(HistoryPos::time(id.pos.ts));
    loop {
        let page = db.at(c, k.clone()).history(from, 16)?;
        let Some(last) = page.entries.last().map(|e| e.pos()) else { return Ok(None) };
        if let Some(e) = page.entries.into_iter().find(|e| e.pos() == id.pos) {
            return Ok(entry_of(id.year, e));
        }
        if !page.more || last.ts > id.pos.ts {
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
    Ok((o.valid && o.sender == e.sender && o.replaces.is_none() && o.id.pos < e.id.pos).then(|| r.clone()))
}

/// A message as a reader sees it: the original's place, the newest version's text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    /// The original's id: what replies, reactions and edits name.
    pub id: Id,
    pub sender: Tid,
    pub time: u64,
    /// Valid. `false` only for this person's own write, turned invalid (a stale writer's, a kicked
    /// member's): others' invalid writes are not shown.
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

/// Entries a timeline fetches at a time. 1: a read per entry; past `HISTORY_PAGE`: that.
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
                self.cursor = HistoryFrom::Before(last.id.pos);
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
        versions.sort_by_key(|v| std::cmp::Reverse(v.0.id.pos));
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
    /// that message again, a late post (a member was offline) as what it is. A deletion of an older
    /// message moves no cursor: `watch`.
    pub messages: Vec<Message>,
    /// Where to go on from: the entry that arrived last of those read (`None`: nothing read, the
    /// same cursor).
    pub cursor: Option<Id>,
    pub more: bool,
    pub complete: bool,
}

/// An entry's place in this node's arrival order: a stamp says nothing of when a post got here.
fn arrival(e: &Entry) -> (u64, HistoryPos) {
    (e.received, e.id.pos)
}

/// What arrived after `after` (`None`: from the start), `n` entries at most, read in arrival order.
/// A cursor is this node's: any entry's id does, and it means the arrival of that entry. Reads the
/// whole history (no arrival index): an app showing a timeline uses `watch`.
/// Limits: an entry arriving in the cursor's millisecond with a lesser ID, or after this node's
/// clock jumped back past the cursor, is not returned.
pub fn since(db: &Osis, c: Tid, after: Option<&Id>, n: usize) -> Result<Since> {
    let from = match after {
        Some(a) => Some(entry_at(db, c, a)?.map_or((a.pos.ts.wall_ms().0, a.pos), |e| arrival(&e))),
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
    shown.sort_by_key(|m| m.id.pos);
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
        if !page.more || page.messages.last().is_some_and(|m| m.id.pos < target.pos) {
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
        w.at(c, year_ak(i.year)?).purge_commit(i.pos.id)?;
    }
    w.commit().map(drop)
}

/// Whether this person's request would drop a body of `sender`'s, by the chat's purge set: a request
/// without the right drops nothing anywhere, so it is refused here.
pub fn may_delete(db: &Osis, c: Tid, sender: Tid) -> Result<bool> {
    let role = db.role_on(c);
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
/// purge set says. Its tombstone stays and reaches new devices.
pub fn delete(db: &Osis, c: Tid, m: &Message) -> Result<()> {
    if !may_delete(db, c, m.sender)? {
        return Err(Error::Permission { tid: c, needs: Role::Admin });
    }
    purge(db, c, &versions_held(m))
}

/// Erases everything `actor` sent, within each write's purge rights; later writes stay, so kick too.
/// One header actor: a person's devices share theirs, each of its thin clients has its own.
pub fn purge_member(db: &Osis, c: Tid, actor: Tid) -> Result<()> {
    let mut w = db.write();
    for y in years(db, c)? {
        w.at(c, year_ak(y)?).purge_author(actor)?;
    }
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

/// Calls `f` per change, through the years from the chat's creation to the next. Subscribe, then
/// read: nothing after the subscription is missed. A watch living past next year needs renewing.
pub fn watch(db: &Osis, c: Tid, f: impl FnMut(&Osis, Event) + Send + 'static) -> Result<Vec<Subscription>> {
    let mode = settings(db, c)?.edit;
    let f = std::sync::Arc::new(std::sync::Mutex::new(f));
    let mut subs = Vec::new();
    for y in years(db, c)? {
        let f = f.clone();
        subs.push(db.at(c, year_ak(y)?).on_history(move |db, ev| {
            let ev = match ev {
                HistoryEvent::Commit { entry, .. } => match entry.and_then(|e| entry_of(y, e)) {
                    Some(mut e) => {
                        e.replaces = replaces_of(db, c, &e, mode).unwrap_or(None);
                        Event::Entry(Box::new(e))
                    }
                    None => return,
                },
                HistoryEvent::Reread => Event::Reread,
                HistoryEvent::Ended(e) => Event::Ended(e.to_string()),
            };
            let mut f = f.lock().unwrap_or_else(|e| e.into_inner());
            (*f)(db, ev);
        })?);
    }
    Ok(subs)
}

/// Tells of this person's own writes on the chat turned invalid: a member who had not seen a
/// retention change or its own kick. Its message is the commit named: `resend` it.
pub fn on_rejected(db: &Osis, c: Tid, mut f: impl FnMut(osis::CommitId) + Send + 'static) -> Subscription {
    db.on_diagnostic(move |_, d| {
        if d.kind == osis::DiagnosticKind::OwnWriteInvalid
            && d.tids.contains(&c)
            && let Some(id) = d.commit
        {
            f(id);
        }
    })
}
