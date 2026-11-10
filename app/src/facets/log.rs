//! `chat:msg~0`: a signal of messages kept forever; entries, a composer, replies. The only file that names
//! osis_chat (its keys and rules). The sender's name is the profile's `name.0`, else `OSIS_CHAT_NAME`.

use osis_kit::view::arrange::{split_sort_key, stream};
use osis_kit::view::{Act, Action, Block, Chip, Composer, ComposerField, Cx, Do, Entry, Facet, Icon, Input, Mark, Section, Summary};
use osis_kit::store::Reader;
use crate::schema::{DRAFT, REPLY_TO};
use osis::core::NAME;
use osis::{Body, Commit, CommitFrom, CommitId, CommitKind, CommitPos, CommitQuery, Osis, ReadOnly, Result, Tid, Time};
use osis_chat::schema::{MSG, SETTINGS};

pub struct LogFacet;
pub static FACET: LogFacet = LogFacet;

const ID: &str = "log";

/// One message as a stream shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Line {
    /// The message's (an edited one's original's).
    pub id: CommitId,
    /// Its place: where it sorts.
    pub pos: CommitPos,
    /// The name it was sent under, else the start of the sender's tid.
    pub who: String,
    /// UTC ms, as shown.
    pub time: u64,
    /// The newest text (`<deleted>` and the like for what has none here).
    pub text: String,
    /// The answered message: its sender and first line, or its id when not here.
    pub reply_to: Option<(CommitId, String)>,
    pub mine: bool,
    pub edited: bool,
}

/// Adds `n` messages to the chat `c`, for the harness (`ViewType::grow`), each answering the
/// oldest message: a quote reaches back the whole history and costs one read of it.
#[allow(clippy::expect_used)]
pub fn grow(d: &osis_kit::store::Data, c: Tid, n: usize) {
    let page = d.db.at(c, MSG).fired(&CommitQuery { from: CommitFrom::Oldest, limit: Some(1), ..Default::default() }).expect("grow: the oldest");
    let first = page.commits.first().map(|k| k.stamp.id);
    for i in 0..n {
        send(&d.db, c, "", &format!("grown {i}"), first).expect("grow: a message");
    }
}

/// A chat with one message, for a view's `sample`.
#[allow(clippy::expect_used)]
pub fn sample(d: &osis_kit::store::Data) -> Tid {
    let c = osis_chat::create(&d.db, &osis_chat::Options::default()).expect("sample: a chat");
    send(&d.db, c, "", "hello", None).expect("sample: a message");
    c
}

/// The log's name: its settings' name, `"Chat"` when unnamed.
pub fn name(db: &osis::ReadOnly, c: Tid) -> Result<String> {
    let n = db.at(c, SETTINGS).get()?.map(|s| s.name).unwrap_or_default();
    Ok(if n.trim().is_empty() { "Chat".into() } else { n })
}

/// The name messages go out under: the profile's `name.0`, else `OSIS_CHAT_NAME`.
pub fn my_name(db: &Osis) -> Result<Option<String>> {
    let own = if db.saved_peers()?.is_empty() { None } else { db.at(db.profile()?, NAME).get()?.filter(|n| !n.trim().is_empty()) };
    Ok(own.or_else(|| std::env::var("OSIS_CHAT_NAME").ok().filter(|n| !n.trim().is_empty())))
}

/// Sends `text` (a `subject` first, as the CLI's `--subject`), answering `reply_to`: its id.
pub fn send(db: &Osis, c: Tid, subject: &str, text: &str, reply_to: Option<CommitId>) -> Result<CommitId> {
    let (s, t) = (subject.trim(), text.trim());
    let text = match (s.is_empty(), t.is_empty()) {
        (_, true) if s.is_empty() => return Err(osis::Error::Invalid("nothing to send".into())),
        (true, _) => t.to_string(),
        (false, true) => s.to_string(),
        (false, false) => format!("{s}\n\n{t}"),
    };
    let mut w = db.write();
    w.at(c, MSG).fire(&osis_chat::schema::Message { text, name: my_name(db)?, reply_to: reply_to.map(|r| r.to_string()) })?;
    Ok(w.commit()?.ok_or_else(|| osis::Error::Invalid("nothing written".into()))?.stamp.id)
}

fn text_of(b: &Body<osis_chat::schema::Message>) -> String {
    match b {
        Body::Held(Some(m)) => m.text.clone(),
        Body::Purged { .. } => "<deleted>".into(),
        Body::NotFetched => "<not here yet>".into(),
        Body::Held(None) | Body::TooLarge { .. } => "<unreadable>".into(),
    }
}

fn who(k: &Commit, b: &Body<osis_chat::schema::Message>) -> String {
    let name = match b {
        Body::Held(Some(x)) => x.name.clone(),
        _ => None,
    };
    name.filter(|n| !n.trim().is_empty()).unwrap_or_else(|| k.stamp.actor.to_string().chars().take(8).collect())
}

/// Message `id` as a reply names it, its sender and first line: `None` when it is not listed here.
/// One commit read, however far back it is.
fn quote(db: &ReadOnly, c: Tid, id: CommitId) -> Result<Option<String>> {
    let Some(k) = db.at(c, MSG).commit(id)? else { return Ok(None) };
    Ok(k.at(c, MSG).map(|p| format!("{}: {}", who(&k, &p.body), text_of(&p.body).lines().next().unwrap_or(""))))
}

/// A quote in a view: its own node, so it moves with the quoted message alone.
fn quote_memo(r: &Reader, c: Tid, id: CommitId) -> Result<std::rc::Rc<Option<String>>> {
    r.memo(("quote", c, id), |r, &(_, c, id)| quote(&r.db, c, id))
}

/// Up to `n` messages from `from`, newest first; `quote` names an answered message. One page
/// read: its cost is the page's, however long the chat.
fn lines(db: &ReadOnly, c: Tid, from: CommitFrom, n: usize, mut quote: impl FnMut(CommitId) -> Result<Option<String>>) -> Result<Vec<Line>> {
    let page = db.at(c, MSG).fired(&CommitQuery { from, limit: Some(n), kinds: vec![CommitKind::Content], ..Default::default() })?;
    let me = db.me();
    let mut out = Vec::with_capacity(page.commits.len());
    for k in &page.commits {
        let Some(p) = k.at(c, MSG) else { continue };
        let reply_to = match &p.body {
            Body::Held(Some(m)) => m.reply(),
            _ => None,
        };
        let reply_to = match reply_to {
            Some(r) => Some((r, quote(r)?.unwrap_or_else(|| r.to_string()))),
            None => None,
        };
        out.push(Line { id: k.stamp.id, pos: k.pos(), who: who(k, &p.body), time: k.stamp.shown().0, text: text_of(&p.body), reply_to, mine: k.stamp.actor == me, edited: p.edited.is_some() });
    }
    Ok(out)
}

/// The newest `n` messages, oldest first, read outside a view.
pub fn recent(db: &osis::ReadOnly, c: Tid, n: usize) -> Result<Vec<Line>> {
    let mut out = lines(db, c, CommitFrom::Newest, n, |r| quote(db, c, r))?;
    out.reverse();
    Ok(out)
}

#[derive(Clone, Debug, PartialEq)]
struct Reply(String, Option<CommitId>);
impl Action for Reply {
    fn run(&self, act: &Act, _: &Input) -> Result<()> {
        match self.1 {
            Some(r) => act.set_state(REPLY_TO, &self.0, &r.to_string()),
            None => act.clear_state(REPLY_TO, &self.0),
        }
    }
}

/// A composer field's entry in `draft.0`.
fn field(node: &str, name: &str) -> String {
    format!("{node}#{name}")
}

/// The answered message of the node, if a valid one.
fn reply_of(cx: &Reader, node: &str) -> Result<Option<CommitId>> {
    Ok(cx.state(REPLY_TO, node)?.and_then(|s| s.parse().ok()))
}

#[derive(Clone, Debug, PartialEq)]
struct Send(Tid, String);
impl Action for Send {
    fn run(&self, act: &Act, input: &Input) -> Result<()> {
        let c = self.0;
        let node = &self.1;
        // the drafts' sessions commit what is pending, so the drafts hold all of it
        act.window.sessions.commit(act.data.window()?)?;
        let read = |name| -> Result<String> { Ok(act.state(DRAFT, &field(node, name))?.unwrap_or_default()) };
        let text = match input {
            Input::Text(t) => t.clone(),
            _ => read("text")?,
        };
        send(&act.data.db, c, &read("subject")?, &text, reply_of(act, node)?)?;
        act.clear_state(DRAFT, &field(node, "subject"))?;
        act.clear_state(DRAFT, &field(node, "text"))?;
        act.clear_state(REPLY_TO, node)
    }
}

/// "Mon 3 Nov 14:05", local.
fn when(utc_ms: u64) -> String {
    use crate::time::{DAY, fmt_day, fmt_time, local_of};
    let l = local_of(i64::try_from(utc_ms).unwrap_or(i64::MAX));
    format!("{} {}", fmt_day(l.div_euclid(DAY)), fmt_time(l))
}

fn entry_of(c: Tid, s: &Summary, l: &Line) -> Entry {
    let mut e = Entry::of(c, s);
    let mut head = format!("{} · {}", l.who, when(l.time));
    if l.edited {
        head.push_str(" · edited");
    }
    // its place's text sorts as places do: rows of one time sort as `fired` pages them
    e.key = format!("{c}/{}", l.pos);
    e.author = Some(head);
    e.text = l.text.clone();
    e.time = Some(l.pos.at().0);
    e.quote = l.reply_to.as_ref().map(|(_, q)| q.clone());
    e.raised = l.mine;
    e
}

impl Facet for LogFacet {
    fn id(&self) -> &'static str {
        ID
    }
    fn claims(&self, ak: &str) -> bool {
        ak.starts_with("chat:")
    }
    fn summarize(&self, cx: &Reader, t: Tid, s: &mut Summary) -> Result<()> {
        s.words.insert(0, "Chat".into());
        s.mark = Mark::Icon(Icon::People);
        if s.name.is_empty() {
            s.name = name(&cx.db, t)?;
        }
        if s.sub.is_empty() {
            s.sub = "Conversation".into();
        }
        Ok(())
    }
    fn show(&self, cx: &Cx, t: Tid) -> Result<Section> {
        let node = cx.path();
        let reply = reply_of(cx, &node)?;
        let mut blocks = Vec::new();
        let list = stream(cx, vec![t], "log")?;
        if matches!(&list, Block::List(l) if l.is_empty()) {
            blocks.push(Block::Line("No messages yet.".into()));
        }
        blocks.push(list);
        let mut foot = Vec::new();
        if let Some(r) = reply.filter(|_| cx.config().get("composer") != Some("none")) {
            let quoted = (*quote_memo(cx, t, r)?).clone();
            let what = format!("Replying to {}", quoted.unwrap_or_else(|| r.to_string()));
            foot.push(Block::Line(what));
            foot.push(Block::Chips(vec![Chip::action(Icon::Back, "Don't reply", Do::new(Reply(node.clone(), None)))]));
        }
        if cx.config().get("composer") != Some("none") && let Some(win) = cx.window_opt()? {
            foot.push(Block::Composer(Composer {
                fields: vec![
                    ComposerField { thing: win, ak: "osis_app:draft.0".into(), key: field(&node, "subject"), placeholder: "Subject (optional)".into() },
                    ComposerField { thing: win, ak: "osis_app:draft.0".into(), key: field(&node, "text"), placeholder: "Message, Enter sends".into() },
                ],
                send: Do::new(Send(t, node.clone())),
            }));
        }
        Ok(Section { blocks, foot })
    }
    fn stream(&self, cx: &Reader, t: Tid, before: Option<&str>, n: usize, out: &mut Vec<Entry>) -> Result<()> {
        let mine = format!("{t}/");
        let from = match before.map(split_sort_key) {
            None => CommitFrom::Newest,
            Some(None) => return Ok(()),
            Some(Some((ms, key))) => match key.strip_prefix(&mine).and_then(|p| p.parse::<CommitPos>().ok()) {
                Some(p) => CommitFrom::Before(p),
                // another thing's row: this chat's rows of its time sort all before it or all after
                None => CommitFrom::Before(CommitPos::time(Time(if mine.as_str() < key { ms.saturating_add(1) } else { ms }))),
            },
        };
        let s = cx.summary(t)?;
        out.extend(lines(&cx.db, t, from, n, |r| Ok((*quote_memo(cx, t, r)?).clone()))?.iter().map(|l| entry_of(t, &s, l)));
        Ok(())
    }
    fn stream_row(&self, cx: &Cx, e: &mut Entry) -> Result<()> {
        if let Some(id) = e.key.rsplit('/').next().and_then(|p| p.parse::<CommitId>().ok()) {
            e.actions = vec![Chip::action(Icon::Back, "Reply", Do::new(Reply(cx.path(), Some(id))))];
        }
        Ok(())
    }
}
