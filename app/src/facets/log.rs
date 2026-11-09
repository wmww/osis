//! `chat:msg~0`: a signal of messages kept forever; entries, a composer, replies. The only file that names
//! osis_chat (its keys and edit rules). The sender's name is the profile's `name.0`, else `OSIS_CHAT_NAME`.

use osis_kit::view::arrange::stream;
use osis_kit::view::{Act, Action, Block, Chip, Composer, ComposerField, Cx, Do, Entry, Facet, Icon, Input, Mark, Section, Summary};
use osis_kit::store::Reader;
use crate::schema::{DRAFT, REPLY_TO};
use osis::core::NAME;
use osis::{Body, CommitPos, Osis, Result, Tid};
use osis_chat::schema::{MSG, SETTINGS};
use osis_chat::{Message, Timeline};
use std::collections::BTreeMap;
use std::rc::Rc;

pub struct LogFacet;
pub static FACET: LogFacet = LogFacet;

const ID: &str = "log";

/// One message as a stream shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Line {
    pub id: CommitPos,
    /// The name it was sent under, else the start of the sender's tid.
    pub who: String,
    /// UTC ms.
    pub time: u64,
    /// The text (`<deleted>` and the like for what has none here).
    pub text: String,
    /// The answered message: its sender and first line, or its id when not here.
    pub reply_to: Option<(CommitPos, String)>,
    pub mine: bool,
    pub edited: bool,
}

/// Adds `n` messages to the chat `c`, for the harness (`ViewType::grow`). No quotes: a quote walks
/// history to its original until signal edits land, the one cost that grows (fast-design step 9).
#[allow(clippy::expect_used)]
pub fn grow(d: &osis_kit::store::Data, c: Tid, n: usize) {
    for i in 0..n {
        send(&d.db, c, "", &format!("grown {i}"), None).expect("grow: a message");
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

/// Sends `text` (a `subject` first, as the CLI's `--subject`), answering `reply_to`.
pub fn send(db: &Osis, c: Tid, subject: &str, text: &str, reply_to: Option<CommitPos>) -> Result<CommitPos> {
    let (s, t) = (subject.trim(), text.trim());
    let text = match (s.is_empty(), t.is_empty()) {
        (_, true) if s.is_empty() => return Err(osis::Error::Invalid("nothing to send".into())),
        (true, _) => t.to_string(),
        (false, true) => s.to_string(),
        (false, false) => format!("{s}\n\n{t}"),
    };
    let mut w = db.write();
    w.at(c, MSG).fire(&osis_chat::schema::Message { text, name: my_name(db)?, reply_to: reply_to.map(|r| r.to_string()), edit: None })?;
    Ok(w.commit()?.ok_or_else(|| osis::Error::Invalid("nothing written".into()))?.pos())
}

fn text_of(b: &Body<osis_chat::schema::Message>) -> String {
    match b {
        Body::Held(Some(m)) => m.text.clone(),
        Body::Purged { .. } => "<deleted>".into(),
        Body::NotFetched => "<not here yet>".into(),
        Body::Held(None) | Body::TooLarge { .. } => "<unreadable>".into(),
    }
}

fn who(m: &Message) -> String {
    let name = match &m.body {
        Body::Held(Some(x)) => x.name.clone(),
        _ => None,
    };
    name.filter(|n| !n.trim().is_empty()).unwrap_or_else(|| m.sender.to_string().chars().take(8).collect())
}

/// A message as a reply names it: its sender and first line.
pub fn quote(m: &Message) -> String {
    quote_of(&who(m), &text_of(&m.body))
}

fn quote_of(who: &str, text: &str) -> String {
    format!("{who}: {}", text.lines().next().unwrap_or(""))
}

/// Messages read per step of the walk through a chat's history (a performance switch: the walk
/// is cached per step; 1 caches each message, infinity re-reads the history per message).
const WALK_STEP: usize = 64;

/// One step of the walk from the newest message back: the messages it reached, and the walker to go on
/// from. The walker carries the edits seen so far, which older steps need; a step reruns only when
/// what it read differs, and is asked for only as deep as a window looks.
#[derive(Clone, PartialEq)]
struct Walk {
    timeline: Timeline,
    lines: Vec<Line>,
    /// The ids answered here that this step does not hold, for the quote memo.
    further: Vec<CommitPos>,
    more: bool,
}

impl std::fmt::Debug for Walk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Walk").field("lines", &self.lines.len()).finish()
    }
}

fn walk(r: &Reader, c: Tid, step: usize) -> Result<Rc<Walk>> {
    r.memo(("walk", c, step), walk_step)
}

fn walk_step(r: &Reader, &(_, c, step): &(&'static str, Tid, usize)) -> Result<Walk> {
    let mut timeline = match step.checked_sub(1) {
        None => Timeline::new(&r.db, c)?,
        Some(p) => walk(r, c, p)?.timeline.clone(),
    };
    let page = timeline.older(&r.db, WALK_STEP)?;
    let me = r.db.me();
    let shown: BTreeMap<CommitPos, &Message> = page.messages.iter().map(|m| (m.id, m)).collect();
    let further: Vec<CommitPos> = page.messages.iter().filter_map(Message::reply_to).filter(|p| !shown.contains_key(p)).collect();
    let lines = page
        .messages
        .iter()
        .map(|m| line_of(m, me, |p| shown.get(&p).map_or_else(String::new, |q| quote(q))))
        .collect();
    Ok(Walk { timeline, lines, further, more: page.more })
}

/// The answered messages of step `step` further back than the step holds. This walks history to the
/// oldest of them: the cost that grows until signal edits land (fast-design step 9); the
/// harness grows chats without quotes.
fn quotes_of(r: &Reader, c: Tid, step: usize) -> Result<Rc<BTreeMap<CommitPos, String>>> {
    r.memo(("quotes", c, step), |r, &(_, c, step)| {
        let w = walk(r, c, step)?;
        if w.further.is_empty() {
            return Ok(BTreeMap::new());
        }
        Ok(w.timeline.find_all(&r.db, &w.further)?.iter().map(|(k, m)| (*k, quote(m))).collect())
    })
}

/// Up to `n` messages, newest first, older than wall ms `before` when given.
fn lines(r: &Reader, c: Tid, before: Option<u64>, n: usize) -> Result<Vec<Line>> {
    let mut out = Vec::new();
    let mut step = 0;
    loop {
        let w = walk(r, c, step)?;
        let quotes = if w.further.is_empty() { None } else { Some(quotes_of(r, c, step)?) };
        for l in &w.lines {
            if before.is_some_and(|b| l.time >= b) {
                continue;
            }
            let mut l = l.clone();
            if let Some((p, q)) = &mut l.reply_to && q.is_empty() {
                *q = quotes.as_ref().and_then(|m| m.get(p)).cloned().unwrap_or_else(|| p.to_string());
            }
            out.push(l);
            if out.len() >= n {
                return Ok(out);
            }
        }
        if !w.more {
            return Ok(out);
        }
        step += 1;
    }
}

/// A message as a stream shows it, `quote` the answered message's text.
fn line_of(m: &Message, me: Tid, quote: impl FnOnce(CommitPos) -> String) -> Line {
    let reply_to = m.reply_to().map(|p| (p, quote(p)));
    Line { id: m.id, who: who(m), time: m.time.0, text: text_of(&m.body), reply_to, mine: m.sender == me, edited: m.edited.is_some() }
}

/// The newest `n` messages, oldest first, read outside a view.
pub fn recent(db: &osis::ReadOnly, c: Tid, n: usize) -> Result<Vec<Line>> {
    let mut timeline = Timeline::new(db, c)?;
    let mut messages = timeline.older(db, n)?.messages;
    messages.reverse();
    let shown: BTreeMap<CommitPos, &Message> = messages.iter().map(|m| (m.id, m)).collect();
    let further: Vec<CommitPos> = messages.iter().filter_map(Message::reply_to).filter(|r| !shown.contains_key(r)).collect();
    let further = timeline.find_all(db, &further)?;
    let me = db.me();
    Ok(messages.iter().map(|m| line_of(m, me, |r| shown.get(&r).copied().or_else(|| further.get(&r)).map_or_else(|| r.to_string(), quote))).collect())
}

#[derive(Clone, Debug, PartialEq)]
struct Reply(String, Option<CommitPos>);
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
fn reply_of(cx: &Reader, node: &str) -> Result<Option<CommitPos>> {
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
    e.key = format!("{c}/{}", l.id);
    e.author = Some(head);
    e.text = l.text.clone();
    e.time = Some(l.time);
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
            // walks to the message: the quote cost named at `quotes_of`
            let quoted = (*cx.memo(("reply quote", t, r), |r, &(_, t, p)| Ok(osis_chat::find(&r.db, t, &p)?.as_ref().map(quote)))?).clone();
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
    fn stream(&self, cx: &Reader, t: Tid, before: Option<u64>, n: usize, out: &mut Vec<Entry>) -> Result<()> {
        let s = cx.summary(t)?;
        out.extend(lines(cx, t, before, n)?.iter().map(|l| entry_of(t, &s, l)));
        Ok(())
    }
    fn stream_row(&self, cx: &Cx, e: &mut Entry) -> Result<()> {
        if let Some(pos) = e.key.rsplit('/').next().and_then(|p| p.parse::<CommitPos>().ok()) {
            e.actions = vec![Chip::action(Icon::Back, "Reply", Do::new(Reply(cx.path(), Some(pos))))];
        }
        Ok(())
    }
}
