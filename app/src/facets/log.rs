//! `chat:msg~0`: a signal of messages kept forever; entries, a composer, replies. The only file that names
//! osis_chat (its keys and edit rules). The sender's name is the profile's `name.0`, else `OSIS_CHAT_NAME`.

use osis_kit::view::arrange::{NEWEST, stream};
use osis_kit::view::{Action, Block, Chip, Composer, ComposerField, Cx, Do, Entry, Facet, Icon, Input, Mark, Notify, Section, Summary, Window};
use crate::schema::{DRAFT, REPLY_TO};
use osis::core::NAME;
use osis::{Body, CommitEvent, CommitPos, Osis, Result, Subscription, Tid};
use osis_chat::schema::{MSG, SETTINGS};
use osis_chat::{Message, Timeline};

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

/// The log's name: its settings' name, `"Chat"` when unnamed.
pub fn name(db: &Osis, c: Tid) -> Result<String> {
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
    format!("{}: {}", who(m), text_of(&m.body).lines().next().unwrap_or(""))
}

/// The newest `n` messages, oldest first.
pub fn recent(db: &Osis, c: Tid, n: usize) -> Result<Vec<Line>> {
    let mut messages = Timeline::new(db, c)?.older(db, n)?.messages;
    messages.reverse();
    let me = db.me();
    let mut out: Vec<Line> = Vec::new();
    for m in &messages {
        let reply_to = match m.reply_to() {
            None => None,
            Some(r) => {
                let to = match messages.iter().find(|x| x.id == r) {
                    Some(x) => Some(x.clone()),
                    // further back than the page: look it up
                    None => osis_chat::find(db, c, &r)?,
                };
                Some((r, to.map_or_else(|| r.to_string(), |x| quote(&x))))
            }
        };
        out.push(Line { id: m.id, who: who(m), time: m.time.0, text: text_of(&m.body), reply_to, mine: m.sender == me, edited: m.edited.is_some() });
    }
    Ok(out)
}

#[derive(Clone, Debug, PartialEq)]
struct Reply(String, Option<CommitPos>);
impl Action for Reply {
    fn run(&self, cx: &Cx<'_>, _: &Input) -> Result<()> {
        match self.1 {
            Some(r) => cx.set_state(REPLY_TO, &self.0, &r.to_string()),
            None => cx.clear_state(REPLY_TO, &self.0),
        }
    }
}

/// A composer field's entry in `draft.0`.
fn field(node: &str, name: &str) -> String {
    format!("{node}#{name}")
}

/// The answered message of the node, if a valid one.
fn reply_of(cx: &Cx<'_>, node: &str) -> Result<Option<CommitPos>> {
    Ok(cx.state(REPLY_TO, node)?.and_then(|s| s.parse().ok()))
}

#[derive(Clone, Debug, PartialEq)]
struct Send(Tid, String);
impl Action for Send {
    fn run(&self, cx: &Cx<'_>, input: &Input) -> Result<()> {
        let c = self.0;
        let node = &self.1;
        let win = cx.data.window()?;
        let keys = [field(node, "subject"), field(node, "text")].map(|k| (node.clone(), win, "osis_app:draft.0".to_string(), Some(k)));
        // the sessions commit what is pending, so the drafts hold all of it
        for k in &keys {
            cx.window.sessions.close_key(k);
        }
        let read = |name| -> Result<String> { Ok(cx.state(DRAFT, &field(node, name))?.unwrap_or_default()) };
        let text = match input {
            Input::Text(t) => t.clone(),
            _ => read("text")?,
        };
        send(&cx.data.db, c, &read("subject")?, &text, reply_of(cx, node)?)?;
        cx.clear_state(DRAFT, &field(node, "subject"))?;
        cx.clear_state(DRAFT, &field(node, "text"))?;
        cx.clear_state(REPLY_TO, node)?;
        // the drafts are empty now: the editors come back over them
        cx.effects.borrow_mut().rebuild = true;
        Ok(())
    }
}

/// "Mon 3 Nov 14:05", local.
fn when(utc_ms: u64) -> String {
    use crate::time::{DAY, fmt_day, fmt_time, local_of};
    let l = local_of(i64::try_from(utc_ms).unwrap_or(i64::MAX));
    format!("{} {}", fmt_day(l.div_euclid(DAY)), fmt_time(l))
}

fn entry_of(node: &str, c: Tid, s: &Summary, l: &Line) -> Entry {
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
    e.actions = vec![Chip::action(Icon::Back, "Reply", Do::new(Reply(node.to_string(), Some(l.id))))];
    e
}

impl Facet for LogFacet {
    fn id(&self) -> &'static str {
        ID
    }
    fn claims(&self, ak: &str) -> bool {
        ak.starts_with("chat:")
    }
    fn summarize(&self, cx: &Cx<'_>, t: Tid, s: &mut Summary) -> Result<()> {
        s.words.insert(0, "Chat".into());
        s.mark = Mark::Icon(Icon::People);
        if s.name.is_empty() {
            s.name = name(&cx.data.db, t)?;
        }
        if s.sub.is_empty() {
            s.sub = "Conversation".into();
        }
        Ok(())
    }
    fn show(&self, cx: &Cx<'_>, t: Tid) -> Result<Section> {
        let lines = recent(&cx.data.db, t, NEWEST)?;
        let s = cx.summary(t)?;
        let node = cx.path();
        let reply = reply_of(cx, &node)?;
        let mut blocks = Vec::new();
        if lines.is_empty() {
            blocks.push(Block::Line("No messages yet.".into()));
        } else if lines.len() == NEWEST {
            blocks.push(Block::Line(format!("The newest {NEWEST} messages.")));
        }
        blocks.push(Block::Entries(stream(lines.iter().map(|l| entry_of(&node, t, &s, l)).collect())));
        let mut foot = Vec::new();
        if let Some(r) = reply.filter(|_| cx.config().get("composer") != Some("none")) {
            let what = match osis_chat::find(&cx.data.db, t, &r)? {
                Some(m) => format!("Replying to {}", quote(&m)),
                None => format!("Replying to {r}"),
            };
            foot.push(Block::Line(what));
            foot.push(Block::Chips(vec![Chip::action(Icon::Back, "Don't reply", Do::new(Reply(node.clone(), None)))]));
        }
        if cx.config().get("composer") != Some("none") && let Some(win) = cx.data.window_opt()? {
            foot.push(Block::Composer(Composer {
                fields: vec![
                    ComposerField { thing: win, ak: "osis_app:draft.0".into(), key: field(&node, "subject"), placeholder: "Subject (optional)".into() },
                    ComposerField { thing: win, ak: "osis_app:draft.0".into(), key: field(&node, "text"), placeholder: "Message, Enter sends".into() },
                ],
                send: Do::new(Send(t, node.clone())),
            }));
        }
        Ok(Section { blocks, foot, follow_end: true })
    }
    fn entries(&self, cx: &Cx<'_>, t: Tid, win: &Window, out: &mut Vec<Entry>) -> Result<()> {
        let Window::Newest(n) = *win else { return Ok(()) };
        let s = cx.summary(t)?;
        let node = cx.path();
        out.extend(recent(&cx.data.db, t, n)?.iter().map(|l| entry_of(&node, t, &s, l)));
        Ok(())
    }
    fn live(&self, cx: &Cx<'_>, t: Tid, n: Notify) -> Result<Option<Subscription>> {
        let sub = cx.data.db.at(t, MSG).on_fire(move |_, e| {
            if matches!(e, CommitEvent::Ended(_)) { (n.ended)() } else { (n.changed)() }
        })?;
        Ok(Some(sub))
    }
}
