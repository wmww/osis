//! Chats (toolkit-free, over osis-chat, notes/chat.md): the chats this store holds, joining by
//! link, the newest messages of one, sending, and the name to send under.
//!
//! The chats are `osis_chat::chats`: those made or joined here or by the CLI on this store alike.
//! The sender's name is the profile's `name.0` (the same word `reach` shows for this person), else
//! `OSIS_CHAT_NAME`, as the CLI's `--from`. A store without hosts has no profile (`profile()`
//! fails): only the variable names it.

use osis::core::NAME;
use osis::{Osis, Result, Tid};
use osis_chat::{Body, Draft, Id, Message, Timeline};

/// One chat as a list shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChatTile {
    pub tid: Tid,
    /// Its settings' name, `"Chat"` when unnamed.
    pub name: String,
}

/// One message as a timeline shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Line {
    pub id: Id,
    /// The name it was sent under, else the start of the sender's tid.
    pub who: String,
    /// UTC ms.
    pub time: u64,
    /// The text (`<deleted>` and the like for what has none here).
    pub text: String,
    /// The answered message: its sender and first line, or its id when not here.
    pub reply_to: Option<(Id, String)>,
    pub mine: bool,
    pub edited: bool,
}

/// The chats this store holds, by name.
pub fn chats(db: &Osis) -> Result<Vec<ChatTile>> {
    let mut out = osis_chat::chats(db)?.into_iter().map(|t| Ok(ChatTile { tid: t, name: name(db, t)? })).collect::<Result<Vec<_>>>()?;
    out.sort_by(|a, b| (&a.name, a.tid).cmp(&(&b.name, b.tid)));
    Ok(out)
}

/// The chat's name.
pub fn name(db: &Osis, c: Tid) -> Result<String> {
    let n = osis_chat::settings(db, c)?.name;
    Ok(if n.trim().is_empty() { "Chat".into() } else { n })
}

/// How long the app waits for a link's host to answer: it runs off the UI thread, and a person is
/// watching. Minor: at 0 every join fails, at infinity one that nobody answers spins for good.
const JOIN_WAIT: std::time::Duration = std::time::Duration::from_secs(60);

/// Joins by an `osis://` link (`osis chat link`): the chat, once here. Blocks until the link's
/// host answers or `JOIN_WAIT` passes.
pub fn join(db: &Osis, link: &str) -> Result<Tid> {
    let l: osis::ShareLink = link.trim().parse().map_err(|e| osis::Error::Invalid(format!("not a chat link: {e}")))?;
    block_on(osis_chat::join(db, &l, JOIN_WAIT))
}

/// The profile, made on first use; `None` on a store without hosts.
fn profile(db: &Osis) -> Result<Option<Tid>> {
    if db.hosts()?.is_empty() { Ok(None) } else { db.profile().map(Some) }
}

/// The name messages go out under: the profile's `name.0`, else `OSIS_CHAT_NAME`.
pub fn my_name(db: &Osis) -> Result<Option<String>> {
    let own = match profile(db)? {
        Some(p) => db.at(p, NAME).get()?.filter(|n| !n.trim().is_empty()),
        None => None,
    };
    Ok(own.or_else(|| std::env::var("OSIS_CHAT_NAME").ok().filter(|n| !n.trim().is_empty())))
}

/// Sets the profile's name (empty: none).
pub fn set_name(db: &Osis, name: &str) -> Result<()> {
    let p = profile(db)?.ok_or_else(|| osis::Error::Invalid("a name needs a host: start with --host".into()))?;
    let mut w = db.write();
    if name.trim().is_empty() { w.at(p, NAME).remove()? } else { w.at(p, NAME).set(&name.trim().to_string())? }
    w.commit()?;
    Ok(())
}

/// Sends `text` (a `subject` first, as the CLI's `--subject`), answering `reply_to`.
pub fn send(db: &Osis, c: Tid, subject: &str, text: &str, reply_to: Option<Id>) -> Result<Id> {
    let (s, t) = (subject.trim(), text.trim());
    let text = match (s.is_empty(), t.is_empty()) {
        (_, true) if s.is_empty() => return Err(osis::Error::Invalid("nothing to send".into())),
        (true, _) => t.to_string(),
        (false, true) => s.to_string(),
        (false, false) => format!("{s}\n\n{t}"),
    };
    osis_chat::send(db, c, &Draft { text, name: my_name(db)?, reply_to })
}

fn text_of(b: &Body) -> String {
    match b {
        Body::Text(t) => t.clone(),
        Body::Deleted { .. } => "<deleted>".into(),
        Body::Gone => "<gone>".into(),
        Body::NotFetched => "<not here yet>".into(),
        Body::Odd => "<unreadable>".into(),
    }
}

/// The name a message was sent under, else the start of its sender's tid.
fn who(m: &Message) -> String {
    m.name.clone().filter(|n| !n.trim().is_empty()).unwrap_or_else(|| m.sender.to_string().chars().take(8).collect())
}

/// A message as a reply names it: its sender and first line.
pub fn quote(m: &Message) -> String {
    format!("{}: {}", who(m), text_of(&m.body).lines().next().unwrap_or(""))
}

/// The newest `n` messages, oldest first.
pub fn recent(db: &Osis, c: Tid, n: usize) -> Result<Vec<Line>> {
    let mut msgs = Timeline::new(db, c)?.older(db, n)?.messages;
    msgs.reverse();
    let me = db.me();
    let mut out: Vec<Line> = Vec::new();
    for m in &msgs {
        let reply_to = match m.reply_to {
            None => None,
            Some(r) => {
                let to = match msgs.iter().find(|x| x.id == r) {
                    Some(x) => Some(x.clone()),
                    // further back than the page: look it up
                    None => osis_chat::find(db, c, &r)?,
                };
                let what = to.map_or_else(|| r.to_string(), |x| quote(&x));
                Some((r, what))
            }
        };
        out.push(Line { id: m.id, who: who(m), time: m.time, text: text_of(&m.body), reply_to, mine: m.sender == me, edited: m.edited.is_some() });
    }
    Ok(out)
}

/// Polls `f` on this thread until it is ready.
fn block_on<F: Future>(f: F) -> F::Output {
    struct Unpark(std::thread::Thread);
    impl std::task::Wake for Unpark {
        fn wake(self: std::sync::Arc<Self>) {
            self.0.unpark();
        }
    }
    let mut f = std::pin::pin!(f);
    let waker = std::task::Waker::from(std::sync::Arc::new(Unpark(std::thread::current())));
    let mut cx = std::task::Context::from_waker(&waker);
    loop {
        if let std::task::Poll::Ready(v) = f.as_mut().poll(&mut cx) {
            return v;
        }
        std::thread::park();
    }
}
