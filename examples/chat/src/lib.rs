//! chat: the group-chat pattern of notes/chat.md over the `osis` API, as scenario functions the
//! tests and the binary drive.
//!
//! - The **chat actor** C is a group owned by its creator's person, synced on the creator's
//!   servers under its own label (not placed in the home group). Its title and hidden-message set live on it.
//!   Every participant is a writer of C; moderators are its admins.
//! - Each participant has a **persona** P per chat: an actor and group owned by its person,
//!   placed in C and added to C's subgroups. Edge (C on P, read) lets everyone in C read what P
//!   owns. P owns the participant's messages (placed in P), reactions and read marker.
//! - **Join by link**: a write link to C; the joiner then makes its persona itself.
//! - **Removal**: the persona leaves C's group, the person is demoted (C's keys rotate).
//! - **Disappearing messages** expire, placement included. **Typing** is a signal on P.
#![forbid(unsafe_code)]

use osis::core::GROUP;
use osis::{Demotion, EdgeOpts, LinkOpts, Lower, Osis, Path, Place, Result, Role, ShareLink, SignalEvent, Subscription, Target, Tid, WallMs, p};
use std::time::Duration;

/// Typed keys generated from chat.osis.
#[allow(dead_code, clippy::all)]
pub mod schema {
    use osis::schema as osis_schema;
    include!(concat!(env!("OUT_DIR"), "/chat.rs"));
}
pub use schema::{HIDDEN, NICK, REACTIONS, READ, TEXT, TITLE, TYPING};

/// A new chat with its creator's persona: (chat actor, persona). The chat is synced under its
/// own label only, not placed in the creator's home group: the creator's other devices find it
/// through the home label's `/label` cross-publish, and its rotations and messages are not
/// copied under the home label.
pub fn new_chat(db: &Osis, title: &str, nick: &str) -> Result<(Tid, Tid)> {
    let chat = db.write_with(|w| {
        let chat = w.create(db.me(), Place::Unsynced)?;
        w.make_group(chat)?;
        w.at(chat, TITLE).set(&title.to_string())?;
        Ok(chat)
    })?;
    db.sync(chat, &[])?;
    let me = persona(db, chat, nick)?;
    Ok((chat, me))
}

/// Makes this participant's persona in `chat` (it must be a writer of the chat already).
pub fn persona(db: &Osis, chat: Tid, nick: &str) -> Result<Tid> {
    let p = db.write_with(|w| {
        let p = w.create(db.me(), Place::In(chat))?;
        w.make_group(p)?;
        w.at(p, NICK).set(&nick.to_string())?;
        w.add_subgroup(chat, p)?;
        Ok(p)
    })?;
    db.grant(p, chat, Role::Read, EdgeOpts::default())?;
    Ok(p)
}

/// A link that makes its redeemer a participant (a writer of the chat).
pub fn invite(db: &Osis, chat: Tid, single_use: bool) -> Result<ShareLink> {
    db.make_link(chat, Role::Write, LinkOpts { until: None, single_use })
}

/// Joins a chat by link: (chat actor, own persona).
pub async fn join(db: &Osis, link: &ShareLink, nick: &str) -> Result<(Tid, Tid)> {
    let chat = db.redeem(link).await?;
    let p = persona(db, chat, nick)?;
    Ok((chat, p))
}

/// Posts a message as `persona`; with `expires`, the message (its text and its placement in the
/// persona) disappears everywhere after that long.
pub fn send(db: &Osis, persona: Tid, text: &str, expires: Option<Duration>) -> Result<Tid> {
    db.write_with(|w| {
        let m = w.create_expiring(persona, Place::In(persona), expires)?;
        w.at(m, TEXT).expires(expires).set(&text.to_string())?;
        Ok(m)
    })
}

/// One message of a timeline.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    pub tid: Tid,
    pub persona: Tid,
    pub nick: String,
    pub text: String,
    /// When it was sent: its creation's display time, `min(ts, received)`.
    pub at: WallMs,
}

/// The personas of a chat (its subgroups).
pub fn personas(db: &Osis, chat: Tid) -> Result<Vec<Tid>> {
    Ok(db.get(chat, GROUP)?.map(|g| g.subgroups.into_iter().collect()).unwrap_or_default())
}

/// The chat's visible messages, oldest first (send time, then commit order and tid). Without a query API this
/// reads every persona's group and every message (issues/api-deferred.md, Queries).
pub fn timeline(db: &Osis, chat: Tid) -> Result<Vec<Message>> {
    let hidden = db.get(chat, HIDDEN)?.unwrap_or_default();
    let mut out = Vec::new();
    for p in personas(db, chat)? {
        let nick = db.get(p, NICK)?.unwrap_or_default();
        let Some(g) = db.get(p, GROUP)? else { continue };
        for m in g.items.into_iter().filter(|m| !hidden.contains(m)) {
            if let (Some(text), Some(c)) = (db.get(m, TEXT)?, db.created(m)) {
                out.push(((c.shown(), c.ts), Message { tid: m, persona: p, nick: nick.clone(), text, at: c.shown() }));
            }
        }
    }
    out.sort_by_key(|(k, m)| (*k, m.tid));
    Ok(out.into_iter().map(|(_, m)| m).collect())
}

/// The texts of the timeline, for quick comparisons.
pub fn texts(db: &Osis, chat: Tid) -> Result<Vec<String>> {
    Ok(timeline(db, chat)?.into_iter().map(|m| m.text).collect())
}

/// Reacts to a message with `emoji` (on the reacting persona; the first reaction to a message
/// creates its entry).
pub fn react(db: &Osis, persona: Tid, msg: Tid, emoji: &str) -> Result<()> {
    db.write_with(|w| w.at(persona, REACTIONS).path(p![msg]).add(&emoji.to_string()))
}

/// Everyone's reactions to `msg`: (nick, emoji).
pub fn reactions(db: &Osis, chat: Tid, msg: Tid) -> Result<Vec<(String, String)>> {
    let mut out = Vec::new();
    for p in personas(db, chat)? {
        let nick = db.get(p, NICK)?.unwrap_or_default();
        let r = db.get(p, REACTIONS)?.unwrap_or_default();
        for e in r.get(&msg).into_iter().flatten() {
            out.push((nick.clone(), e.clone()));
        }
    }
    Ok(out)
}

/// Moves the persona's read marker to `msg`.
pub fn mark_read(db: &Osis, persona: Tid, msg: Tid) -> Result<()> {
    db.write_with(|w| w.at(persona, READ).set(&msg))
}

pub fn read_marker(db: &Osis, persona: Tid) -> Result<Option<Tid>> {
    db.get(persona, READ)
}

/// A moderator hides a message (nobody edits or purges another participant's message).
pub fn hide(db: &Osis, chat: Tid, msg: Tid) -> Result<()> {
    db.write_with(|w| w.at(chat, HIDDEN).path(Path::root()).add(&msg))
}

/// Says this participant is typing (or stopped). Never stored.
pub fn typing(db: &Osis, persona: Tid, on: bool) -> Result<()> {
    db.send_signal(persona, &TYPING, &on, Target::All)
}

/// Calls `f(persona, typing)` for typing signals of the chat's personas, joiners after this
/// call included.
pub fn on_typing(db: &Osis, chat: Tid, f: impl Fn(Tid, bool) + Send + 'static) -> Subscription {
    db.on_signal_in(chat, TYPING, move |_, e: SignalEvent<bool>| {
        if let Ok(on) = e.value {
            f(e.tid, on)
        }
    })
}

/// A moderator removes a participant: its persona leaves the chat's group, then its person
/// loses its edge (after the pre-sync; keys rotate). For a participant who joined by link that
/// edge is on the link's actor, and the link goes too (`Osis::demote`); the other joiners stay.
pub async fn remove(db: &Osis, chat: Tid, persona: Tid) -> Result<()> {
    let person = db.owner_of(persona).ok_or(osis::Error::UnknownThing { tid: persona })?;
    db.write_with(|w| {
        w.remove_subgroup(chat, persona)?;
        w.unplace(persona, chat)
    })?;
    db.demote(chat, person, Lower::Remove, Demotion::default()).await
}
