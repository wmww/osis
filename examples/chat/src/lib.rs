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
use osis::{Demotion, EdgeOpts, FieldId, LinkOpts, Lower, Osis, Path, Place, Result, Role, ShareLink, SignalEvent, Subscription, Target, Tid, p};
use std::time::Duration;

/// Typed keys generated from chat.osis.
#[allow(dead_code, clippy::all)]
pub mod schema {
    use osis::schema as osis_schema;
    include!(concat!(env!("OUT_DIR"), "/chat.rs"));
}
pub use schema::{HIDDEN, NICK, REACTIONS, READ, SENT, TEXT, TITLE, TYPING};

/// `/group` field 0: items.
fn items() -> Path {
    p![FieldId(0)]
}

/// A new chat with its creator's persona: (chat actor, persona). The chat is synced under its
/// own label only, not placed in the creator's home group: the creator's other devices find it
/// through the home label's `/label` cross-publish, and its rotations and messages are not
/// copied under the home label.
pub fn new_chat(db: &Osis, title: &str, nick: &str) -> Result<(Tid, Tid)> {
    let mut w = db.write();
    let chat = w.create(db.me(), Place::Unsynced)?;
    w.make_group(chat)?;
    w.at(chat, TITLE).set(&title.to_string())?;
    w.commit()?;
    db.sync(chat, &[])?;
    let me = persona(db, chat, nick)?;
    Ok((chat, me))
}

/// Makes this participant's persona in `chat` (it must be a writer of the chat already).
pub fn persona(db: &Osis, chat: Tid, nick: &str) -> Result<Tid> {
    let mut w = db.write();
    let p = w.create(db.me(), Place::In(chat))?;
    w.make_group(p)?;
    w.at(p, NICK).set(&nick.to_string())?;
    w.add_subgroup(chat, p)?;
    w.commit()?;
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

/// Posts a message as `persona` at `sent` (ms, the sender's clock); with `expires`, the message
/// (its text, time and placement) disappears everywhere after that long.
pub fn send(db: &Osis, persona: Tid, text: &str, sent: i64, expires: Option<Duration>) -> Result<Tid> {
    let mut w = db.write();
    let m = w.create(persona, Place::Unsynced)?;
    expiring(w.at(m, TEXT), expires).set(&text.to_string())?;
    expiring(w.at(m, SENT), expires).set(&sent)?;
    // the placement is a write to the persona's `/group`: it expires with the message
    expiring(w.at(persona, GROUP), expires).path(items()).add(&m)?;
    w.commit()?;
    Ok(m)
}

fn expiring<'w, 'd, K: osis::AspectKey>(a: osis::AspectWrite<'w, 'd, K>, expires: Option<Duration>) -> osis::AspectWrite<'w, 'd, K> {
    match expires {
        Some(d) => a.expires_in(d),
        None => a,
    }
}

/// One message of a timeline.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    pub tid: Tid,
    pub persona: Tid,
    pub nick: String,
    pub text: String,
    pub sent: i64,
}

/// The personas of a chat (its subgroups).
pub fn personas(db: &Osis, chat: Tid) -> Result<Vec<Tid>> {
    Ok(db.get(chat, GROUP)?.map(|g| g.subgroups.into_iter().collect()).unwrap_or_default())
}

/// The chat's visible messages, oldest first (sent time, then tid). Without a query API this
/// reads every persona's group and every message (issues/api-deferred.md, Queries).
pub fn timeline(db: &Osis, chat: Tid) -> Result<Vec<Message>> {
    let hidden = db.get(chat, HIDDEN)?.unwrap_or_default();
    let mut out = Vec::new();
    for p in personas(db, chat)? {
        let nick = db.get(p, NICK)?.unwrap_or_default();
        let Some(g) = db.get(p, GROUP)? else { continue };
        for m in g.items.into_iter().filter(|m| !hidden.contains(m)) {
            if let (Some(text), Some(sent)) = (db.get(m, TEXT)?, db.get(m, SENT)?) {
                out.push(Message { tid: m, persona: p, nick: nick.clone(), text, sent });
            }
        }
    }
    out.sort_by_key(|m| (m.sent, m.tid));
    Ok(out)
}

/// The texts of the timeline, for quick comparisons.
pub fn texts(db: &Osis, chat: Tid) -> Result<Vec<String>> {
    Ok(timeline(db, chat)?.into_iter().map(|m| m.text).collect())
}

/// Reacts to a message with `emoji` (on the reacting persona).
pub fn react(db: &Osis, persona: Tid, msg: Tid, emoji: &str) -> Result<()> {
    let e = emoji.to_string();
    // a path op into an absent map key fails: the first reaction puts the set
    let known = db.at(persona, REACTIONS).path(p![msg]).get_value()?.is_some();
    db.write_with(|w| {
        let mut a = w.at(persona, REACTIONS);
        if known { a.path(p![msg]).add(&e) } else { a.path(Path::root()).put(&msg, &std::collections::BTreeSet::from([e.clone()])) }
    })?;
    Ok(())
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
    db.write_with(|w| w.at(persona, READ).set(&msg))?;
    Ok(())
}

pub fn read_marker(db: &Osis, persona: Tid) -> Result<Option<Tid>> {
    db.get(persona, READ)
}

/// A moderator hides a message (nobody edits or purges another participant's message).
pub fn hide(db: &Osis, chat: Tid, msg: Tid) -> Result<()> {
    db.write_with(|w| w.at(chat, HIDDEN).path(Path::root()).add(&msg))?;
    Ok(())
}

/// Says this participant is typing (or stopped). Never stored.
pub fn typing(db: &Osis, persona: Tid, on: bool) -> Result<()> {
    db.send_signal(persona, &TYPING, &on, Target::All)
}

/// Calls `f(persona, typing)` for typing signals of the chat's current personas. One
/// subscription per persona: a persona that joins later needs a new call.
pub fn on_typing(db: &Osis, chat: Tid, f: impl Fn(Tid, bool) + Send + Sync + 'static) -> Result<Vec<Subscription>> {
    let f = std::sync::Arc::new(f);
    Ok(personas(db, chat)?
        .into_iter()
        .map(|p| {
            let f = f.clone();
            db.on_signal(p, TYPING, move |_, e: SignalEvent<bool>| {
                if let Ok(on) = e.value {
                    f(p, on)
                }
            })
        })
        .collect())
}

/// A moderator removes a participant: its persona leaves the chat's group, then its person
/// loses its edge (after the pre-sync; keys rotate). A participant who joined by link is a
/// member of the link's actor, not of the chat: it is removed there, and a multi-use link is
/// revoked too (the joiner may keep its seed, spec/permissions.md §9); the other joiners stay.
pub async fn remove(db: &Osis, chat: Tid, persona: Tid) -> Result<()> {
    let person = owner(db, persona)?;
    db.write_with(|w| {
        w.remove_subgroup(chat, persona)?;
        w.unplace(persona, chat)
    })?;
    if db.roster(chat).contains_key(&person) {
        return db.demote(chat, person, Lower::Remove, Demotion::default()).await;
    }
    for l in db.links(chat) {
        if db.roster(l.id).contains_key(&person) {
            // a multi-use link ends with the joiner, in one commit (one rotation)
            return if l.single_use { db.demote(l.id, person, Lower::Remove, Demotion::default()).await } else { db.revoke_joiner(l.id, person, Demotion::default()).await };
        }
    }
    Err(osis::Error::UnknownActor { tid: person })
}

/// The owner of a thing, from its creation record (the person behind a persona).
pub fn owner(db: &Osis, t: Tid) -> Result<Tid> {
    match db.get(t, osis::core::CREATED)? {
        Some(osis::schema::osis_core::CreationRecord::Thing { owner, .. }) => Ok(owner),
        _ => Err(osis::Error::UnknownThing { tid: t }),
    }
}
