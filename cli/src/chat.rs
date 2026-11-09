//! `osis chat`: chats over plain osis calls on schema/chat.osis, with osis-chat's creation and edit
//! rules (notes/chat.md).

use crate::args::ChatCmd;
use crate::Ctx;
use crate::cmd::{deliver, parse_role};
use crate::json::J;
use crate::{exit, parse_dur, usage};
use osis::core::REQUIRED;
use osis::{Body, Commit, CommitEvent, CommitKind, CommitPos, GrantOpts, HolderKind, LinkOpts, Osis, PurgeBy, Role, SetRoleOpts, Tid};
use osis_chat::schema::{self, EditMode, MSG, SETTINGS};
use osis_chat::{Message, Options, Timeline};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, mpsc};

fn id(s: &str) -> anyhow::Result<CommitPos> {
    Ok(s.parse::<CommitPos>()?)
}

fn opt_id(i: Option<&CommitPos>) -> J {
    J::opt(i.map(|i| J::str(i.to_string())))
}

/// A body's state word and its text.
fn state(b: &Body<schema::Message>) -> (&'static str, &str) {
    match b {
        Body::Held(Some(m)) => ("text", &m.text),
        Body::Held(None) | Body::TooLarge { .. } => ("odd", ""),
        Body::Purged { .. } => ("deleted", ""),
        Body::NotFetched => ("not-fetched", ""),
    }
}

fn name_of(b: &Body<schema::Message>) -> Option<String> {
    match b {
        Body::Held(Some(m)) => m.name.clone(),
        _ => None,
    }
}

fn reply_of(b: &Body<schema::Message>) -> Option<CommitPos> {
    match b {
        Body::Held(Some(m)) => m.reply_to.as_deref().and_then(|r| r.parse().ok()),
        _ => None,
    }
}

fn who(sender: Tid, name: Option<&String>) -> String {
    name.map_or_else(|| sender.to_uri(), |n| format!("{n} ({})", sender.to_uri()))
}

fn shown(b: &Body<schema::Message>) -> String {
    match b {
        Body::Held(Some(m)) => m.text.clone(),
        Body::Purged { actor: Some(w), .. } => format!("<deleted by {}>", w.to_uri()),
        b => format!("<{}>", state(b).0),
    }
}

fn deleted_by(b: &Body<schema::Message>) -> J {
    J::opt(match b {
        Body::Purged { actor, .. } => actor.map(J::tid),
        _ => None,
    })
}

fn message_line(json: bool, m: &Message) -> String {
    let (s, t) = state(&m.body);
    let name = name_of(&m.body);
    let reply_to = m.reply_to();
    if json {
        return J::obj([
            ("id", J::str(m.id.to_string())),
            ("sender", J::tid(m.sender)),
            ("name", J::opt(name.map(J::str))),
            ("time", J::int(m.time.0)),
            ("state", J::str(s)),
            ("text", J::str(t)),
            ("deleted_by", deleted_by(&m.body)),
            ("reply_to", opt_id(reply_to.as_ref())),
            ("edited", J::Bool(m.edited.is_some())),
            ("earlier", J::Arr(m.earlier.iter().map(|e| J::str(e.1.text.clone())).collect())),
            ("valid", J::Bool(m.valid)),
        ])
        .text();
    }
    let reply = reply_to.map_or_else(String::new, |r| format!(" (to {r})"));
    let edited = if m.edited.is_some() { " (edited)" } else { "" };
    let bad = if m.valid { "" } else { " (not delivered)" };
    format!("{} {} {}{reply}{edited}{bad}: {}", m.id, who(m.sender, name.as_ref()), m.time.0, shown(&m.body))
}

/// One message commit as a watch hears it, with the original it honestly edits.
fn commit_line(db: &Osis, c: Tid, json: bool, k: &Commit) -> Option<String> {
    let part = k.at(c, MSG).filter(|_| k.kind == CommitKind::Content)?;
    let of = osis_chat::edit_of(db, c, k).ok().flatten();
    let (s, t) = state(&part.body);
    let (name, reply_to, time) = (name_of(&part.body), reply_of(&part.body), k.stamp.shown().0);
    if json {
        return Some(
            J::obj([
                ("id", J::str(k.pos().to_string())),
                ("sender", J::tid(k.stamp.actor)),
                ("name", J::opt(name.map(J::str))),
                ("time", J::int(time)),
                ("state", J::str(s)),
                ("text", J::str(t)),
                ("deleted_by", deleted_by(&part.body)),
                ("reply_to", opt_id(reply_to.as_ref())),
                ("replaces", opt_id(of.as_ref())),
                ("valid", J::Bool(part.valid)),
            ])
            .text(),
        );
    }
    let reply = reply_to.map_or_else(String::new, |r| format!(" (to {r})"));
    let what = of.map_or_else(String::new, |o| format!(" replaces {o}"));
    let bad = if part.valid { "" } else { " (invalid)" };
    Some(format!("{} {} {time}{reply}{what}{bad}: {}", k.pos(), who(k.stamp.actor, name.as_ref()), shown(&part.body)))
}

fn find(ctx: &Ctx<'_>, c: Tid, i: &str) -> anyhow::Result<Message> {
    osis_chat::find(&ctx.db, c, &id(i)?)?.ok_or_else(|| exit(3, format!("no message {i}")))
}

/// Prints `s`, the first line out of the way of a reader of `cursor`.
fn print_since(ctx: &mut Ctx<'_>, s: &osis_chat::Since, from: Option<&CommitPos>) -> anyhow::Result<()> {
    let json = ctx.g.json;
    for m in &s.messages {
        ctx.line(&message_line(json, m))?;
    }
    let cursor = s.cursor.as_ref().or(from);
    if json {
        ctx.line(&J::obj([("cursor", opt_id(cursor)), ("more", J::Bool(s.more)), ("complete", J::Bool(s.complete))]).text())
    } else if let Some(c) = cursor {
        ctx.line(&format!("cursor {c}"))
    } else {
        Ok(())
    }
}

/// Fires `m` on chat `c`: its place.
fn fire(db: &Osis, c: Tid, m: &schema::Message) -> anyhow::Result<CommitPos> {
    let mut w = db.write();
    w.at(c, MSG).fire(m)?;
    Ok(w.commit()?.ok_or_else(|| anyhow::anyhow!("nothing written"))?.pos())
}

pub(crate) fn run(ctx: &mut Ctx<'_>, c: ChatCmd) -> anyhow::Result<()> {
    let db = ctx.db.clone();
    match c {
        ChatCmd::Create { name, purge, edit, disappear, no_retain_copy, peer } => {
            let purge = match purge.as_str() {
                "author-or-admin" => PurgeBy::AuthorOrAdmin,
                "author" => PurgeBy::Author,
                "admin" => PurgeBy::Admin,
                "nobody" => PurgeBy::Nobody,
                x => return Err(usage(format!("--purge: author-or-admin, author, admin or nobody, not {x:?}"))),
            };
            let edit = match edit.as_str() {
                "purge" => EditMode::Purge,
                "keep" => EditMode::Keep,
                "off" => EditMode::Off,
                x => return Err(usage(format!("--edit: purge, keep or off, not {x:?}"))),
            };
            let peers = peer.iter().map(|h| h.parse()).collect::<Result<Vec<osis::Address>, _>>()?;
            let o = Options { name, purge, edit, disappear: disappear.as_deref().map(parse_dur).transpose()?, retain_copies: !no_retain_copy, peers };
            let t = osis_chat::create(&db, &o)?;
            send_out(ctx, Some(t))?;
            ctx.emit(&[t.to_uri()], J::obj([("tid", J::tid(t))]))
        }
        ChatCmd::Add { chat, account, role } => {
            let t = ctx.tid(&chat)?;
            db.grant(t, ctx.tid(&account)?, parse_role(&role)?, GrantOpts::default())?;
            send_out(ctx, Some(t))
        }
        ChatCmd::Link { chat, role, single_use } => {
            let t = ctx.tid(&chat)?;
            let l = db.make_link(t, parse_role(&role)?, LinkOpts { until: None, single_use, direct: false })?;
            send_out(ctx, Some(t))?;
            ctx.emit(&[l.to_string()], J::obj([("link", J::str(l.to_string()))]))
        }
        ChatCmd::Join { link } => {
            let l: osis::ShareLink = ctx.arg_text(&link)?.parse()?;
            let t = crate::cmd::confirm(ctx, db.redeem(&l))?;
            send_out(ctx, None)?;
            // a `read` through the daemon does not pull: the first messages are here when this ends
            if !db.has_store() {
                catch_up(ctx, t);
            }
            ctx.emit(&[t.to_uri()], J::obj([("tid", J::tid(t))]))
        }
        ChatCmd::Kick { chat, account, erase, retain_copy, purge } => {
            let (t, p) = (ctx.tid(&chat)?, ctx.tid(&account)?);
            let retain_copy = if erase {
                Some(false)
            } else if retain_copy {
                Some(true)
            } else {
                None
            };
            db.set_role(t, p, None, SetRoleOpts { retain_copy })?;
            if purge {
                let mut w = db.write();
                w.at(t, MSG).purge(osis::Purge::Author(p))?;
                w.commit()?;
            }
            send_out(ctx, None)
        }
        ChatCmd::Post { chat, text, subject, from, reply_to } => {
            let t = ctx.tid(&chat)?;
            let body = ctx.arg_text(&text)?;
            let text = subject.map_or_else(|| body.clone(), |s| format!("{s}\n\n{body}"));
            let reply_to = reply_to.as_deref().map(id).transpose()?.map(|r| r.to_string());
            let m = fire(&db, t, &schema::Message { text, name: from, reply_to, edit: None })?;
            send_out(ctx, None)?;
            ctx.emit(&[m.to_string()], J::obj([("id", J::str(m.to_string()))]))
        }
        ChatCmd::Read { chat, max, before, after } => {
            let t = ctx.tid(&chat)?;
            pull(ctx, t);
            if let Some(a) = after {
                let a = id(&a)?;
                let s = osis_chat::since(&db, t, Some(&a), max)?;
                return print_since(ctx, &s, Some(&a));
            }
            let before = before.as_deref().map(id).transpose()?;
            // from the newest: a timeline has then seen every edit of what it reaches
            let mut tl = Timeline::new(&db, t)?;
            let mut got = Vec::new();
            let (mut more, mut complete);
            loop {
                let p = tl.older(&db, max.max(1))?;
                (more, complete) = (p.more, p.complete);
                got.extend(p.messages.into_iter().filter(|m| before.is_none_or(|b| m.id < b)));
                if got.len() >= max || !more {
                    break;
                }
            }
            more |= got.len() > max;
            got.truncate(max);
            // the cursor to go on from is the last arrived entry, whatever the page shows
            let cursor = osis_chat::cursor(&db, t)?;
            got.reverse();
            print_since(ctx, &osis_chat::Since { messages: got, cursor, more, complete }, None)
        }
        ChatCmd::Watch { chat, count, after } => {
            let t = ctx.tid(&chat)?;
            let json = ctx.g.json;
            let (tx, rx) = mpsc::channel::<String>();
            let wake = tx.clone();
            // over for good: the stream ends, and the command says so
            let ended = Arc::new(Mutex::new(None));
            let (mut tx, why) = (Some(tx), ended.clone());
            let sub = db.at(t, MSG).on_fire(move |db, e| {
                let line = match e {
                    CommitEvent::Commit { commit: Some(k), .. } => match commit_line(db, t, json, &k) {
                        Some(l) => l,
                        None => return,
                    },
                    CommitEvent::Commit { id: c, commit: None } => if json { J::obj([("left", J::str(c.to_string()))]).text() } else { format!("left {c}") },
                    CommitEvent::Reread => if json { J::obj([("reread", J::Bool(true))]).text() } else { "reread".to_string() },
                    CommitEvent::Ended(m) => {
                        *why.lock().unwrap_or_else(|e| e.into_inner()) = Some(m.to_string());
                        tx = None;
                        return;
                    }
                };
                if let Some(tx) = &tx {
                    let _ = tx.send(line);
                }
            })?;
            // subscribed first: nothing between the page and the stream is missed; a repeat is harmless
            if let Some(a) = after {
                let mut at = id(&a)?;
                loop {
                    let s = osis_chat::since(&db, t, Some(&at), crate::args::PAGE)?;
                    for m in &s.messages {
                        let _ = wake.send(message_line(json, m));
                    }
                    match s.cursor {
                        Some(c) if s.more => at = c,
                        _ => break,
                    }
                }
            }
            drop(wake);
            let timeout = ctx.timeout_or(None)?;
            let r = crate::cmd::stream_lines(ctx, &rx, count, timeout);
            drop(sub);
            let why = ended.lock().unwrap_or_else(|e| e.into_inner()).take();
            match why {
                Some(m) if r.is_ok() => Err(exit(1, format!("watch ended: {m}"))),
                _ => r,
            }
        }
        ChatCmd::Edit { chat, id: i, text } => {
            let t = ctx.tid(&chat)?;
            let m = find(ctx, t, &i)?;
            let new = osis_chat::edit(&db, t, &m, &text)?;
            send_out(ctx, None)?;
            ctx.emit(&[new.to_string()], J::obj([("id", J::str(new.to_string()))]))
        }
        ChatCmd::Resend { chat, id: i } => {
            // one's own message turned invalid (`OwnWriteInvalid`), its text, name and reply as a
            // new message; the old one stays, to this account alone
            let t = ctx.tid(&chat)?;
            let m = find(ctx, t, &i)?;
            let Body::Held(Some(body)) = &m.body else { return Err(exit(1, "its text is not here")) };
            if m.valid || m.sender != db.me() {
                return Err(exit(1, "only one's own undelivered message is sent again"));
            }
            let new = fire(&db, t, &schema::Message { edit: None, ..body.clone() })?;
            send_out(ctx, None)?;
            ctx.emit(&[new.to_string()], J::obj([("id", J::str(new.to_string()))]))
        }
        ChatCmd::Delete { chat, id: i } => {
            let t = ctx.tid(&chat)?;
            let m = find(ctx, t, &i)?;
            osis_chat::delete(&db, t, &m)?;
            send_out(ctx, None)
        }
        ChatCmd::Leave { chat } => {
            db.leave(db.me(), ctx.tid(&chat)?)?;
            send_out(ctx, None)
        }
        ChatCmd::Participants { chat } => {
            let t = ctx.tid(&chat)?;
            pull(ctx, t);
            let ways = db.holders(t)?;
            let (m, links) = people_and_links(&ways);
            let name = db.at(t, SETTINGS).get()?.map(|s| s.name).unwrap_or_default();
            // through an actor, or none: a joiner's `via` is its link's actor
            let via = |p: Tid| ways.iter().find(|h| h.actor == p).and_then(|h| match h.through.as_slice() {
                [k] => Some(*k),
                _ => None,
            });
            let mut text: Vec<String> = m.iter().map(|(p, r)| format!("{} {r:?}{}", p.to_uri(), via(*p).map_or_else(String::new, |k| format!(" via {}", k.to_uri())))).collect();
            text.extend(links.iter().map(|(k, r)| format!("link {} {r:?}", k.to_uri())));
            let j = J::obj([
                ("name", J::str(name)),
                ("participants", J::Arr(m.iter().map(|(p, r)| J::obj([("account", J::tid(*p)), ("role", J::str(format!("{r:?}"))), ("via", J::opt(via(*p).map(J::tid)))])).collect())),
                ("links", J::Arr(links.iter().map(|(k, r)| J::obj([("link", J::tid(*k)), ("role", J::str(format!("{r:?}")))])).collect())),
            ]);
            ctx.emit(&text, j)
        }
        ChatCmd::Disappear { chat, after } => {
            // later messages take it, earlier ones keep what they have
            let t = ctx.tid(&chat)?;
            let d = if after == "off" { None } else { Some(parse_dur(&after)?) };
            let mut rules = db.at(t, REQUIRED).get()?.unwrap_or_default();
            rules.rules.get_mut(&MSG.name()).ok_or_else(|| exit(3, format!("{chat} has no message rule: not a chat")))?.expires = d;
            let mut w = db.write();
            w.at(t, REQUIRED).set(&rules)?;
            w.commit()?;
            send_out(ctx, None)
        }
    }
}

/// A store this command just opened brings what its peers have (best effort: reading works offline).
fn pull(ctx: &mut Ctx<'_>, t: Tid) {
    if ctx.db.has_store() {
        catch_up(ctx, t);
    }
}

/// Waits a moment for what its peers have of `t` (best effort).
fn catch_up(ctx: &mut Ctx<'_>, t: Tid) {
    let db = ctx.db.clone();
    if db.saved_peers().is_ok_and(|h| !h.is_empty()) {
        let _ = db.nudge_sync();
        let _ = crate::cmd::within(Some(crate::DEFAULT_WAIT.min(std::time::Duration::from_secs(10))), db.wait_synced(osis::SyncScope::Thing(t)));
    }
}

/// What this command wrote reaches its peers before the process exits; a daemon sees to it itself.
fn send_out(ctx: &mut Ctx<'_>, shared: Option<Tid>) -> anyhow::Result<()> {
    if !ctx.db.has_store() || ctx.db.saved_peers()?.is_empty() {
        return Ok(());
    }
    deliver(ctx, shared.map_or(crate::cmd::Delivers::All, |t| crate::cmd::Delivers::Thing(t.to_uri())))
}

/// A chat's share view from its holders: the actors holding it directly and those who joined by a
/// link (each at its best role), and the links that work (a link's key still holds its actor).
fn people_and_links(ways: &[osis::Holder]) -> (BTreeMap<Tid, Role>, BTreeMap<Tid, Role>) {
    let is_link = |k: &Tid| ways.iter().any(|h| h.actor == *k && h.kind == HolderKind::Link && h.through.is_empty());
    let mut people = BTreeMap::new();
    let mut links = BTreeMap::new();
    for h in ways {
        match (h.kind, h.through.as_slice()) {
            (HolderKind::Link, []) if ways.iter().any(|x| x.kind == HolderKind::Key && x.through == [h.actor]) => {
                links.insert(h.actor, h.role);
            }
            (HolderKind::Actor, through) if through.is_empty() || matches!(through, [k] if is_link(k)) => {
                let r = people.entry(h.actor).or_insert(h.role);
                *r = h.role.max(*r);
            }
            _ => {}
        }
    }
    (people, links)
}
