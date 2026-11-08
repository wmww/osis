//! `osis chat`: a command per call of osis-chat (notes/chat.md).

use crate::args::ChatCmd;
use crate::Ctx;
use crate::cmd::{deliver, parse_role};
use crate::json::J;
use crate::{exit, parse_dur, usage};
use osis::Tid;
use osis_chat::{Body, Draft, EditMode, Entry, Event, Id, Message, Options, PurgeBy, Timeline};
use std::sync::{Arc, Mutex, mpsc};

fn id(s: &str) -> anyhow::Result<Id> {
    Ok(s.parse::<Id>()?)
}

fn opt_id(i: Option<&Id>) -> J {
    J::opt(i.map(|i| J::str(i.to_string())))
}

fn state(b: &Body) -> (&'static str, &str) {
    match b {
        Body::Text(t) => ("text", t),
        Body::Deleted { .. } => ("deleted", ""),
        Body::NotFetched => ("not-fetched", ""),
        Body::Odd => ("odd", ""),
    }
}

fn who(sender: Tid, name: Option<&String>) -> String {
    name.map_or_else(|| sender.to_uri(), |n| format!("{n} ({})", sender.to_uri()))
}

fn shown(b: &Body) -> String {
    match b {
        Body::Text(t) => t.clone(),
        Body::Deleted { who: Some(w), .. } => format!("<deleted by {}>", w.to_uri()),
        b => format!("<{}>", state(b).0),
    }
}

fn deleted_by(b: &Body) -> J {
    J::opt(match b {
        Body::Deleted { who, .. } => who.map(J::tid),
        _ => None,
    })
}

fn message_line(json: bool, m: &Message) -> String {
    let (s, t) = state(&m.body);
    if json {
        return J::obj([
            ("id", J::str(m.id.to_string())),
            ("sender", J::tid(m.sender)),
            ("name", J::opt(m.name.clone().map(J::str))),
            ("time", J::int(m.time)),
            ("state", J::str(s)),
            ("text", J::str(t)),
            ("deleted_by", deleted_by(&m.body)),
            ("reply_to", opt_id(m.reply_to.as_ref())),
            ("edited", J::Bool(m.edited.is_some())),
            ("earlier", J::Arr(m.earlier.iter().map(|e| J::str(state(&e.body).1)).collect())),
            ("valid", J::Bool(m.valid)),
        ])
        .text();
    }
    let reply = m.reply_to.map_or_else(String::new, |r| format!(" (to {r})"));
    let edited = if m.edited.is_some() { " (edited)" } else { "" };
    let bad = if m.valid { "" } else { " (not delivered)" };
    format!("{} {} {}{reply}{edited}{bad}: {}", m.id, who(m.sender, m.name.as_ref()), m.time, shown(&m.body))
}

fn entry_line(json: bool, e: &Entry) -> String {
    let (s, t) = state(&e.body);
    let of = e.replaces.as_ref().map(|r| r.original);
    if json {
        return J::obj([
            ("id", J::str(e.id.to_string())),
            ("sender", J::tid(e.sender)),
            ("name", J::opt(e.name.clone().map(J::str))),
            ("time", J::int(e.time)),
            ("state", J::str(s)),
            ("text", J::str(t)),
            ("deleted_by", deleted_by(&e.body)),
            ("reply_to", opt_id(e.reply_to.as_ref())),
            ("replaces", opt_id(of.as_ref())),
            ("valid", J::Bool(e.valid)),
        ])
        .text();
    }
    let reply = e.reply_to.map_or_else(String::new, |r| format!(" (to {r})"));
    let what = of.map_or_else(String::new, |o| format!(" replaces {o}"));
    let bad = if e.valid { "" } else { " (invalid)" };
    format!("{} {} {}{reply}{what}{bad}: {}", e.id, who(e.sender, e.name.as_ref()), e.time, shown(&e.body))
}

fn find(ctx: &Ctx<'_>, c: Tid, i: &str) -> anyhow::Result<Message> {
    osis_chat::find(&ctx.db, c, &id(i)?)?.ok_or_else(|| exit(3, format!("no message {i}")))
}

/// Prints `s`, the first line out of the way of a reader of `cursor`.
fn print_since(ctx: &mut Ctx<'_>, s: &osis_chat::Since, from: Option<&Id>) -> anyhow::Result<()> {
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
            let peers = peer.iter().map(|h| h.parse()).collect::<Result<Vec<osis::Address>, _>>()?;
            let o = Options { name, purge, edit: edit.parse::<EditMode>()?, disappear: disappear.as_deref().map(parse_dur).transpose()?, retain_copies: !no_retain_copy, peers };
            let t = osis_chat::create(&db, &o)?;
            send_out(ctx, Some(t))?;
            ctx.emit(&[t.to_uri()], J::obj([("tid", J::tid(t))]))
        }
        ChatCmd::Add { chat, account, role } => {
            let t = ctx.tid(&chat)?;
            osis_chat::add(&db, t, ctx.tid(&account)?, parse_role(&role)?)?;
            send_out(ctx, Some(t))
        }
        ChatCmd::Link { chat, role, single_use } => {
            let t = ctx.tid(&chat)?;
            let l = osis_chat::link(&db, t, parse_role(&role)?, single_use)?;
            send_out(ctx, Some(t))?;
            ctx.emit(&[l.to_string()], J::obj([("link", J::str(l.to_string()))]))
        }
        ChatCmd::Join { link } => {
            let l: osis::ShareLink = ctx.arg_text(&link)?.parse()?;
            let t = crate::cmd::confirm(ctx, osis_chat::join(&db, &l))?;
            send_out(ctx, None)?;
            // a `read` through the daemon does not pull: the first messages are here when this ends
            if !db.has_store() {
                catch_up(ctx, t);
            }
            ctx.emit(&[t.to_uri()], J::obj([("tid", J::tid(t))]))
        }
        ChatCmd::Kick { chat, account, erase, retain_copy, purge } => {
            let (t, p) = (ctx.tid(&chat)?, ctx.tid(&account)?);
            let word = if erase {
                Some(false)
            } else if retain_copy {
                Some(true)
            } else {
                None
            };
            osis_chat::kick(&db, t, p, word)?;
            if purge {
                osis_chat::purge_participant(&db, t, p)?;
            }
            send_out(ctx, None)
        }
        ChatCmd::Post { chat, text, subject, from, reply_to } => {
            let t = ctx.tid(&chat)?;
            let body = ctx.arg_text(&text)?;
            let text = subject.map_or_else(|| body.clone(), |s| format!("{s}\n\n{body}"));
            let d = Draft { text, name: from, reply_to: reply_to.as_deref().map(id).transpose()? };
            let m = osis_chat::send(&db, t, &d)?;
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
            let sub = osis_chat::on_event(&db, t, move |_, e| {
                let line = match e {
                    Event::Entry(e) => entry_line(json, &e),
                    Event::Left(c) => if json { J::obj([("left", J::str(c.to_string()))]).text() } else { format!("left {c}") },
                    Event::Reread => if json { J::obj([("reread", J::Bool(true))]).text() } else { "reread".to_string() },
                    Event::Ended(m) => {
                        *why.lock().unwrap_or_else(|e| e.into_inner()) = Some(m);
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
            let t = ctx.tid(&chat)?;
            let m = find(ctx, t, &i)?;
            let new = osis_chat::resend(&db, t, &m)?;
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
            osis_chat::leave(&db, ctx.tid(&chat)?)?;
            send_out(ctx, None)
        }
        ChatCmd::Participants { chat } => {
            let t = ctx.tid(&chat)?;
            pull(ctx, t);
            let m = osis_chat::participants(&db, t)?;
            let links = osis_chat::links(&db, t)?;
            let s = osis_chat::settings(&db, t)?;
            // through an actor, or none: a joiner's `via` is its link's actor
            let ways = db.holders(t)?;
            let via = |p: Tid| ways.iter().find(|h| h.actor == p).and_then(|h| match h.through.as_slice() {
                [k] => Some(*k),
                _ => None,
            });
            let mut text: Vec<String> = m.iter().map(|(p, r)| format!("{} {r:?}{}", p.to_uri(), via(*p).map_or_else(String::new, |k| format!(" via {}", k.to_uri())))).collect();
            text.extend(links.iter().map(|(k, r)| format!("link {} {r:?}", k.to_uri())));
            let j = J::obj([
                ("name", J::str(s.name)),
                ("participants", J::Arr(m.iter().map(|(p, r)| J::obj([("account", J::tid(*p)), ("role", J::str(format!("{r:?}"))), ("via", J::opt(via(*p).map(J::tid)))])).collect())),
                ("links", J::Arr(links.iter().map(|(k, r)| J::obj([("link", J::tid(*k)), ("role", J::str(format!("{r:?}")))])).collect())),
            ]);
            ctx.emit(&text, j)
        }
        ChatCmd::Disappear { chat, after } => {
            let t = ctx.tid(&chat)?;
            let d = if after == "off" { None } else { Some(parse_dur(&after)?) };
            osis_chat::set_disappearing(&db, t, d)?;
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
    deliver(ctx, shared.map(|t| t.to_uri()))
}
