//! `osis chat`: chats over plain osis calls on schema/chat.osis, with osis-chat's creation, edit
//! and arrival rules (notes/chat.md).

use crate::args::ChatCmd;
use crate::Ctx;
use crate::cmd::{deliver, parse_role};
use crate::json::J;
use crate::{exit, parse_dur, usage};
use osis::core::RETENTION;
use osis::{Body, Commit, CommitEvent, CommitFrom, CommitId, CommitKind, CommitQuery, GrantOpts, HolderKind, LinkOpts, Osis, PurgeBy, ReadOnly, Role, SetRoleOpts, Tid};
use osis_chat::schema::{self, EditMode, MSG, SETTINGS};
use osis_chat::{Cursor, Options};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, mpsc};

fn id(s: &str) -> anyhow::Result<CommitId> {
    Ok(s.parse::<CommitId>()?)
}

fn opt_str(s: Option<String>) -> J {
    J::opt(s.map(J::str))
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

/// The earlier versions of an edited message whose text is here, newest first: the chat keeps
/// edit history, or another node's edit has not purged it here yet.
fn earlier(db: &ReadOnly, c: Tid, k: &Commit, newest: osis::CommitPos) -> anyhow::Result<Vec<String>> {
    let (mut out, mut from) = (Vec::new(), CommitFrom::Newest);
    loop {
        let p = db.at(c, MSG).versions(k.stamp.id, &CommitQuery { from, kinds: vec![CommitKind::Content], ..Default::default() })?;
        out.extend(p.commits.iter().filter(|v| v.pos() != newest).filter_map(|v| match v.at(c, MSG)?.body {
            Body::Held(Some(m)) => Some(m.text),
            _ => None,
        }));
        match p.commits.last() {
            Some(l) if p.more => from = CommitFrom::Before(l.pos()),
            _ => return Ok(out),
        }
    }
}

/// One message as `fired` lists it (under its id, its newest text): a line of `read` and of
/// `watch` alike. `None`: no message there.
fn message_line(db: &ReadOnly, c: Tid, json: bool, k: &Commit) -> anyhow::Result<Option<String>> {
    let Some(part) = k.at(c, MSG).filter(|_| k.kind == CommitKind::Content) else { return Ok(None) };
    let (s, t) = state(&part.body);
    let (name, reply_to) = match &part.body {
        Body::Held(Some(m)) => (m.name.clone(), m.reply()),
        _ => (None, None),
    };
    let earlier = match part.edited {
        Some(newest) => earlier(db, c, k, newest)?,
        None => Vec::new(),
    };
    let (sender, time) = (k.stamp.actor, k.stamp.shown().0);
    if json {
        return Ok(Some(
            J::obj([
                ("id", J::str(k.stamp.id.to_string())),
                ("sender", J::tid(sender)),
                ("name", opt_str(name)),
                ("time", J::int(time)),
                ("state", J::str(s)),
                ("text", J::str(t)),
                ("deleted_by", deleted_by(&part.body)),
                ("reply_to", opt_str(reply_to.map(|r| r.to_string()))),
                ("edited", J::Bool(part.edited.is_some())),
                ("earlier", J::Arr(earlier.into_iter().map(J::str).collect())),
                ("valid", J::Bool(part.valid)),
            ])
            .text(),
        ));
    }
    let reply = reply_to.map_or_else(String::new, |r| format!(" (to {r})"));
    let edited = if part.edited.is_some() { " (edited)" } else { "" };
    let bad = if part.valid { "" } else { " (not delivered)" };
    Ok(Some(format!("{} {} {time}{reply}{edited}{bad}: {}", k.stamp.id, who(sender, name.as_ref()), shown(&part.body))))
}

/// Message `i` of chat `c`, as listed here.
fn find(ctx: &Ctx<'_>, c: Tid, i: &str) -> anyhow::Result<Commit> {
    ctx.db.at(c, MSG).commit(id(i)?)?.ok_or_else(|| exit(3, format!("no message {i}")))
}

/// Prints `messages`, then the cursor line: the first line out of the way of a reader of it.
fn print_since(ctx: &mut Ctx<'_>, t: Tid, s: &osis_chat::Since, from: Option<&Cursor>) -> anyhow::Result<()> {
    let json = ctx.g.json;
    for k in &s.messages {
        if let Some(l) = message_line(&ctx.db, t, json, k)? {
            ctx.line(&l)?;
        }
    }
    let cursor = s.cursor.as_ref().or(from);
    if json {
        ctx.line(&J::obj([("cursor", opt_str(cursor.map(Cursor::to_string))), ("more", J::Bool(s.more)), ("complete", J::Bool(s.complete))]).text())
    } else if let Some(c) = cursor {
        ctx.line(&format!("cursor {c}"))
    } else {
        Ok(())
    }
}

/// Fires `m` on chat `c`: its id.
fn fire(db: &Osis, c: Tid, m: &schema::Message) -> anyhow::Result<CommitId> {
    Ok(osis_chat::send(db, c, m)?)
}

pub(crate) fn run(ctx: &mut Ctx<'_>, c: ChatCmd) -> anyhow::Result<()> {
    let db = ctx.db.clone();
    match c {
        ChatCmd::Create { name, purge, edit, disappear, no_retain_copy, peer } => {
            let purge = match purge.as_str() {
                "author-or-admin" => PurgeBy::AuthorOrAdmin,
                "admin" => PurgeBy::Admin,
                "writer" => PurgeBy::Writer,
                x => return Err(usage(format!("--purge: author-or-admin, admin or writer, not {x:?}"))),
            };
            let edit = match edit.as_str() {
                "purge" => Some(EditMode::Purge),
                "keep" => Some(EditMode::Keep),
                "off" => None,
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
            let m = fire(&db, t, &schema::Message { text, name: from, reply_to })?;
            send_out(ctx, None)?;
            ctx.emit(&[m.to_string()], J::obj([("id", J::str(m.to_string()))]))
        }
        ChatCmd::Read { chat, max, before, after } => {
            let t = ctx.tid(&chat)?;
            pull(ctx, t);
            if let Some(a) = after {
                let a: Cursor = a.parse()?;
                let s = osis_chat::since(&db, t, Some(&a), max)?;
                return print_since(ctx, t, &s, Some(&a));
            }
            let mut from = match before {
                Some(b) => CommitFrom::Before(find(ctx, t, &b)?.pos()),
                None => CommitFrom::Newest,
            };
            let (mut got, mut more, mut complete) = (Vec::new(), true, true);
            while got.len() < max && more {
                let p = db.at(t, MSG).fired(&CommitQuery { from, limit: Some(max - got.len()), kinds: vec![CommitKind::Content], ..Default::default() })?;
                (more, complete) = (p.more, complete && p.complete);
                let Some(last) = p.commits.last().map(Commit::pos) else { break };
                from = CommitFrom::Before(last);
                got.extend(p.commits);
            }
            // the cursor to go on from is the last arrived entry, whatever the page shows
            let cursor = osis_chat::cursor(&db, t)?;
            got.reverse();
            print_since(ctx, t, &osis_chat::Since { messages: got, cursor, more, complete }, None)
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
                    CommitEvent::Commit { commit: Some(k), .. } => match message_line(db, t, json, &k) {
                        Ok(Some(l)) => l,
                        Ok(None) => return,
                        Err(e) => if json { J::obj([("error", J::str(e.to_string()))]).text() } else { format!("error {e}") },
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
                let mut at: Cursor = a.parse()?;
                loop {
                    let s = osis_chat::since(&db, t, Some(&at), crate::args::PAGE)?;
                    for k in &s.messages {
                        if let Some(l) = message_line(&db, t, json, k)? {
                            let _ = wake.send(l);
                        }
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
            let m = id(&i)?;
            osis_chat::edit(&db, t, m, &text)?;
            send_out(ctx, None)?;
            ctx.emit(&[m.to_string()], J::obj([("id", J::str(m.to_string()))]))
        }
        ChatCmd::Resend { chat, id: i } => {
            // one's own message turned invalid (`OwnWriteInvalid`), its text, name and reply as a
            // new message; the old one stays, to this account alone
            let t = ctx.tid(&chat)?;
            let k = find(ctx, t, &i)?;
            let Some(part) = k.at(t, MSG) else { return Err(exit(3, format!("no message {i}"))) };
            let Body::Held(Some(body)) = part.body else { return Err(exit(1, "its text is not here")) };
            if part.valid || k.stamp.actor != db.me() {
                return Err(exit(1, "only one's own undelivered message is sent again"));
            }
            let new = fire(&db, t, &body)?;
            send_out(ctx, None)?;
            ctx.emit(&[new.to_string()], J::obj([("id", J::str(new.to_string()))]))
        }
        ChatCmd::Delete { chat, id: i } => {
            // the message and every version of it here
            let t = ctx.tid(&chat)?;
            let k = find(ctx, t, &i)?;
            let mut w = db.write();
            w.at(t, MSG).purge(osis::Purge::Commit(k.stamp.id))?;
            w.commit()?;
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
            let mut rules = db.at(t, RETENTION).get()?.unwrap_or_default();
            rules.rules.get_mut(&MSG.name()).ok_or_else(|| exit(3, format!("{chat} has no message rule: not a chat")))?.expires = d;
            let mut w = db.write();
            w.at(t, RETENTION).set(&rules)?;
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
