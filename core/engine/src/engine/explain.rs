//! Debug-build diagnostics for tests (notes/test-harnesses.md, Why kept and row dumps): why a
//! thing is still held (`Engine::why_kept`, read from the retention rule's own needs) and a
//! row-level dump of the store's local rows (`Engine::rows`), and the node's role on a thing and
//! its secrets (`Engine::why_role`, read from `tickets::role_on` and `rotation::lost`'s clauses).

use super::testing::family;
use super::{Core, Engine};
use crate::error::Result;
use crate::retention::needed::{self, Need, Root};
use crate::sync::units::Ctx;
use osis_base::{CommitId, Role, Tid};
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fmt::Write;

/// One store row as `Engine::rows` describes it.
#[doc(hidden)]
#[derive(Clone, Debug)]
pub struct Row {
    /// Its family: the key up to its first `/`, else 3 bytes (as `Engine::local_census`).
    pub family: String,
    /// The key decoded: past the family, known tids as `t:<tid>`, held commit IDs as `c:<hex>`,
    /// printable runs as text, other bytes as hex.
    pub key: String,
    /// The tids the key names, directly or by a held commit it names (that commit's things).
    pub tids: BTreeSet<Tid>,
    /// Key plus value bytes.
    pub bytes: usize,
    /// The raw key.
    pub raw: Vec<u8>,
}

/// `t` with what it is to this node, if anything.
fn label(core: &Core, t: &Tid) -> String {
    let what = if core.node_root == Some(*t) {
        " (node root)"
    } else if core.account_and_root().is_some_and(|(_, d)| d == *t) {
        " (account root)"
    } else if core.account.get() == Some(*t) {
        " (account)"
    } else if core.is_account(t) {
        " (an account)"
    } else if core.is_key_actor(t) {
        " (a key actor)"
    } else {
        ""
    };
    format!("{t}{what}")
}

fn short(c: &CommitId) -> String {
    c.0.iter().take(6).map(|b| format!("{b:02x}")).collect()
}

fn ctx(c: &Ctx) -> String {
    match c {
        Ctx::Local => "local".into(),
        Ctx::Read(t) => format!("read {t}"),
        Ctx::Unread(t) => format!("unread {t}"),
        Ctx::Ticket(t) => format!("ticket {t}"),
    }
}

/// The node closure's path to `t`, one strong per step with the context it is taken in.
fn path(core: &Core, t: &Tid) -> String {
    let Some(p) = core.ix.closure.path(t) else { return "no path".into() };
    let mut out = String::new();
    for (i, (c, x)) in p.iter().enumerate() {
        match i {
            0 => out.push_str(&label(core, x)),
            _ => {
                let _ = write!(out, " -[{}]-> {}", ctx(c), label(core, x));
            }
        }
    }
    out
}

fn root(core: &Core, x: &Tid, r: &Root) -> String {
    match r {
        Root::Held if core.ix.closure.holds(x) => format!("in the node closure: {}", path(core, x)),
        Root::Held => "leaving the node closure, not released yet".into(),
        Root::Copy(a) if a == x => "a retained copy".into(),
        Root::Copy(a) => format!("the retained copy of {}", label(core, a)),
        Root::SelfRemoval(c) => format!("an own self-removal from it (c:{}) waits to be sealed", short(c)),
        Root::Awaited => "a pending part awaits its record or its entry into the node closure".into(),
    }
}

fn need(core: &Core, x: &Tid, n: &Need) -> String {
    let x = label(core, x);
    match n {
        Need::Holder => format!("{x} has a held edge write naming it holder"),
        Need::Pending(c) => format!("pending commit c:{} on {x} is signed by it or awaits its record", short(c)),
        Need::Acting(c) => format!("held commit c:{} on {x} acts as it", short(c)),
        Need::Missing(c) => format!("held commit c:{} on it has a part missing on {x}", short(c)),
        Need::Holding => format!("an edge write on it names {x} holder"),
        Need::Strong(ak) => format!("{x}'s {ak} holds a strong to it"),
        Need::Inbox => format!("account {x}'s keys.0 names it (its inbox)"),
    }
}

/// What is held of `t` (`needed::holds_any`'s parts).
fn held_of(core: &Core, t: &Tid) -> String {
    let mut out = vec![if core.created(t).is_some() { "record".to_owned() } else { "no record".to_owned() }];
    let on: Vec<String> = core.on_thing(t).map(|c| format!("c:{}", short(&c))).collect();
    match on.len() {
        0 => {}
        n @ 1..=6 => out.push(format!("{n} commits on it {}", on.join(" "))),
        n => out.push(format!("{n} commits on it {} ...", on.get(..6).unwrap_or_default().join(" "))),
    }
    if core.ix.secrets.get(t).is_some() {
        out.push("secrets".into());
    }
    if crate::apply::awaited(core, t) {
        out.push("a pending part awaits its record or its entry".into());
    }
    out.join(", ")
}


/// The identities whose roles are the node's (`rotation::role_here`): its account, itself, its
/// held key actors, each named.
fn ours(core: &Core) -> Vec<(Tid, &'static str)> {
    let mut out: Vec<(Tid, &'static str)> = core.member().map(|m| (m, "account")).into_iter().collect();
    out.push((core.id.tid(), "node"));
    out.extend(core.key_actors.keys().map(|k| (*k, "key actor")));
    out
}

/// The widest paths into `t` over the timelines' current edges (each thing's roster now, its
/// record edge included; with no timeline, its mint admin), as `View::roles_to` walks them for
/// `role_now`: per holder reached, its role and the next step toward `t`.
fn widest_to(core: &Core, t: &Tid) -> BTreeMap<Tid, (Role, Option<Tid>)> {
    let at = osis_perm::At::now(crate::flows::now_ts(core));
    let mut best: BTreeMap<Tid, (Role, Option<Tid>)> = BTreeMap::from([(*t, (Role::Admin, None))]);
    let mut stack = vec![*t];
    while let Some(x) = stack.pop() {
        let Some(&(level, _)) = best.get(&x) else { continue };
        let holders: Vec<(Tid, Role)> = match core.timelines().on(&x) {
            Some(on) => on.roster(at).into_iter().map(|(m, e)| (m, e.role)).collect(),
            None => core.mint_admin(&x).map(|a| (a, Role::Admin)).into_iter().collect(),
        };
        for (h, r) in holders {
            let v = level.min(r);
            if best.get(&h).is_none_or(|(b, _)| v > *b) {
                best.insert(h, (v, Some(x)));
                stack.push(h);
            }
        }
    }
    best
}

/// One edge of a path: holder `h` on `x`, by the role commit in force or its record edge.
fn edge(core: &Core, h: &Tid, x: &Tid) -> String {
    let on = core.timelines().on(x);
    let r = match &on {
        Some(o) => o.roster(osis_perm::At::now(crate::flows::now_ts(core))).get(h).map(|e| format!("{:?}{}", e.role, e.until.map_or(String::new(), |u| format!(" until {}", u.0)))),
        None => Some("Admin".into()),
    };
    let by = match on.as_ref().and_then(|o| o.in_force(h)) {
        Some(c) => format!("c:{}", short(&c)),
        None if core.mint_admin(x) == Some(*h) => "record edge".into(),
        None => "no edge write in force".into(),
    };
    format!("-[{} {by}]->", r.unwrap_or_else(|| "?".into()))
}

/// `why_role`'s lines for `t`.
fn role_lines(tx: &mut crate::engine::Tx<'_>, t: &Tid, out: &mut String) -> Result<()> {
    let core = &*tx.core;
    let role = crate::sync::tickets::role_on(core, t);
    let commits = crate::rotation::role_here(core, t);
    let _ = write!(out, "{}: role {role:?} (role commits {commits:?})", label(core, t));
    if let Some(h) = core.root_holders(t) {
        let _ = write!(out, "\n  an account root: roster {}", h.iter().map(|(m, r)| format!("{}={r:?}", label(core, m))).collect::<Vec<_>>().join(", "));
    }
    let paths = widest_to(core, t);
    for (id, what) in ours(core) {
        let (now, keyed) = (core.role_now(&id, t), core.keyed_role_now(&id, t));
        if now.is_none() && keyed.is_none() && !paths.contains_key(&id) {
            continue;
        }
        let _ = write!(out, "\n  as {what} {}: role {now:?}{}", label(core, &id), if keyed != now { format!(", {keyed:?} with key access (a keyless grant on the way)") } else { String::new() });
        if id == *t {
            out.push_str(" (it is the thing)");
            continue;
        }
        let Some((r, _)) = paths.get(&id) else {
            out.push_str("; no current path");
            continue;
        };
        let mut steps = vec![label(core, &id)];
        let mut x = id;
        let mut n = 0;
        while let Some((_, Some(next))) = paths.get(&x) {
            steps.push(edge(core, &x, next));
            steps.push(label(core, next));
            x = *next;
            n += 1;
        }
        let kind = match (what, n) {
            ("account", 1) => "account, direct",
            ("account", _) => "account, chain",
            (_, 1) => "direct",
            _ => "chain",
        };
        let _ = write!(out, "; {kind} path at {r:?}: {}", steps.join(" "));
    }
    // the ticket's word (`tickets::words_on`, what `role_on` reads): only while a held strong
    // reaches `t` with a ticket opening here, and a read word only while no held role commit
    // reaches its holder
    let accepted = core.ix.closure.accepted(t);
    let all = core.ix.closure.ticket_words(t);
    if accepted || !all.is_empty() {
        let _ = write!(out, "\n  tickets: accepted (a held strong reaches it, a ticket opens) {accepted}");
        let counted = crate::sync::tickets::words_on(core, t);
        for (h, r) in &all {
            let why = match counted.iter().find(|(w, _)| *w == (*h, *r)) {
                None => "does not count: not accepted",
                Some((_, true)) if *r == Role::Sync => "counts: a sync word",
                Some((_, true)) => "counts: no held role commit reaches its holder",
                Some((_, false)) => "does not count: a held role commit reaches its holder, the role commits decide",
            };
            let _ = write!(out, "\n    word {r:?} boxed to {}: {why}", label(core, h));
        }
    }
    Ok(())
}

/// `why_role`'s kept-copy line for `t` (`retention::forget`'s retain decision): whether it is
/// held as a kept copy and of which actor, whether a held path reads it (which keeps it whole
/// instead), and the kept marks (`Core::ix.kept`) on `t` and on the actor its secrets derive
/// from, each with the holders it hangs on.
fn kept_lines(core: &Core, t: &Tid, out: &mut String) {
    let copy = match crate::retention::forget::copy_of(core, t) {
        Some(a) => format!("yes, of {}", label(core, &a)),
        None => "no".into(),
    };
    let on: BTreeSet<Tid> = [Some(*t), core.secret_actor(t)].into_iter().flatten().collect();
    let marks: Vec<String> = on.iter().filter_map(|x| core.ix.kept.get(x).map(|hs| format!("{} on {}", label(core, x), hs.iter().map(|h| label(core, h)).collect::<Vec<_>>().join(", ")))).collect();
    let marks = if marks.is_empty() { "none".to_owned() } else { marks.join("; ") };
    let _ = write!(out, "\n  kept copy: {copy} (a held path reads it: {}); kept marks: {marks} ({} in all)", crate::retention::forget::read_path(core, t), core.ix.kept.len());
}

impl Engine {
    /// Debug builds: what node-held commit `c` is, for naming a trace's `C..`: its kind, its
    /// signer and the thing it acts for (`View::purge_author`), each thing and aspect it writes
    /// with that part's validity and hold here, and its rotation, re-seal, undo or expiry if any.
    /// `None` when this node holds no record of it.
    #[doc(hidden)]
    pub fn describe_commit(&self, c: &CommitId) -> Option<String> {
        let core = &self.core;
        let m = core.ix.commits.get(c)?;
        let v = &m.view;
        let mut out = format!("c:{} {:?} by {} as {}", short(c), v.kind, label(core, &v.signer), label(core, &v.purge_author));
        let parts: Vec<String> = v.aspects.iter().enumerate().map(|(ai, a)| {
            let valid = if m.valid_at(ai) { "" } else { " invalid" };
            let hold = m.hold(ai).map_or("no hold".to_owned(), |h| format!("{h:?}"));
            format!("{} {}{valid} {hold}", label(core, &a.tid), a.ak)
        }).collect();
        let _ = write!(out, " on [{}]", parts.join(", "));
        if let Some(h) = osis_base::costs::paused(|| m.header.decoded()) {
            if h.rotation.is_some() {
                out.push_str(", a rotation");
            }
            if h.reseal.is_some() {
                out.push_str(", a seed re-seal");
            }
            if let Some(u) = &h.undoes {
                let _ = write!(out, ", undoes c:{}", short(u));
            }
            if let Some(x) = h.expires {
                let _ = write!(out, ", expires {x}");
            }
        }
        if v.memory {
            out.push_str(", a memory commit");
        }
        Some(out)
    }

    /// Debug builds: why `t` is still held, from the retention rule's own needs
    /// (`retention::needed::search`): rooted (in the node closure, by its path of strongs from
    /// the node root and their contexts, or otherwise), the chain of needs to the first rooted
    /// thing, or that nothing rooted needs it and it goes at the next pass end.
    #[doc(hidden)]
    pub fn why_kept(&mut self, t: &Tid) -> String {
        let t = *t;
        let r = osis_base::costs::paused(|| {
            osis_base::memo::unrecorded(|| {
                self.read(|tx| {
                    let core = &*tx.core;
                    let name = format!("{} [{}]", label(core, &t), held_of(core, &t));
                    if !needed::holds_any(core, &t) {
                        return Ok(format!("{name}: nothing of it is held"));
                    }
                    let mut reached = needed::Reached::new();
                    let Some((r, why)) = needed::search(tx, &t, &mut reached)? else {
                        let core = &*tx.core;
                        let others: Vec<String> = reached.keys().filter(|x| **x != t).map(|x| label(core, x)).collect();
                        return Ok(format!("{name}: nothing rooted needs it: goes when next judged (a pass end or a lost need){}", if others.is_empty() { String::new() } else { format!(" (with {})", others.join(", ")) }));
                    };
                    let core = &*tx.core;
                    let mut chain = vec![];
                    let mut x = r;
                    while let Some(Some((y, n))) = reached.get(&x) {
                        chain.push(format!("{} is needed: {}", label(core, y), need(core, &x, n)));
                        x = *y;
                    }
                    chain.reverse();
                    let mut out = format!("{name}:");
                    for l in chain {
                        let _ = write!(out, "\n  {l}");
                    }
                    let _ = write!(out, "\n  {} is rooted: {}", label(core, &r), root(core, &r, &why));
                    Ok(out)
                })
            })
        });
        r.unwrap_or_else(|e| format!("{t}: why_kept failed: {e:?}"))
    }

    /// Debug builds: the node's role on `t` and its secrets, read from the rule's own code
    /// (notes/test-harnesses.md, Why kept and row dumps): the role `tickets::role_on` gives and
    /// the role commits' (`rotation::role_here`); per identity of the node (account, itself, key
    /// actors) its role and the widest current path to `t` (direct, chain, account),
    /// each edge by the role commit in force or the record edge; each held ticket's word and why
    /// it counts or not; the secrets held of the actor `t`'s derive from, with that actor's role
    /// when it is another, and `lost_due`'s clauses (without its side effects).
    #[doc(hidden)]
    pub fn why_role(&mut self, t: &Tid) -> String {
        let t = *t;
        let r = osis_base::costs::paused(|| {
            osis_base::memo::unrecorded(|| {
                self.read(|tx| {
                    let mut out = String::new();
                    role_lines(tx, &t, &mut out)?;
                    let a = tx.core.secret_actor(&t).unwrap_or(t);
                    if a != t {
                        let _ = write!(out, "\n  secrets derive from {}; its role:\n  ", label(tx.core, &a));
                        let mut sub = String::new();
                        role_lines(tx, &a, &mut sub)?;
                        out.push_str(&sub.replace('\n', "\n  "));
                    }
                    let due = crate::rotation::explain_due(tx, &a)?;
                    let _ = write!(out, "\n  lost access ({}): {due}", label(tx.core, &a));
                    let cl = &tx.core.ix.closure;
                    let _ = write!(out, "\n  node closure: contexts {:?}, left {:?}, reads {}, content held {}", cl.contexts(&t), cl.left().get(&t), cl.reads(&t), crate::retention::needed::holds_content(tx.core, &t));
                    kept_lines(tx.core, &t, &mut out);
                    Ok(out)
                })
            })
        });
        r.unwrap_or_else(|e| format!("{t}: why_role failed: {e:?}"))
    }

    /// Debug builds: the store's local rows whose family starts with `prefix` and, with `tid`,
    /// that name it (`Row::tids`), each described (`describe_rows`).
    #[doc(hidden)]
    pub fn rows(&mut self, prefix: &[u8], tid: Option<&Tid>) -> Result<Vec<Row>> {
        let rows = osis_base::costs::paused(|| self.read(|tx| Ok(tx.txn.scan_local(b"", b"", usize::MAX)?)))?;
        Ok(self.describe_rows(rows, prefix, tid))
    }

    /// Debug builds: `rows` (any store's local rows, e.g. node sync's) described as `Row`s, by the
    /// tids and commits this engine knows, kept where the family starts with `prefix` and, with
    /// `tid`, the row names it.
    #[doc(hidden)]
    pub fn describe_rows(&self, rows: Vec<(Vec<u8>, Vec<u8>)>, prefix: &[u8], tid: Option<&Tid>) -> Vec<Row> {
        let ix = &self.core.ix;
        let mut known: BTreeSet<Tid> = ix.commits.values().flat_map(|m| m.view.aspects.iter().map(|a| a.tid)).collect();
        known.extend(ix.closure.things().copied().chain(ix.closure.left().keys().copied()).chain(ix.held.things().copied()).chain(ix.secrets.keys().copied()).chain(ix.kept.keys().copied()));
        known.extend(self.core.node_root.into_iter().chain(self.core.account_and_root().into_iter().flat_map(|(a, d)| [a, d])));
        let mut out = Vec::new();
        for (k, v) in rows {
            let fam = family(&k);
            if !fam.starts_with(prefix) {
                continue;
            }
            let rest = k.get(fam.len()..).unwrap_or_default();
            let (mut key, mut tids, mut i, mut run) = (String::new(), BTreeSet::new(), 0, Vec::new());
            let flush = |key: &mut String, run: &mut Vec<u8>| {
                if run.is_empty() {
                    return;
                }
                match run.iter().all(|b| b.is_ascii_graphic() || *b == b' ') && run.len() >= 2 {
                    true => key.push_str(&String::from_utf8_lossy(run)),
                    false => key.extend(run.iter().map(|b| format!("{b:02x}"))),
                }
                key.push(' ');
                run.clear();
            };
            while i < rest.len() {
                let c = rest.get(i..i + 32).and_then(|b| <[u8; 32]>::try_from(b).ok()).map(CommitId).filter(|c| ix.commits.contains_key(c));
                if let Some(c) = c {
                    flush(&mut key, &mut run);
                    let _ = write!(key, "c:{} ", short(&c));
                    tids.extend(ix.commits.get(&c).into_iter().flat_map(|m| m.view.aspects.iter().map(|a| a.tid)));
                    i += 32;
                    continue;
                }
                let t = rest.get(i..i + 15).and_then(|b| <[u8; 15]>::try_from(b).ok()).map(Tid::from_bytes).filter(|t| known.contains(t));
                if let Some(t) = t {
                    flush(&mut key, &mut run);
                    let _ = write!(key, "t:{t} ");
                    tids.insert(t);
                    i += 15;
                    continue;
                }
                run.extend(rest.get(i).copied());
                i += 1;
            }
            flush(&mut key, &mut run);
            if tid.is_some_and(|t| !tids.contains(t)) {
                continue;
            }
            out.push(Row { family: String::from_utf8_lossy(fam).into_owned(), key: key.trim_end().to_owned(), tids, bytes: k.len() + v.len(), raw: k });
        }
        out
    }
}
