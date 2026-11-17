//! Debug-build diagnostics for tests (notes/test-harnesses.md, Why kept and row dumps): why a
//! thing is still held (`Engine::why_kept`, read from the retention rule's own needs) and a
//! row-level dump of the store's local rows (`Engine::rows`).

use super::testing::family;
use super::{Core, Engine};
use crate::error::Result;
use crate::retention::needed::{self, Need, Root};
use crate::sync::units::Ctx;
use osis_base::{CommitId, Tid};
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
        Root::Closure => format!("in the node closure: {}", path(core, x)),
        Root::Leaving => "leaving the node closure, not released yet".into(),
        Root::Kept => "a kept copy".into(),
        Root::CopyOf(a) => format!("the kept copy of {}", label(core, a)),
        Root::KeyActor => "a key actor that is no account".into(),
        Root::FollowedLink => "the K of a followed link".into(),
        Root::HeldKeyActor(h) => format!("key actor {} held here is named holder on it", label(core, h)),
        Root::SelfRemoval(c) => format!("an own self-removal from it (c:{}) waits to be sealed", short(c)),
    }
}

fn need(core: &Core, x: &Tid, n: &Need) -> String {
    let x = label(core, x);
    match n {
        Need::Holder => format!("{x} has a held edge write naming it holder"),
        Need::Signed(c) => format!("held commit c:{} on {x} is signed (authored or acted in) by it", short(c)),
        Need::Pending(c) => format!("pending commit c:{} on {x} is signed by it or awaits its record", short(c)),
        Need::Missing(c) => format!("held commit c:{} on it has a part missing on {x}", short(c)),
        Need::Holding => format!("an edge write on it names {x} holder"),
        Need::Strong(ak) => format!("{x}'s {ak} holds a strong to it"),
        Need::Inbox => format!("account {x}'s keys.0 names it (its inbox)"),
        Need::Profile => format!("it is account {x}'s profile"),
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
    if core.ix.pend_on.contains_key(&crate::apply::Wake::Record(*t)) {
        out.push("a pending commit awaits its record".into());
    }
    out.join(", ")
}

impl Engine {
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
