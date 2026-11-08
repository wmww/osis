//! Addenda (spec/permissions.md §5.2, Addenda): a writer's answer to an explicit demotion it
//! applied. For every node the demotion takes below write on a thing this node writes, it lists
//! that node's plain-content commits on the thing (and those acting for it) that it had received
//! before the demotion's `ts` and the demotion's frontier does not list, as one `addenda.0` entry
//! on the thing keyed by the demotion's commit ID; every writer does, the demoter's own node for
//! what its frontier left out. One addendum per thing, so none crosses a label.

use crate::engine::{Engine, Step, Tx, records};
use crate::error::Result;
use crate::events::{Diagnostic, DiagnosticKind};
use osis_base::{CommitId, Role, Tid, Value};
use osis_crdt::{Op, PathOp, PathSeg};
use osis_perm::Point;
use osis_schema::Codec;
use osis_schema::core_types as ct;
use osis_store::Shred;
use crate::engine::secrets::{holds_listed_keys, published_keys};
use std::collections::{BTreeMap, BTreeSet};

/// Whether a part on `ak` is plain content an addendum may list (spec/permissions.md §5.2,
/// Addenda): no role-class or admin-only aspect, no creation record; another addendum is one.
fn plain_ak(ak: &osis_base::Ak) -> bool {
    let s = ak.as_str();
    !ct::is_role_class(s) && !ak.admin_only() && s != "created.0"
}

/// Answers every explicit demotion applied here and not yet answered (`Indexes::addenda_due`)
/// with this node's addenda, in this transaction (so a witness lists what it still holds), each
/// once: an answered removal leaves the due set, and an addendum is a content commit, never a
/// removal to answer. A removal whose answer goes on a thing whose delete keys this node does not
/// hold yet stays due, answered whole by the first transaction that holds them (spec/permissions.md
/// §5.2, Addenda: "writes it once it can"). Each answer is one step (`Tx::step`): one that fails
/// leaves nothing, is reported (`DiagnosticKind::AddendaFailed`) and stays due, and the
/// transaction goes on.
pub(crate) fn answer_removals(tx: &mut Tx<'_>) -> Result<()> {
    if !tx.core.addenda_on {
        return Ok(());
    }
    let due: Vec<CommitId> = tx.core.ix.addenda_due.iter().copied().collect();
    let me = tx.core.id.tid();
    for r in due {
        if let Err(e) = tx.step(Step::Answer, |tx| answer_removal(tx, &r, me)) {
            let now = tx.now();
            tx.core.events.diagnostic(Diagnostic { kind: DiagnosticKind::AddendaFailed, tids: Vec::new(), commit: Some(r), peer: None, detail: e.to_string() }, now);
        }
    }
    Ok(())
}

/// Writes this node's addenda to removal `r` and takes it off the due set, unless it waits for
/// delete keys.
fn answer_removal(tx: &mut Tx<'_>, r: &CommitId, me: Tid) -> Result<()> {
    let Some(addenda) = answer(tx, r, me)? else { return Ok(()) };
    for (n, lists) in addenda {
        // a new entry of this delta's own (`put_new`): an addendum is the entries its delta
        // creates, whatever this node holds at the key (another writer's answer to `r`)
        let mut mu = crate::Mutation::new();
        mu.op(n, &ct::ADDENDA, PathOp { path: vec![PathSeg::Key(Value::bytes(&r.0))], op: Op::Put(ct::Frontier { commits: lists }.to_value()) })?;
        Engine::commit_tx(tx, mu)?;
    }
    tx.core.ix.addenda_due.remove(r);
    tx.txn.remove_local(&[records::ADDENDA_DUE, &r.0[..]].concat(), Shred::No)?;
    Ok(())
}

/// This node's addenda to removal `r`: per thing, what it lists (`answer_removals`). `None`: a
/// thing to answer on whose delete keys this node does not hold yet.
fn answer(tx: &mut Tx<'_>, r: &CommitId, me: Tid) -> Result<Option<BTreeMap<Tid, BTreeSet<CommitId>>>> {
    let r = *r;
    let mut out: BTreeMap<Tid, BTreeSet<CommitId>> = BTreeMap::new();
    let Some(m) = tx.core.ix.commits.get(&r) else { return Ok(Some(out)) };
    let Some(frontier) = m.view.frontier.clone() else { return Ok(Some(out)) };
    let point = Point { ts: m.view.ts, node: m.view.author, commit: r };
    let wall = m.view.ts.wall_ms().0;
    let targets: BTreeSet<Tid> = m.view.aspects.iter().filter(|a| crate::apply::validity::edge_ak(a.ak.as_str())).map(|a| a.tid).collect();
    let mut demoted: BTreeSet<(Tid, Tid)> = BTreeSet::new();
    for t in &targets {
        if let Some(tl) = tx.core.timelines.get(t) {
            demoted.extend(tl.demoted_below_write(&r));
        }
    }
    for (x, n) in demoted {
        if x == me || tx.core.role_now(&me, &n) < Some(Role::Write) {
            continue;
        }
        let core = &*tx.core;
        let cands = core.ix.by_thing.get(&(n, x)).into_iter().flatten().chain(core.ix.by_actor.get(&(n, x)).into_iter().flatten());
        for c in cands {
            let Some(cm) = core.ix.commits.get(c) else { continue };
            let v = &cm.view;
            // rule 4: plain content only (no role commit, no snapshot); rule 2: received by the demotion's `ts`, ordered
            // before it; what the frontier lists needs no witness
            if v.memory || v.purges || v.kind != osis_commit::Kind::Content || frontier.covers(c) || cm.received.0 > wall || (Point { ts: v.ts, node: v.author, commit: *c }) >= point {
                continue;
            }
            // a part on n (an acting commit's part on n is its Acting check), rule 3: what this
            // node could write itself on n
            if !v.aspects.iter().any(|a| plain_ak(&a.ak) && (a.tid == n || v.actor == n)) {
                continue;
            }
            out.entry(n).or_default().insert(*c);
        }
    }
    for n in out.keys() {
        let created = Default::default();
        let published = published_keys(tx, &created, [*n])?;
        if !holds_listed_keys(tx.core, &created, &published, n) {
            return Ok(None);
        }
    }
    Ok(Some(out))
}
