//! Forgetting a commit (memory: expired, superseded, covered; durable: covered, purged or invalid,
//! `Engine::forgettable`): `unindex_commit`, the mirror of
//! what applying a commit indexes (`tests::forget_equals_never_indexed`).

use crate::engine::records;
use crate::engine::Tx;
use crate::error::Result;
use osis_base::{CommitId, Tid};
use osis_store::Shred;
use std::collections::BTreeSet;

/// Removes commit `id` from every index applying it added to and its records from the store:
/// the mirror of `index_commit` and the rest of `apply_verified`.
pub(crate) fn unindex_commit(tx: &mut Tx<'_>, id: &CommitId) -> Result<()> {
    unindex(tx, id, true)?;
    tx.core.update_timelines();
    Ok(())
}

/// `unindex_commit` of a commit forgotten as never received (`retention::forget`: its thing
/// released or unreadable here): nothing of it stays as a cover, a name or a forgotten mark; the
/// rows of its blobs as this node opened or sealed them (`sync::bodies`) stay with the blobs, which
/// the sync store may keep (an own entry, opened again once the thing reads again); a release
/// drops them, and the store's own entries of them (`sync::bodies::forget`). The caller gives
/// the timelines the held set's change (`Core::update_timelines`) once it has forgotten all it
/// forgets: each update re-walks the components touched.
pub(crate) fn unindex_unreceived(tx: &mut Tx<'_>, id: &CommitId) -> Result<()> {
    // every thing it writes on had something forgotten (a part waiting on one outside the node
    // closure goes with it): a strong reaching it later pulls anew (`Core::brought`)
    if let Some(m) = tx.core.ix.commits.get(id) {
        for a in &m.header.aspects {
            tx.core.brought.remove(&a.tid);
        }
    }
    // never received, nothing keeps it out: fetched again where present once needed
    let blobs: Vec<osis_base::BlobId> = tx.core.ix.commit_blobs.get(id).into_iter().flatten().copied().collect();
    for b in blobs {
        tx.blobs.unreceived(&b);
    }
    unindex(tx, id, false)
}

/// `marks`: forgotten as covered, purged, spent or invalid, so it leaves its marks and its
/// blobs' rows go; else as never received.
fn unindex(tx: &mut Tx<'_>, id: &CommitId, marks: bool) -> Result<()> {
    // the indexes change
    tx.core.touch();
    // its bodies leave with the record
    let held: Vec<usize> = tx.core.ix.commits.get(id).map(|m| (0..m.view.aspects.len()).filter(|ai| m.holds(*ai) && !m.stripped(*ai)).collect()).unwrap_or_default();
    tx.pin_states(id, &held)?;
    // what it dropped under stays its covers while something names it
    if marks {
        crate::retention::handed::note(tx, id)?;
    }
    // the holders its `roles.0` entries keyed
    super::validity::unkey_holders(tx, id, &|_| true)?;
    // a role commit's `secrets.0` bodies: what they noted (`boxes_to`) goes with them, re-derived
    // from the bodies still held, as a drop re-derives it (`keys::forget_dropped`)
    let mut boxes: Vec<(usize, Vec<osis_crdt::Fragment>)> = Vec::new();
    if let Some(m) = tx.core.ix.commits.get(id).filter(|m| m.view.kind.is_role()).cloned() {
        for ai in (0..m.view.aspects.len()).filter(|ai| m.holds(*ai) && m.view.aspects.get(*ai).is_some_and(|a| a.ak.as_str() == "secrets.0")) {
            boxes.push((ai, super::held_fragment(tx, id, ai)?.into_iter().collect()));
        }
    }
    // what sync's facade kept of it: section epochs, blob parts
    if marks {
        crate::sync::bodies::forget(tx, id)?;
    }
    tx.core.redeliver.remove(id);
    // its blob waits (an applied memory commit's trees)
    tx.core.walks.drop_all(id);
    // a fire carries nothing once forgotten (spec/commits.md §4 Pending storage)
    super::carriers::fire_gone(tx, id)?;
    // a memory commit's held parts go with it: what they link joins the freed sets
    // (`retention::freed`), memory rows; node-sync deletes the pieces as durable ones
    let held: Vec<usize> = tx.core.ix.commits.get(id).filter(|m| m.view.memory).map(|m| (0..m.header.aspects.len()).filter(|ai| m.holds(*ai)).collect()).unwrap_or_default();
    for ai in held {
        crate::retention::freed::free_part(tx, id, ai)?;
    }
    // a held snapshot carrying its writes keeps its name (`retention::names`)
    if marks {
        crate::retention::names::note(tx, id)?;
    }
    let core = &mut *tx.core;
    let Some(m) = core.take_meta(id) else { return Ok(()) };
    let v = &m.view;
    for ai in 0..v.aspects.len() {
        unjudge_part(core, id, ai);
    }
    for (ai, a) in v.aspects.iter().enumerate() {
        let k = (a.tid, a.ak.clone());
        core.ix.by_aspect.remove(&k, &(v.ts, *id));
        if !core.ix.by_aspect.contains_key(&k) {
            core.ix.aspect_things.remove(&a.ak, &a.tid);
        }
        core.ix.invalid.remove(&k, id);
        core.ix.by_thing.remove(&(a.tid, v.signer), id);
        core.ix.purges_on.remove(&a.tid, id);
        if a.ak.as_str() == osis_commit::retention::RETENTION {
            super::validity::forget_setting(core, &a.tid, id);
        }
        if v.form.counted() && v.kind.has_own_writes() && a.lo < a.hi {
            core.ix.ranges.remove(&(a.tid, a.ak.clone(), v.form.own_source(v.signer, *id)), &(a.lo, *id));
        }
        super::atomic::forget_snapshot(core, &a.tid, &a.ak, id);
        // a memory commit's aspect holds no durable one (ephemeral aspects): one row per aspect;
        // an invalid part replaced nothing (`undo::parts_before` skips it), so it stands for none;
        // nor does a fire: a signal reads absent before and after any write (spec/commits.md §7);
        // nor a part on a thing whose record is not held (a release forgot it): the row goes with
        // the thing, so none is written for one gone
        if marks && m.valid_at(ai) && !a.ak.signal() && core.created(&a.tid).is_some() && core.ix.forgotten.get(&k).is_none_or(|t| *t < v.ts) {
            if !v.memory {
                tx.txn.put_local(&records::aspect_key(records::FORGOTTEN, &a.tid, &a.ak), &v.ts.to_u64().to_be_bytes(), Shred::No)?;
            }
            core.ix.forgotten.insert(k, v.ts);
        }
    }
    // Interim (issues/stated-path-certificates.md): every listed thing of each stated path
    if let Some(x) = v.other_purge_author() {
        core.ix.by_actor.remove(&(x, v.signer), id);
        // the last held commit acting as it was a need (`retention::needed::Need::Acting`)
        if core.acting_for(&x).next().is_none() {
            core.note_lost(x);
        }
    }
    core.ix.paths_unknown.remove(id);
    super::validity::forget_addenda(core, id, &v.aspects);
    crate::engine::edits::unindex_commit(core, id, v);
    // its keyset parts' rows (`records::OWN_SECRETS`: kept while the commit is held)
    let keyed: BTreeSet<Tid> = v.aspects.iter().filter(|a| a.ak.as_str() == "keys.0").map(|a| a.tid).filter(|t| core.ix.keyset_parts.get(t).is_some_and(|s| s.contains(id))).collect();
    for t in &keyed {
        core.touch();
        core.ix.keyset_parts.remove(t, id);
        tx.txn.remove_local(&records::own_secrets_key(t, id), Shred::No)?;
    }
    let void = core.ix.void.remove(id);
    for a in &v.aspects {
        core.ix.miskeyed.remove(&(*id, a.tid));
    }
    core.ix.rekeyed.remove(id);
    super::set_pending(core, id, None);
    core.ix.unresolved.remove(id);
    // perm reads nothing of a commit not held: its edge writes
    core.ix.held.remove(id);
    core.stale_commits.remove(id);
    if void {
        tx.txn.remove_local(&[records::VOID, &id.0[..]].concat(), Shred::No)?;
    }
    // its retention timers
    tx.remove_timers_of(id, None)?;
    // its writes off the gone list: a copy arriving again applies as new (a batched
    // rebuild still to run strips their values first, `apply::run_batched`)
    for (ai, a) in m.header.aspects.iter().enumerate() {
        let owned = crate::retention::writes_of(&m.header, id, ai);
        if owned.is_empty() {
            continue;
        }
        match &mut tx.core.batched {
            Some(b) => {
                // a memory aspect's rebuild: in the memory class however it was asked
                let e = b.entry((a.tid, a.ak.clone())).or_default();
                e.unlist.extend(owned);
                e.memory |= v.memory;
            }
            None => crate::retention::off_gone(tx, &a.tid, &a.ak, &owned),
        }
    }
    // what its `keys.0` parts gave (held or dropped: `Dropped::keysets`) and its `secrets.0`
    // parts' boxes (`Indexes::boxed`), re-derived from the parts still held, as a drop
    // re-derives them (`keys::forget_dropped`)
    let keys: BTreeSet<Tid> = v.aspects.iter().filter(|a| a.ak.as_str() == "keys.0").map(|a| a.tid).collect();
    let boxed: BTreeSet<Tid> = v.aspects.iter().filter(|a| matches!(a.ak.as_str(), "keys.0" | "secrets.0")).map(|a| a.tid).collect();
    super::keys::rebuild_keysets(tx, &boxed)?;
    super::keys::refresh_independent(tx, &keys, false)?;
    // the reading-only secrets its invalid boxes gave go with it (`keys::read_invalid`)
    if tx.core.waits.read_any(id) {
        super::keys::forget_unchecked(tx, id)?;
    }
    // a signal with no fire left held keeps no cursor (`retention::leaving`)
    for a in m.header.aspects.iter().filter(|a| a.ak.signal()) {
        crate::retention::leaving::unplaced(tx, &a.tid, &a.ak)?;
    }
    tx.remove_commit(id)?;
    for (ai, bodies) in boxes {
        super::keys::forget_dropped(tx, &m.header.clone(), ai, &bodies)?;
    }
    Ok(())
}

/// The rows part `ai` of `c`'s judgment derived (the roles its `secrets.0` or `keys.0` delta
/// needs, an overreach) go: the part went missing
/// (`retention::reopen_in`) or its commit is forgotten. The commit's reading moves with them
/// (`validity::reading`): touched, the caller giving it to the walk.
pub(crate) fn unjudge_part(core: &mut crate::engine::Core, c: &CommitId, ai: usize) {
    if core.ix.rotation_role.remove(&(*c, ai)).is_some() {
        core.ix.held.touch_commit(*c);
    }
    core.ix.overreach.remove(&(*c, ai));
}

#[cfg(test)]
mod tests {
    use crate::engine::journal::Journaled;
    use crate::local_peer::LocalPeer;
    use crate::{Engine, Mutation};
    use osis_base::{Ak, Value, Time};

    /// Every journaled index but `forgotten`, which keeps what forgetting leaves on purpose, and
    /// perm's view.
    fn digest(e: &Engine) -> String {
        let ix: Vec<String> = e.core.ix.contents().lines().filter(|l| !l.starts_with("forgotten ")).map(String::from).collect();
        format!("{}\n{}", ix.join("\n"), e.perm_digest(false))
    }

    fn ak(s: &str) -> Ak {
        Ak::new(s).unwrap()
    }

    // Memory commits on a durable thing that
    // are superseded, or whose last part vanishes, are forgotten: every journaled index (and perm's view) as if they had never applied, the
    // state too, but for the newest forgotten `ts` per aspect. spec: none (internal)
    #[test]
    fn forget_equals_never_indexed() {
        let mut lp = LocalPeer::fresh(1, Time(1_700_000_000_000));
        let e = &mut lp.peers[0].engine;
        let me = e.tid();
        let mut m = Mutation::new();
        let g = e.new_thing(&mut m, me);
        m.set(g, &ak("t:reg.0"), &Value::Str("g".into())).unwrap();
        e.commit(m).unwrap();
        let before = digest(e);
        let key = Value::Str("k".into());
        for i in 0..3 {
            let mut m = Mutation::new();
            m.op(g, &ak("t:m+.0"), osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Key(key.clone())], op: osis_crdt::Op::Put(Value::Str(format!("v{i}"))) }).unwrap();
            m.expires(g, &ak("t:m+.0"), Time(e.now().0 + 1000)).unwrap();
            e.commit_in_memory(m).unwrap().unwrap();
        }
        assert_eq!(e.core.ix.commits.values().filter(|m| m.view.memory).count(), 1, "superseded moves are forgotten");
        let last = *e.core.ix.commits.iter().find(|(_, m)| m.view.memory).unwrap().0;
        e.run(|tx| {
            crate::retention::memory::vanish(tx, &last, 0)?;
            crate::retention::memory::forget_if_spent(tx, &last)
        })
        .unwrap();
        assert_eq!(digest(e), before);
        assert_eq!(e.get(&g, &ak("t:m+.0")).unwrap(), None);
        assert!(e.core.ix.forgotten.get(&(g, ak("t:m+.0"))).is_some(), "an undo still counts them (`undo::replaced_kept`)");
    }

    // spec/commits.md §4 (counter ranges on one aspect overlap are both invalid): two opens of one store under
    // one session nonce (a copy opened alike) write the same counter of a memory aspect; both
    // are void at the node they reach. Forgotten, each takes its `void` row with it: the
    // persisted index opens as a rebuild computes it.
    #[test]
    fn forgotten_void_commit_leaves_no_void_row_spec_commits_4() {
        let mut lp = LocalPeer::fresh(1, Time(1_700_000_000_000));
        let me = lp.peers[0].engine.tid();
        let mut m = Mutation::new();
        let g = lp.peers[0].engine.new_thing(&mut m, me);
        m.set(g, &ak("t:reg.0"), &Value::Str("g".into())).unwrap();
        lp.peers[0].engine.commit(m).unwrap();
        lp.hold(g);
        let mut ids = Vec::new();
        for v in ["x", "y"] {
            // the same seed: the same session nonce, counter 1 in each
            let mut f = lp.peers[0].fork(7).unwrap();
            let mut m = Mutation::new();
            m.set(g, &ak("t:m+.0"), &Value::Str(v.into())).unwrap();
            let id = f.engine.commit_in_memory(m).unwrap().unwrap();
            let pk = f.engine.package(&id).unwrap().unwrap();
            lp.peers[0].engine.ingest_memory(&pk.bytes, u64::MAX).unwrap();
            ids.push(id);
        }
        let e = &mut lp.peers[0].engine;
        assert_eq!(e.core.ix.void.iter().copied().collect::<Vec<_>>(), { ids.sort(); ids.clone() }, "overlapping counters void both");
        for id in &ids {
            e.run(|tx| {
                crate::retention::memory::vanish(tx, id, 0)?;
                crate::retention::memory::forget_if_spent(tx, id)
            })
            .unwrap();
            assert!(!e.core.ix.commits.contains_key(id), "forgotten");
        }
        e.check_index();
    }

    // spec/commits.md §6: an HLC ahead of the clock (a peer's fast clock read, here the clock set
    // back) has passed a short expiry: the write goes through, expiring just after its `ts`.
    #[test]
    fn short_expiry_behind_hlc_is_raised_spec_commits_6() {
        let mut lp = LocalPeer::fresh(1, Time(1_700_000_000_000));
        let e = &mut lp.peers[0].engine;
        let me = e.tid();
        let mut m = Mutation::new();
        let g = e.new_thing(&mut m, me);
        m.set(g, &ak("t:reg.0"), &Value::Str("g".into())).unwrap();
        e.commit(m).unwrap();
        lp.peers[0].clock.set(Time(1_700_000_000_000 - 60_000));
        let e = &mut lp.peers[0].engine;
        let mut m = Mutation::new();
        m.set(g, &ak("t:m.0"), &Value::Str("typing".into())).unwrap();
        m.expires(g, &ak("t:m.0"), Time(e.now().0 + 5_000)).unwrap();
        let c = e.commit(m).unwrap().unwrap();
        let h = e.header(&c).unwrap();
        assert_eq!(h.expires, Some(h.ts.wall_ms().0 + 1));
        assert_eq!(e.get(&g, &ak("t:m.0")).unwrap(), Some(Value::Str("typing".into())));
        lp.advance(60_002);
        lp.peers[0].tick().unwrap();
        let e = &mut lp.peers[0].engine;
        assert_eq!(e.get(&g, &ak("t:m.0")).unwrap(), None);
    }

    // spec/commits.md §5 Purge on replace, notes/ephemeral.md Principle: a memory aspect under
    // purge on replace drops a replaced part at once under the replacer's cover, while the
    // commit's live part on another aspect stays held, and goes at its expiry, nothing of it held
    // (spec/crdt.md §4.7).
    #[test]
    fn memory_purge_on_replace_drops_the_replaced_part_spec_commits_5() {
        let mut lp = LocalPeer::fresh(1, Time(1_700_000_000_000));
        let e = &mut lp.peers[0].engine;
        let me = e.tid();
        let mut m = Mutation::new();
        let g = e.new_thing(&mut m, me);
        m.set(g, &ak("t:reg.0"), &Value::Str("g".into())).unwrap();
        m.set(g, &osis_schema::core_types::RETENTION, &osis_schema::core_types::RetentionSetting::of(ak("t:r+.0"), osis_schema::History::PurgeOnReplace)).unwrap();
        e.commit(m).unwrap();
        let t = Time(e.now().0 + 2 * 3_600_000);
        let mut m = Mutation::new();
        for (k, v) in [("t:r+.0", "v"), ("t:s+.0", "live")] {
            m.set(g, &ak(k), &Value::Str(v.into())).unwrap();
            m.expires(g, &ak(k), t).unwrap();
        }
        let c = e.commit_in_memory(m).unwrap().unwrap();
        lp.advance(10);
        let e = &mut lp.peers[0].engine;
        let mut m = Mutation::new();
        m.set(g, &ak("t:r+.0"), &Value::Str("w".into())).unwrap();
        e.commit_in_memory(m).unwrap().unwrap();
        let r = e.core.ix.commits.get(&c).and_then(|m| m.aspect(&g, &ak("t:r+.0"))).unwrap();
        assert!(e.core.ix.commits.get(&c).is_some_and(|m| m.dropped_parts().count() == 1 && m.is_dropped(r)), "the replaced part goes");
        assert_eq!(e.get(&g, &ak("t:r+.0")).unwrap(), Some(Value::Str("w".into())));
        assert_eq!(e.get(&g, &ak("t:s+.0")).unwrap(), Some(Value::Str("live".into())));
        lp.advance(2 * 3_600_000);
        lp.peers[0].tick().unwrap();
        let e = &mut lp.peers[0].engine;
        assert_eq!(e.get(&g, &ak("t:s+.0")).unwrap(), None, "gone at its expiry");
        assert!(e.core.ix.commits.get(&c).is_none_or(|m| m.stripped_parts().count() == 0 && (0..m.view.aspects.len()).all(|ai| !m.holds(ai))), "nothing of it held");
    }

    // notes/engine-store.md Aspect units: an aspect is listed (its unit) exactly while it has a
    // state. A durable and a memory value going at their expiry leave no unit, live or after a
    // reload; the aspects that keep a state stay listed. spec: none (internal)
    #[test]
    fn an_expired_state_leaves_no_unit() {
        let mut lp = LocalPeer::fresh(1, Time(1_700_000_000_000));
        let e = &mut lp.peers[0].engine;
        let me = e.tid();
        let mut m = Mutation::new();
        let g = e.new_thing(&mut m, me);
        m.set(g, &ak("t:reg.0"), &Value::Str("g".into())).unwrap();
        e.commit(m).unwrap();
        let t = Time(e.now().0 + 3_600_000);
        let mut m = Mutation::new();
        m.set(g, &ak("t:d.0"), &Value::Int(1)).unwrap();
        m.expires(g, &ak("t:d.0"), t).unwrap();
        e.commit(m).unwrap();
        let mut m = Mutation::new();
        m.set(g, &ak("t:m+.0"), &Value::Int(2)).unwrap();
        m.expires(g, &ak("t:m+.0"), t).unwrap();
        e.commit_in_memory(m).unwrap();
        let listed = |e: &mut Engine| e.all_aspects().unwrap().into_iter().filter(|x| x.0 == g).map(|x| x.1.as_str().to_string()).collect::<Vec<_>>();
        let before = listed(e);
        assert!(before.iter().any(|a| a == "t:d.0") && before.iter().any(|a| a == "t:m+.0"), "{before:?}");
        lp.advance(3_600_001);
        lp.peers[0].tick().unwrap();
        let e = &mut lp.peers[0].engine;
        assert_eq!(e.get(&g, &ak("t:d.0")).unwrap(), None);
        let after = listed(e);
        assert!(after.iter().any(|a| a == "t:reg.0") && !after.iter().any(|a| a == "t:d.0" || a == "t:m+.0"), "{after:?}");
        assert!(e.run(|tx| Ok(tx.txn.get_aspect(&g, &ak("t:d.0"))?)).unwrap().is_none(), "no unit");
        e.check_index();
        e.reload().unwrap();
        assert_eq!(listed(e), after, "a reload lists the same");
    }
}
