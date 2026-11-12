//! The join of a commit's parts before streaming (issues/durable-decode-bound.md step 3), kept
//! as the oracle of `atomic::joins`: every part decoded whole (`examine` under
//! `Core::whole_apply`), joined whole, a reset or encoding change of a paged collection loading
//! and rewriting the whole state. `tests_paged` requires both to leave the same.

use super::Parts;
use super::atomic::{Joins, note_snapshot, strip_valueless};
use crate::engine::{Gives, Tx};
use crate::retention::Killed;
use crate::error::Result;
use osis_base::{Ak, CommitId, Tid};
use osis_commit::{Decoded, Header};
use osis_crdt::{Changes, Fragment};
use osis_store::Shred;

fn fragment(d: Decoded) -> (Fragment, Option<Gives>) {
    match d {
        Decoded::Delta(x) => (x.fragment, None),
        Decoded::Snapshot(x) => (x.fragment, Some((x.frontiers, x.absorbed.into_iter().collect()))),
    }
}

pub(super) fn joins(tx: &mut Tx<'_>, h: &Header, id: &CommitId, parts: &Parts, valid: &[bool], j: &mut Joins) -> Result<()> {
    for (ai, d) in &parts.whole {
        let (ai, d) = (*ai, d.clone());
        let Some(a) = h.aspects.get(ai) else { continue };
        let (f, fr) = fragment(d);
        // a signal joins no state (`join_part`)
        if a.ak.signal() {
            continue;
        }
        // every held snapshot's frontiers, whatever its validity
        if let Some(fr) = fr {
            note_snapshot(tx.core, &a.tid, &a.ak, h.ts, id, fr);
        }
        // an invalid part joins nothing (`atomic::join_part`)
        if !valid.get(ai).copied().unwrap_or(false) {
            continue;
        }
        j.touched.note(&a.tid, &a.ak, &f);
        let mut dead = Killed::default();
        let ch = join_into_state(tx, &a.tid, &a.ak, f, &mut dead)?;
        if ch.is_changed() {
            j.changed.insert((a.tid, a.ak.clone()));
        }
        j.joined.push((a.tid, a.ak.clone(), dead));
    }
    Ok(())
}

fn join_into_state(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, mut delta: Fragment, dead: &mut Killed) -> Result<Changes> {
    tx.load_lazy(tid, ak)?;
    strip_valueless(tx.core, tid, ak, &mut delta);
    let touch = crate::engine::pages::touch_of(&delta, tx.core.pages.get(&(*tid, ak.clone())));
    tx.ensure_touch(tid, ak, &touch)?;
    let k = (*tid, ak.clone());
    tx.core.touch();
    tx.core.wrote(k.clone());
    let mut st = tx.core.states.get_mut(&k).and_then(Option::take).unwrap_or_default();
    // the reference index: the tids at the join's reach, before and after
    let refs = crate::engine::refs::indexed(ak).then(|| (crate::engine::refs::Delta::reach(&st, &delta, -1), delta.clone()));
    let (before, d) = (Killed::before(&st, &delta), delta.clone());
    let roots = crate::retention::compact::roots(ak, &st, &delta);
    let ch = st.join(delta);
    let refs = refs.filter(|_| ch.is_changed()).map(|(mut d, x)| {
        d.add(&st.reach(&x), 1);
        d
    });
    dead.note(&before, &st, &d);
    let after = crate::retention::compact::roots(ak, &st, &d);
    let st = tx.kept(tid, ak, st)?;
    if ch.is_changed() {
        tx.set_state_touched(tid, ak, st, &touch, Shred::No)?;
        crate::engine::refs::note(tx, tid, ak, refs.unwrap_or_default())?;
    } else {
        tx.core.states.insert(k, st);
    }
    crate::retention::compact::Trigger::unlinked(tx, tid, ak, &roots, &after)?;
    Ok(ch)
}
