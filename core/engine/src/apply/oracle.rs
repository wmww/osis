//! The join of a commit's parts before streaming (issues/durable-decode-bound.md step 3), kept
//! as the oracle of `atomic::joins`: every part decoded whole (`examine` under
//! `Core::whole_apply`), joined whole, a reset or encoding change of a paged collection loading
//! and rewriting the whole state. `tests_paged` requires both to leave the same.

use super::Parts;
use super::atomic::{Joins, Unmerge, invalid_of, note_snapshot, strip_valueless};
use super::{copies, validity};
use crate::engine::{Gives, Tx};
use crate::error::Result;
use osis_base::{Ak, CommitId, Tid};
use osis_commit::{AspectEntry, Decoded, Header};
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
        let snap = fr.is_some();
        // every held snapshot's frontiers and carried writes, whatever its validity
        if let Some(fr) = fr {
            let v = valid.get(ai).copied().unwrap_or(false);
            if note_snapshot_part(tx, a, h.ts, id, &f, fr, v) || v && misstates_held(tx, &a.tid, &a.ak, &f)? {
                j.rebuild.insert((a.tid, a.ak.clone()));
            }
        }
        if !valid.get(ai).copied().unwrap_or(false) {
            // an invalid delta joins nothing: rebuilt once stored (`atomic::join_part`)
            if !snap && !validity::perm_ak(a.ak.as_str()) {
                j.rebuild.insert((a.tid, a.ak.clone()));
            }
            continue;
        }
        j.touched.note(&a.tid, &a.ak, &f);
        let ch = join_into_state(tx, &a.tid, &a.ak, f, snap)?;
        if ch.is_changed() {
            j.changed.insert((a.tid, a.ak.clone()));
        }
        j.joined.push((a.tid, a.ak.clone(), snap, ch.into_deaths()));
    }
    Ok(())
}

fn note_snapshot_part(tx: &mut Tx<'_>, a: &AspectEntry, ts: osis_base::Ts, id: &CommitId, f: &Fragment, fr: Gives, valid: bool) -> bool {
    note_snapshot(tx.core, &a.tid, &a.ak, ts, id, fr);
    let c = copies::carried_of(tx.core, &a.tid, &a.ak, f);
    copies::note_carried_of(tx.core, &a.tid, &a.ak, id, c);
    if !valid {
        return false;
    }
    let owned = invalid_of(tx.core, &a.tid, &a.ak);
    copies::vouches_any(f, &owned)
}

fn misstates_held(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, f: &Fragment) -> Result<bool> {
    if !f.holds_owned(&|src, lo, hi| super::atomic::core_holds_delta(tx.core, tid, ak, src, lo, hi)) {
        return Ok(false);
    }
    tx.load(tid, ak)?;
    let core = &*tx.core;
    let Some(Some(st)) = core.states.get(&(*tid, ak.clone())) else { return Ok(false) };
    Ok(!f.misstated(&[st], &|d| copies::delta_held(core, tid, ak, d), &|d| copies::delta_expires(core, tid, ak, d)).is_empty())
}

fn join_into_state(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, mut delta: Fragment, snap: bool) -> Result<Changes> {
    tx.load_lazy(tid, ak)?;
    let un = Unmerge::probe(tx, tid, ak, &delta)?;
    if !un.is_empty() {
        if snap {
            let mine = delta.copy_index();
            delta.remove_dots(&|d| un.bad(d) && !mine.holds(d));
        } else {
            un.strip(&mut delta);
        }
        crate::retention::mark_if_bounded(tx, tid, ak)?;
    }
    strip_valueless(tx.core, tid, ak, &mut delta);
    let touch = crate::engine::pages::touch_of(&delta, tx.core.pages.get(&(*tid, ak.clone())));
    tx.ensure_touch(tid, ak, &touch)?;
    let k = (*tid, ak.clone());
    tx.core.touch();
    tx.core.wrote(k.clone());
    let mut st = tx.core.states.get_mut(&k).and_then(Option::take).unwrap_or_default();
    let ch = st.join(delta);
    let st = tx.kept(tid, ak, st)?;
    if ch.is_changed() || !ch.deaths().is_empty() {
        tx.set_state_touched(tid, ak, st, &touch, Shred::No)?;
    } else {
        tx.core.states.insert(k, st);
    }
    Ok(ch)
}
