//! The join of a part before streaming (issues/durable-decode-bound.md step 3), kept as the
//! oracle of `atomic::join_into_state`: every part decoded whole (`examine` under
//! `Core::whole_apply`), joined whole, a reset or encoding change of a paged collection loading
//! and rewriting the whole state. `tests_paged` requires both to leave the same.

use super::atomic::strip_valueless;
use crate::engine::Tx;
use crate::retention::Killed;
use crate::error::Result;
use osis_base::{Ak, Tid};
use osis_crdt::{Changes, Fragment};
use osis_store::Shred;

/// Joins `delta` into `(tid, ak)` whole (`atomic::join_part` under `Core::whole_apply`, in place
/// of `atomic::join_into_state`): the state loaded and rewritten as before streaming. Only the
/// join differs: every other decision of a part's apply is `join_part`'s in both worlds.
pub(super) fn join_into_state(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, mut delta: Fragment, dead: Option<&mut Killed>) -> Result<Changes> {
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
    if let Some(dead) = dead {
        dead.note(&before, &st, &d);
    }
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
