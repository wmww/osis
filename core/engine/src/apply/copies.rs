//! Which delta carries a dot (spec/permissions.md §5.2), and whether a snapshot is valid: a valid
//! snapshot's writes join like any write (spec/crdt.md §4.1 copy order) and are never compared
//! with their own delta's.

use crate::engine::{Core, Meta};
use osis_base::{Ak, CommitId, Tid};
use osis_commit::Form;
use osis_crdt::Dot;

/// Whether some held commit carrying dot `d` on `(tid, ak)` (spec/permissions.md §5.2) has its
/// delta of that aspect as `f` judges it: the session-form commit whose range holds it; for
/// `Commit(c)`, `c` itself as a commit-form commit with the aspect.
pub(crate) fn any_delta(core: &Core, tid: &Tid, ak: &Ak, d: &Dot, f: &dyn Fn(&CommitId, &Meta, usize) -> bool) -> bool {
    let at = |m: &Meta| m.aspect(tid, ak);
    let d = d.origin();
    match d.src.kind() {
        osis_crdt::SourceKind::Session(_) => core.commit_of(tid, ak, d).is_some_and(|c| core.ix.commits.get(&c).is_some_and(|m| at(m).is_some_and(|ai| f(&c, m, ai)))),
        osis_crdt::SourceKind::Commit(c) => core.ix.commits.get(c).filter(|m| m.view.form == Form::Commit && m.view.kind.has_own_writes()).is_some_and(|m| at(m).is_some_and(|ai| f(c, m, ai))),
        osis_crdt::SourceKind::Derived(_) => false,
    }
}

/// Whether the delta carrying dot `d` on `(tid, ak)` was ever held here (held or dropped).
pub(crate) fn delta_received(core: &Core, tid: &Tid, ak: &Ak, d: &Dot) -> bool {
    any_delta(core, tid, ak, d, &|_, m, ai| !m.missing(ai))
}

/// Whether the state of `(tid, ak)` reflects the delta that wrote dot `d` (spec/sync.md §7
/// Sweep): applied here and valid, or reached by a held valid snapshot's `Frontiers` or
/// `Absorbed` (spec/crdt.md §8). Never a `Derived` dot: its record is its register write's.
pub(crate) fn reflected(core: &Core, tid: &Tid, ak: &Ak, d: &Dot) -> bool {
    osis_base::costs::count("sweep: reflected", 1);
    if matches!(d.src.kind(), osis_crdt::SourceKind::Derived(_)) {
        return false;
    }
    if any_delta(core, tid, ak, d, &|_, m, ai| m.valid_at(ai) && !m.missing(ai)) {
        return true;
    }
    let held = |s: &CommitId| core.ix.commits.get(s).is_some_and(|m| m.aspect(tid, ak).is_some_and(|ai| m.valid_at(ai) && !m.missing(ai) && !m.body_gone(ai)));
    core.ix.snapshots.get(&(*tid, ak.clone())).into_iter().flatten().any(|(_, s, fr, abs, _)| {
        let reaches = match d.src.kind() {
            osis_crdt::SourceKind::Commit(c) => abs.iter().any(|x| x.0 == *c),
            _ => fr.lists(&d.src) && fr.of(&d.src) >= d.ctr,
        };
        reaches && held(s)
    })
}

/// Whether held snapshot `snap`'s part on `(tid, ak)` is valid (`Judge::part`: its author could
/// write the aspect at it).
pub(crate) fn snapshot_valid(core: &Core, snap: &CommitId, tid: &Tid, ak: &Ak) -> bool {
    core.ix.commits.get(snap).is_some_and(|m| m.aspect(tid, ak).is_some_and(|ai| m.valid_at(ai)))
}
