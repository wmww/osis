//! The paths of split commits as this node knows them (spec/wire.md §4 `Split`; notes/path-form.md
//! Per consumer). A thing's path is header data: a node judging the thing's parts opens its entry
//! with the path key an encryption of the thing's parts carried (`CommitBlob::keys`), else with
//! the read roles secrets it holds of the things up the thing's record chain. A thing whose path
//! opens to a bad list, or opens nowhere here, has its parts judged invalid (`View::path_known`);
//! one opening nowhere here is opened again as the node's role inputs move (`refresh`, from
//! `atomic::rejudged`) or a late encryption brings its key (`atomic::join_late`).

use crate::engine::{Core, Tx};
use osis_base::Tid;
use osis_commit::{Header, ThingPath};
use std::collections::BTreeMap;
use std::sync::Arc;

/// The path commit header `h` states for the thing `t` at place `i`, opened here: under `key`
/// where an encryption carried it, else under the read roles secrets held of the things up `t`'s
/// record chain (`t` itself, its mint admin, …), newest first. `None`: nothing held opens it.
pub(crate) fn open(core: &Core, h: &Header, key: Option<&[u8; 32]>, i: usize, t: &Tid) -> Option<ThingPath> {
    if let Some(k) = key {
        return h.open_path(i, k);
    }
    let mut x = Some(*t);
    for _ in 0..=osis_base::format::MAX_CHAIN_DEPTH + 1 {
        let Some(cur) = x else { break };
        if let Some(e) = core.epochs(&cur) {
            let mut eps: Vec<_> = e.read.epochs().map(|(ep, _)| *ep).collect();
            eps.reverse();
            for ep in eps {
                if let Some(s) = e.read.roles_secret(&ep)
                    && let Some(p) = h.open_path(i, &osis_commit::path_key(&s, &h.blind, t))
                {
                    return Some(p);
                }
            }
        }
        x = core.created(&cur).and_then(osis_base::CreationRecord::mint_admin);
    }
    None
}

/// What this node decided of the path split commit header `h` states for each thing: `true` known
/// and not bad, `false` bad; a thing whose path opens nowhere here yet is absent. `keys`: the path
/// keys its held encryptions carried. `None` where its path is in the clear (`View::paths`).
pub(crate) fn decided(core: &Core, h: &Header, keys: &BTreeMap<usize, [u8; 32]>) -> Option<Arc<BTreeMap<Tid, bool>>> {
    if !h.is_split() {
        return None;
    }
    let out = h.things().into_iter().enumerate().filter_map(|(i, t)| Some((t, matches!(open(core, h, keys.get(&i), i, &t)?, ThingPath::Known(_))))).collect();
    Some(Arc::new(out))
}

/// Whether a split commit's view leaves a thing undecided (`decided`).
pub(crate) fn undecided(h: &Header, paths: Option<&BTreeMap<Tid, bool>>) -> bool {
    paths.is_some_and(|p| h.things().iter().any(|t| !p.contains_key(t)))
}

/// Opens again the paths of every held split commit with a thing whose path opened nowhere here
/// (`Indexes::paths_unknown`), the node's role inputs having moved: where more are decided, its
/// view takes them and its parts are judged again. Such a thing has no key held, so only roles
/// secrets are tried. Brute force over those commits (notes/path-form.md Per consumer: a holder
/// lacking an entry's epoch and every encryption of the thing's parts).
pub(crate) fn refresh(tx: &mut Tx<'_>) {
    let ids: Vec<osis_base::CommitId> = tx.core.ix.paths_unknown.iter().copied().collect();
    for id in ids {
        let Some(m) = tx.core.ix.commits.get(&id).cloned() else { continue };
        let h = m.header.clone();
        let mut now = m.view.paths.as_deref().cloned().unwrap_or_default();
        let before = now.len();
        for (i, t) in h.things().into_iter().enumerate() {
            if !now.contains_key(&t)
                && let Some(p) = open(tx.core, &h, None, i, &t)
            {
                now.insert(t, matches!(p, ThingPath::Known(_)));
            }
        }
        if now.len() != before {
            set_paths(tx, &id, Some(Arc::new(now)));
        }
    }
}

/// Commit `id`'s view with the paths decided here `paths`: its parts judged again, and it leaves
/// `Indexes::paths_unknown` once none is undecided.
pub(crate) fn set_paths(tx: &mut Tx<'_>, id: &osis_base::CommitId, paths: Option<Arc<BTreeMap<Tid, bool>>>) {
    let Some(mut m) = tx.core.ix.commits.get(id).cloned() else { return };
    if !undecided(&m.header, paths.as_deref()) {
        tx.core.ix.paths_unknown.remove(id);
    }
    m.view = Arc::new(crate::engine::View { paths, ..(*m.view).clone() });
    let h = m.header.clone();
    m.valid = (0..m.valid.len()).map(|ai| crate::apply::validity::part_valid(tx.core, &h, &m.view, id, ai)).collect();
    tx.core.put_meta(*id, m);
    tx.core.index_validity(id);
    tx.core.stale_commits.insert(*id);
}
