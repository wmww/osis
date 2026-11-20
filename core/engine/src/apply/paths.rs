//! The paths of split commits as this node knows them (spec/wire.md §4 `Split`; notes/path-form.md
//! Per consumer). A thing's path is header data: a node judging the thing's parts opens its entry
//! with the path key an encryption of the thing's parts carried (`CommitBlob::keys`), else with
//! the read roles secrets it holds of the things up the thing's record chain. A thing whose path
//! opens to a bad list, or opens nowhere here, has its parts judged invalid (`View::paths`);
//! one opening nowhere here waits (`Wait`) and is opened again when a roles secret or a record
//! that may open it moves (`refresh`) or a late encryption brings its key (`atomic::join_late`).

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

/// What the node holds of the things `open` tries for the things of commit `id` whose paths open
/// nowhere here: per such thing, per thing up its record chain, the epochs of its own secrets
/// whose roles secret is held (`Indexes::secrets`) and, for an account, the epochs whose seeds are
/// held. What may open an entry, read from stamped containers alone (no state, no derivation): a
/// `memo::Effects` following it is due exactly when one of them moves (a record learned up a
/// chain, an independent thing's or an account's secrets). A key actor's are fixed.
fn openers(core: &Core, id: &osis_base::CommitId) -> Openers {
    let Some(m) = core.ix.commits.get(id) else { return Vec::new() };
    let Some(paths) = m.view.paths.as_deref() else { return Vec::new() };
    let mut undecided: Vec<Tid> = m.view.aspects.iter().map(|a| a.tid).filter(|t| !paths.contains_key(t)).collect();
    undecided.dedup();
    let mut out = Vec::new();
    for t in undecided {
        let mut x = Some(t);
        for _ in 0..=osis_base::format::MAX_CHAIN_DEPTH + 1 {
            let Some(cur) = x else { break };
            let own = core.ix.secrets.get(&cur).map(|e| e.read.epochs().filter(|(ep, _)| e.read.roles_secret(ep).is_some()).map(|(ep, _)| *ep).collect()).unwrap_or_default();
            let seeds = core.accounts.get(&cur).map(|a| a.keys.keys().cloned().collect()).unwrap_or_default();
            out.push((cur, own, seeds));
            x = core.created(&cur).and_then(osis_base::CreationRecord::mint_admin);
        }
    }
    out
}

type Openers = Vec<(Tid, Vec<osis_crypto::Epoch>, Vec<osis_crypto::VerifyingKey>)>;

/// The wait of held split commits with a thing whose path opens nowhere here
/// (`Indexes::paths_unknown`, journaled): each followed (`memo::Effects`) by what may open it
/// (`openers`), opened again only when that moves (notes/sync-facade.md Pending). In memory only:
/// an open, a reload and a rollback build it again from `paths_unknown`, taking what they find as
/// tried (each commit's view was decided against what was held when it was last judged).
pub(crate) struct Wait {
    fx: osis_base::memo::Effects<osis_base::CommitId, Openers>,
    /// `paths_unknown`'s additions since: followed, and tried on their first settle.
    added: osis_base::memo::Feed<osis_base::CommitId>,
}

/// Opens again the paths of the held split commits waiting in `Indexes::paths_unknown` whose
/// openers moved (`Wait`): where more are decided, a commit's view takes them and its parts are
/// judged again. Such a thing has no key held (a held part carries its own), so only roles
/// secrets are tried. Costs the commits whose openers moved, never the commits waiting.
pub(crate) fn refresh(tx: &mut Tx<'_>) {
    let built = tx.core.paths_wait.is_none();
    let mut w = tx.core.paths_wait.take().unwrap_or_else(|| Wait { fx: osis_base::memo::Effects::new("paths: wait"), added: tx.core.ix.paths_unknown.feed() });
    let mut fresh = std::collections::BTreeSet::new();
    if built {
        for id in tx.core.ix.paths_unknown.iter() {
            w.fx.want(*id);
        }
    }
    for id in w.added.added() {
        if tx.core.ix.paths_unknown.contains(&id) {
            w.fx.want(id);
            fresh.insert(id);
        }
    }
    for id in w.fx.due() {
        if !tx.core.ix.paths_unknown.contains(&id) {
            w.fx.unwant(&id);
            continue;
        }
        let core: &Core = tx.core;
        let moved = w.fx.settle(&id, || {
            osis_base::costs::count("paths: waits settled", 1);
            openers(core, &id)
        });
        // a commit followed anew is tried once (what came in its own transaction); one built
        // from the index again, only once its openers move
        let tried = match moved {
            Some((Some(_), _)) => true,
            Some((None, _)) => fresh.contains(&id),
            None => false,
        };
        if tried {
            reopen(tx, &id);
            if !tx.core.ix.paths_unknown.contains(&id) {
                w.fx.unwant(&id);
            }
        }
    }
    tx.core.paths_wait = Some(w);
}

/// Tries the roles secrets held on commit `id`'s things whose paths open nowhere here.
fn reopen(tx: &mut Tx<'_>, id: &osis_base::CommitId) {
    let Some(m) = tx.core.ix.commits.get(id).cloned() else { return };
    osis_base::costs::count("paths: commits opened again", 1);
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
        set_paths(tx, id, Some(Arc::new(now)));
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
