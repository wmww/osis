//! The paths of split commits as this node knows them (spec/wire.md §4 `Split`; notes/path-form.md
//! Per consumer). A thing's path is header data: a node judging the thing's parts opens its entry
//! with the path key an encryption of the thing's parts carried (`CommitBlob::keys`), else with
//! the read roles secrets it holds of the things up the thing's record chain. A thing whose path
//! opens to a bad list, or opens nowhere here, has its parts judged invalid (`View::paths`);
//! one opening nowhere here waits (`Wait`) and is opened again when a roles secret or a record
//! that may open it moves (`refresh`) or a late encryption brings its key (`atomic::join_late`).

use crate::engine::{Core, Decided, Tx};
use osis_base::Tid;
use osis_commit::{Header, ThingPath};
use std::collections::BTreeMap;
use std::sync::Arc;

/// The path commit header `h` states for the thing `t` at place `i`, opened here: under `key`
/// where an encryption carried it, else under the read roles secrets held of the things up `t`'s
/// record chain (`t` itself, its mint admin, …), newest first. `None`: nothing held is the key
/// the entry commits to. Every route gives that one key (`Split::open`), so which route or roles
/// secret found it changes nothing.
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

/// What this node decided of the path split commit header `h` states for each thing: its path,
/// `None` where bad; a thing whose path opens nowhere here yet is absent. `keys`: the path
/// keys its held encryptions carried. `None` where its path is in the clear (`View::paths`).
pub(crate) fn decided(core: &Core, h: &Header, keys: &BTreeMap<usize, [u8; 32]>) -> Option<Arc<Decided>> {
    if !h.is_split() {
        return None;
    }
    let out = h.things().into_iter().enumerate().filter_map(|(i, t)| Some((t, known(open(core, h, keys.get(&i), i, &t)?)))).collect();
    Some(Arc::new(out))
}

/// An opened entry as `Decided` keeps it.
fn known(p: ThingPath) -> Option<osis_commit::Path> {
    match p {
        ThingPath::Known(p) => Some(p),
        ThingPath::Bad => None,
    }
}

/// Whether a split commit's view leaves a thing undecided (`decided`).
pub(crate) fn undecided(h: &Header, paths: Option<&Decided>) -> bool {
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
/// a rollback and an open rebuilding the index build it again from `paths_unknown`, trying each
/// commit there once (what moved since its view was decided is unknown: a rollback may come
/// between a commit's judging and a roles secret's arrival); an open from the persisted index
/// takes each as tried (`follow_loaded`).
#[derive(Clone)]
pub(crate) struct Wait {
    fx: osis_base::memo::Effects<osis_base::CommitId, Openers>,
    /// `paths_unknown`'s additions since: followed, and tried at their first settle.
    added: osis_base::memo::Feed<osis_base::CommitId>,
}

impl Wait {
    /// Following every commit in `paths_unknown`, none settled yet.
    fn new(core: &Core) -> Wait {
        let mut fx = osis_base::memo::Effects::new("paths: wait");
        for id in core.ix.paths_unknown.iter() {
            fx.want(*id);
        }
        Wait { fx, added: core.ix.paths_unknown.feed() }
    }
}

/// An open from the persisted index: the wait follows each commit in `paths_unknown` as tried,
/// its view decided against what the store holds with it (no wake was missed at a durable
/// transaction's end: `missed`). Decodes no header.
pub(crate) fn follow_loaded(tx: &mut Tx<'_>) {
    let mut w = Wait::new(tx.core);
    let core: &Core = tx.core;
    for id in w.fx.due() {
        w.fx.settle(&id, || openers(core, &id));
    }
    tx.core.paths_wait = Some(w);
}

/// Opens again the paths of the held split commits waiting in `Indexes::paths_unknown` whose
/// openers moved (`Wait`): where more are decided, a commit's view takes them and its parts are
/// judged again. Such a thing has no key held (a held part carries its own), so only roles
/// secrets are tried. Costs the commits whose openers moved, never the commits waiting (but
/// each once where the wait is built again).
pub(crate) fn refresh(tx: &mut Tx<'_>) {
    let mut w = tx.core.paths_wait.take().unwrap_or_else(|| Wait::new(tx.core));
    for id in w.added.added() {
        if tx.core.ix.paths_unknown.contains(&id) {
            w.fx.want(id);
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
        // tried at its first settle (followed anew) and whenever its openers move
        if moved.is_some() {
            reopen(tx, &id);
            if !tx.core.ix.paths_unknown.contains(&id) {
                w.fx.unwant(&id);
            }
        }
    }
    tx.core.paths_wait = Some(w);
}

/// Debug builds, after every durable transaction and at an engine's drop: no wake of the wait was
/// missed. No thing of a commit waiting in `Indexes::paths_unknown` has an entry a fresh attempt
/// with what is held now opens. `Some`: the first that does.
#[cfg(debug_assertions)]
pub(crate) fn missed(tx: &mut Tx<'_>) -> crate::Result<Option<String>> {
    let core: &Core = tx.core;
    for id in core.ix.paths_unknown.iter() {
        let Some(m) = core.ix.commits.get(id) else { return Ok(Some(format!("{id:?} waits, not held"))) };
        let h = m.header.clone();
        let known = m.view.paths.as_deref();
        for (i, t) in h.things().into_iter().enumerate() {
            if known.is_some_and(|p| !p.contains_key(&t))
                && let Some(p) = open(core, &h, None, i, &t)
            {
                return Ok(Some(format!("{id:?} waits on {t:?}, whose entry opens to {p:?}")));
            }
        }
    }
    Ok(None)
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
            now.insert(t, known(p));
        }
    }
    if now.len() != before {
        set_paths(tx, id, Some(Arc::new(now)));
    }
}

/// Commit `id`'s view with the paths decided here `paths`: its parts judged again, and it leaves
/// `Indexes::paths_unknown` once none is undecided.
pub(crate) fn set_paths(tx: &mut Tx<'_>, id: &osis_base::CommitId, paths: Option<Arc<Decided>>) {
    let Some(mut m) = tx.core.ix.commits.get(id).cloned() else { return };
    if !undecided(&m.header, paths.as_deref()) {
        tx.core.ix.paths_unknown.remove(id);
    }
    m.view = Arc::new(crate::engine::View { paths, ..(*m.view).clone() });
    let h = m.header.clone();
    tx.core.update_timelines();
    let v = (0..m.parts()).map(|ai| crate::apply::validity::part_valid(tx.core, &h, &m.view, id, ai)).collect();
    m.set_valid(v);
    tx.core.put_meta(*id, m);
    tx.core.index_validity(id);
    tx.core.stale_commits.insert(*id);
    tx.core.ix.held.touch_commit(*id);
}
