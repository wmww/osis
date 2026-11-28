//! A part's members and hops (spec/permissions.md §1 Path): one definition read by the walk
//! (which interns the grants) and by content.

use osis_base::format::{MAX_CHAIN_DEPTH, PathMarks};
use osis_base::{Holder, SignKey, Tid};
use std::collections::{BTreeMap, BTreeSet};

/// What a part's stated path gives it to rest on.
#[derive(Clone, Debug, Default)]
pub(crate) struct Shape {
    /// Its members name no thing twice, its marks are valid, and a grant write's holder is not
    /// its target.
    pub well: bool,
    /// A self-removal: a grant write whose path ends at the holder of the grant it sets, or a key
    /// lowering its own grant on the thing it signs as, acting as that thing.
    pub leave: bool,
    /// What it rests on in order: its key hop (key, signer), then its path's grants; none where
    /// not `well`, and none for a key lowering its own grant (it rests on that grant alone).
    pub hops: Vec<(Holder, Tid)>,
}

/// The grants joining consecutive members `p`, `q` (spec/permissions.md §1 Hops): the record grants
/// from `p` down to `q` where `p` is on `q`'s record chain, else their direct grant. A record
/// holding a key ends the chain.
pub(crate) fn joins(mint: &BTreeMap<Tid, Holder>, p: Tid, q: Tid) -> Vec<(Holder, Tid)> {
    let mut down = vec![];
    let mut t = q;
    while let Some(&Holder::Thing(m)) = mint.get(&t) {
        down.push((Holder::Thing(m), t));
        if m == p {
            down.reverse();
            return down;
        }
        if down.len() >= MAX_CHAIN_DEPTH {
            break;
        }
        t = m;
    }
    vec![(Holder::Thing(p), q)]
}

/// The shape of a part signed by `key` as `signer` on `on` along `path` marking the hops
/// `direct`; `holder` for a grant write (spec/permissions.md §1 Path). Members are
/// [S, A1..Ak, T]; [S] where S acts as itself (T is S, nothing listed); a self-removal's end at its
/// holder. A key's grant on S written by that key acting as S is its self-removal: it states no
/// hop. Every other part rests on its key hop (key, S) first, then each consecutive pair's
/// joining grants. A hop marked direct is its pair's direct grant; a mark on a hop not otherwise
/// read as a descent of two steps or more, or past the members, leaves the part not `well`
/// (Direct mark), as does a member named twice or a grant write whose holder is its target.
#[allow(clippy::too_many_arguments)]
pub(crate) fn shape(mint: &BTreeMap<Tid, Holder>, key: SignKey, signer: Tid, path: &[Tid], direct: PathMarks, on: Tid, holder: Option<Holder>, grant_class: bool) -> Shape {
    let itself = path.is_empty() && on == signer;
    let own_hop = grant_class && itself && holder == Some(Holder::Key(key));
    let last = *path.last().unwrap_or(&signer);
    let leave = own_hop || holder == Some(Holder::Thing(last));
    let marked = |j: usize| j < PathMarks::BITS as usize && direct >> j & 1 == 1;
    let mut members = vec![signer];
    members.extend(path);
    if !leave && !itself {
        members.push(on);
    }
    let mut well = members.iter().collect::<BTreeSet<_>>().len() == members.len() && holder != Some(Holder::Thing(on));
    // no mark past the hops
    well &= (members.len() - 1..PathMarks::BITS as usize).all(|j| !marked(j));
    // Invariant: every part but a key's lowering of its own grant rests on its key hop first, so
    // a key holding no grant on S (a stranger's, one removed, one never granted) gives nothing as
    // S whatever path it states (`hand_content::a_key_hop_is_an_grant_like_any`). The key is the
    // one that signed: the caller hands the key the commit's signature was checked against.
    let mut hops = vec![(Holder::Key(key), signer)];
    for (j, pair) in members.windows(2).enumerate() {
        if let [a, b] = pair {
            let down = joins(mint, *a, *b);
            if !marked(j) {
                hops.extend(down);
            } else if down.len() >= 2 {
                hops.push((Holder::Thing(*a), *b));
            } else {
                well = false;
            }
        }
    }
    if !well || own_hop {
        hops.clear();
    }
    Shape { well, leave, hops }
}
