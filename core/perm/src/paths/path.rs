//! A part's members and hops (draft §1 Path), in thing tids: one definition read by the walk
//! (which interns the edges) and by content.

use osis_base::format::{MAX_CHAIN_DEPTH, PathMarks};
use osis_base::Tid;
use std::collections::{BTreeMap, BTreeSet};

/// What a part's stated path gives it to rest on.
#[derive(Clone, Debug, Default)]
pub(crate) struct Shape {
    /// Its members name no thing twice, its marks are valid, an edge-class part is not on its own
    /// signer, and its signer's key hop stands (the signer's record names no mint admin).
    pub well: bool,
    /// An edge write whose path ends at the holder of the edge it sets: a self-removal.
    pub leave: bool,
    /// Its path's edges (holder, target) in order; none where not `well`.
    pub hops: Vec<(Tid, Tid)>,
}

/// The edges joining consecutive members `p`, `q` (draft §1 Hops): the record edges from `p`
/// down to `q` where `p` is on `q`'s record chain, else their direct edge.
pub(crate) fn joins(mint: &BTreeMap<Tid, Tid>, p: Tid, q: Tid) -> Vec<(Tid, Tid)> {
    let mut down = vec![];
    let mut t = q;
    while let Some(&m) = mint.get(&t) {
        down.push((m, t));
        if m == p {
            down.reverse();
            return down;
        }
        if down.len() >= MAX_CHAIN_DEPTH {
            break;
        }
        t = m;
    }
    vec![(p, q)]
}

/// The shape of a part by `signer` on `on` along `path` marking the hops `direct`; `holder` for
/// an edge write. Members are [S, A1..Ak, T]; a self-removal's end at its holder; content by a
/// key actor on itself (`on` the signer, the empty path) has the members [S] and no hop. An
/// edge-class part on its own signer is bad input: no edge write targets a key actor
/// (spec/permissions.md §1 Key actor); an edge write whose holder is its target is not applied
/// (§1). A hop marked direct is its pair's direct edge; a mark on a
/// hop not otherwise read as a descent of two steps or more, or past the members, leaves the part
/// not `well` (draft §1 Path, Direct mark).
///
/// Interim (issues/perm-walk-trails-model.md): the walk keeps no key grant until A4, so the key
/// hop stands at admin where the signer's record holds its key (names no mint admin) and gives
/// nothing elsewhere: a part signed as a thing with a mint admin is not `well`.
pub(crate) fn shape(mint: &BTreeMap<Tid, Tid>, signer: Tid, path: &[Tid], direct: PathMarks, on: Tid, holder: Option<Tid>, edge_class: bool) -> Shape {
    let ak = *path.last().unwrap_or(&signer);
    let leave = holder.is_some_and(|h| h == ak);
    let marked = |j: usize| j < PathMarks::BITS as usize && direct >> j & 1 == 1;
    if mint.contains_key(&signer) {
        return Shape { well: false, leave, hops: vec![] };
    }
    if !edge_class && on == signer && path.is_empty() && direct == 0 {
        return Shape { well: true, leave: false, hops: vec![] };
    }
    let mut members = vec![signer];
    members.extend(path);
    if !leave {
        members.push(on);
    }
    let mut well = members.iter().collect::<BTreeSet<_>>().len() == members.len() && !(edge_class && on == signer) && holder != Some(on);
    // no mark past the hops
    well &= (members.len() - 1..PathMarks::BITS as usize).all(|j| !marked(j));
    let mut hops = vec![];
    for (j, pair) in members.windows(2).enumerate() {
        if let [a, b] = pair {
            let down = joins(mint, *a, *b);
            if !marked(j) {
                hops.extend(down);
            } else if down.len() >= 2 {
                hops.push((*a, *b));
            } else {
                well = false;
            }
        }
    }
    if !well {
        return Shape { well, leave, hops: vec![] };
    }
    Shape { well, leave, hops }
}
