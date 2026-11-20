//! A part's members and hops (draft §1 Path), in thing tids: one definition read by the walk
//! (which interns the edges) and by content.

use osis_base::format::MAX_CHAIN_DEPTH;
use osis_base::Tid;
use std::collections::{BTreeMap, BTreeSet};

/// What a part's stated path gives it to rest on.
#[derive(Clone, Debug, Default)]
pub(crate) struct Shape {
    /// Its members name no thing twice (and an edge-class part is not on its own signer).
    pub well: bool,
    /// An edge write whose path ends at the holder of the edge it sets: a self-removal.
    pub leave: bool,
    /// Its path's edges (holder, target) in order; none where not `well`.
    pub hops: Vec<(Tid, Tid)>,
    /// The final hop where it joins Ak (the signer for an empty path) to the thing in one edge
    /// (draft §1 Path's last edge); none for a self-removal.
    pub last: Option<(Tid, Tid)>,
    /// The final edge of the hops joining Ak to the thing (read by the order within a commit).
    pub final_hop: Option<(Tid, Tid)>,
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

/// The shape of a part by `signer` on `on` along `path`; `holder` for an edge write. Members are
/// [S, A1..Ak, T]; a self-removal's end at its holder; content by a key actor on itself (`on` the
/// signer, the empty path) has the members [S] and no hop. An edge-class part on its own signer
/// is bad input: no edge write or vouch targets a key actor (spec/permissions.md §1 Key actor).
pub(crate) fn shape(mint: &BTreeMap<Tid, Tid>, signer: Tid, path: &[Tid], on: Tid, holder: Option<Tid>, edge_class: bool) -> Shape {
    let ak = *path.last().unwrap_or(&signer);
    let leave = holder.is_some_and(|h| h == ak);
    let final_hop = joins(mint, ak, on).last().copied();
    if !edge_class && on == signer && path.is_empty() {
        return Shape { well: true, leave: false, hops: vec![], last: None, final_hop };
    }
    let mut members = vec![signer];
    members.extend(path);
    if !leave {
        members.push(on);
    }
    let well = members.iter().collect::<BTreeSet<_>>().len() == members.len() && !(edge_class && on == signer);
    if !well {
        return Shape { well, leave, hops: vec![], last: None, final_hop };
    }
    let mut hops = vec![];
    for pair in members.windows(2) {
        if let [a, b] = pair {
            hops.extend(joins(mint, *a, *b));
        }
    }
    let last = hops.last().copied().filter(|&l| l == (ak, on) && !leave);
    Shape { well, leave, hops, last, final_hop }
}
