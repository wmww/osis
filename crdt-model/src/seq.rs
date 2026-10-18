//! Linearization of a sequence state (spec §6).
use crate::stamp::{Dot, Source};
use crate::state::{Anchor, Content, SeqElem};
use std::collections::{BTreeMap, BTreeSet, HashMap};

#[derive(Clone, Debug, PartialEq, Eq)]
enum Cand {
    Real(Anchor),
    End,
}

/// Order of elements that are not deleted (§5.7: text by flag, list by absent content).
pub fn linearize(elems: &BTreeMap<Dot, SeqElem>, text: bool) -> Vec<Dot> {
    linearize_full(elems).0.into_iter().filter(|d| !elems[d].is_deleted(text)).collect()
}

/// Order of every placed element (deleted ones included) and each element's chosen parent
/// (`None` = HEAD or END), after cycle breaking (§6.2). Hidden elements (unknown anchor) are absent.
///
/// An anchor naming a `Derived` dot that is not in the state counts as a bare anchor at END (§6.1): such records
/// exist only while they carry a write (§4.7), but every node knows the dot from the delta's `Sources`.
pub fn linearize_full(elems: &BTreeMap<Dot, SeqElem>) -> (Vec<Dot>, HashMap<Dot, Option<Dot>>) {
    let virtual_anchors: BTreeSet<Dot> = elems
        .values()
        .flat_map(|e| e.pos.iter().map(|p| &p.1))
        .filter_map(|a| match a {
            Anchor::Dot(d) if matches!(d.source, Source::Derived(_)) && !elems.contains_key(d) => Some(d.clone()),
            _ => None,
        })
        .collect();
    if virtual_anchors.is_empty() {
        return linearize_known(elems);
    }
    let mut full = elems.clone();
    for d in &virtual_anchors {
        full.insert(d.clone(), SeqElem::write(Content::None, vec![], None));
    }
    let (order, mut parents) = linearize_known(&full);
    for d in &virtual_anchors {
        parents.remove(d);
    }
    (order.into_iter().filter(|d| !virtual_anchors.contains(d)).collect(), parents)
}

fn linearize_known(elems: &BTreeMap<Dot, SeqElem>) -> (Vec<Dot>, HashMap<Dot, Option<Dot>>) {
    // candidate index per element: 0 = cur, 1 = prev, 2 = END
    let mut cand: HashMap<&Dot, usize> = elems.keys().map(|d| (d, 0)).collect();
    let chosen = |d: &Dot, ci: usize| -> Cand {
        let el = &elems[d];
        match el.pos.get(ci) {
            Some((_, a)) => match a {
                Anchor::Head => Cand::Real(Anchor::Head),
                Anchor::Dot(x) if elems.contains_key(x) => Cand::Real(Anchor::Dot(x.clone())),
                // unknown anchor: hidden on the cur slot, END on the prev slot (§6.2 step 3)
                Anchor::Dot(_) if ci == 0 => Cand::Real(a.clone()),
                Anchor::Dot(_) => Cand::End,
            },
            None => Cand::End,
        }
    };
    loop {
        // parent map over elements with a known anchor
        let parent: HashMap<&Dot, Option<&Dot>> = elems
            .keys()
            .filter_map(|d| match chosen(d, cand[d]) {
                Cand::Real(Anchor::Head) | Cand::End => Some((d, None)),
                Cand::Real(Anchor::Dot(x)) => elems.get_key_value(&x).map(|(k, _)| (d, Some(k))),
            })
            .collect();
        // find a cycle by walking parents
        let mut cycle: Option<Vec<&Dot>> = None;
        let mut state: HashMap<&Dot, u8> = HashMap::new(); // 1 visiting, 2 done
        'outer: for start in parent.keys() {
            if state.contains_key(start) {
                continue;
            }
            let mut path: Vec<&Dot> = Vec::new();
            let mut cur: &Dot = start;
            loop {
                match state.get(cur) {
                    Some(2) => break,
                    Some(1) => {
                        let i = path.iter().position(|x| *x == cur).unwrap();
                        cycle = Some(path[i..].to_vec());
                        break 'outer;
                    }
                    _ => {}
                }
                state.insert(cur, 1);
                path.push(cur);
                match parent.get(cur) {
                    Some(Some(p)) if parent.contains_key(p) => cur = p,
                    _ => break,
                }
            }
            for d in path {
                state.insert(d, 2);
            }
        }
        match cycle {
            None => break,
            Some(cyc) => {
                // demote the element whose current edge has the smallest stamp and still has a next candidate
                let victim = cyc
                    .iter()
                    .filter(|d| cand[*d] < 2)
                    .min_by_key(|d| elems[*d].pos.get(cand[*d]).map(|p| p.0.clone()))
                    .copied()
                    .expect("END always available");
                let next = if cand[victim] == 0 && elems[victim].pos.len() > 1 { 1 } else { 2 };
                cand.insert(victim, next);
            }
        }
    }
    // build children lists
    let mut children: HashMap<Option<&Dot>, Vec<(&Dot, usize)>> = HashMap::new();
    let mut ends: Vec<&Dot> = Vec::new();
    for d in elems.keys() {
        match chosen(d, cand[d]) {
            Cand::End => ends.push(d),
            Cand::Real(Anchor::Head) => children.entry(None).or_default().push((d, cand[d])),
            Cand::Real(Anchor::Dot(x)) => match elems.get_key_value(&x) {
                Some((k, _)) => children.entry(Some(k)).or_default().push((d, cand[d])),
                None => {} // hidden
            },
        }
    }
    for v in children.values_mut() {
        v.sort_by(|a, b| elems[b.0].pos[b.1].0.cmp(&elems[a.0].pos[a.1].0)); // greatest first
    }
    ends.sort();
    let mut out = Vec::new();
    let mut stack: Vec<&Dot> = Vec::new();
    // END elements come last: push them (reversed) first so they pop after HEAD's subtrees
    for d in ends.iter().rev() {
        stack.push(*d);
    }
    if let Some(cs) = children.get(&None) {
        for (c, _) in cs.iter().rev() {
            stack.push(*c);
        }
    }
    let mut seen: BTreeSet<&Dot> = BTreeSet::new();
    let mut parents: HashMap<Dot, Option<Dot>> = HashMap::new();
    while let Some(d) = stack.pop() {
        if !seen.insert(d) {
            continue;
        }
        out.push(d.clone());
        let p = match chosen(d, cand[d]) {
            Cand::Real(Anchor::Dot(x)) => Some(x),
            _ => None,
        };
        parents.insert(d.clone(), p);
        if let Some(cs) = children.get(&Some(d)) {
            for (c, _) in cs.iter().rev() {
                stack.push(*c);
            }
        }
    }
    (out, parents)
}
