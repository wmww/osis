//! Deleting by link (issues/chunk-list-in-tree.md, step 0): the freed judgment over random small
//! worlds (reuse across authors and epochs, two labels, forged cross-thing links, false Del,
//! nodes lacking node blobs), drops interleaved with judging, and scripted cases.
use held_model::freed::*;
use held_model::gen::Rng;
use std::collections::BTreeSet;

/// Drops, and bodies held again (fetched again, or arriving anew), interleaved with freed-set
/// steps until nothing moves; checks at every accepted delete that no source the deleter holds
/// of the piece's thing reaches it (P1) and that the blob bears the key under the thing it was
/// signed for (P3). A body held again while its links wait is what judging at the drop, rather
/// than when the delete is sent, gets wrong.
fn run(w: &mut World, rng: &mut Rng, drops: &mut Vec<(usize, usize)>) {
    let mut again = Vec::new();
    loop {
        let pending: Vec<(usize, Thing, Link)> = w.nodes.iter().enumerate().flat_map(|(n, s)| s.freed.iter().map(move |(t, l)| (n, *t, l.clone()))).collect();
        if !drops.is_empty() && (pending.is_empty() || rng.chance(30)) {
            let (n, s) = drops.remove(rng.below(drops.len() as u64) as usize);
            w.drop_source(n, s);
            if rng.chance(25) {
                again.push((n, s));
            }
            continue;
        }
        if !again.is_empty() && rng.chance(20) {
            let (n, s) = again.remove(rng.below(again.len() as u64) as usize);
            w.nodes[n].held.insert(s);
            continue;
        }
        let before = w.deleted.len();
        let mut moved = false;
        for (n, t, l) in pending {
            if !w.nodes[n].freed.contains(&(t, l.clone())) {
                continue;
            }
            let reach = w.held_reach(n, t);
            let k = w.deleted.len();
            moved |= w.step(n, t, &l) != Step::Waits;
            for d in &w.deleted[k..] {
                assert!(!reach.contains(&d.piece), "P1: node {n} deleted piece {} a held source of thing {t} reaches", d.piece);
                let p = &w.pieces[d.piece];
                assert!(p.thing == d.thing && p.group.contains(&d.key), "P3: a delete through a link its blob does not bear");
            }
        }
        if !moved && drops.is_empty() && again.is_empty() {
            break;
        }
        let _ = before;
    }
}

/// P2: once settled, a piece no node's held source of its thing reaches is gone, under each
/// label, wherever a node that held a source reaching it (`before`: per node, the (thing, piece)
/// pairs its sources reached at the start) and has nothing left waiting holds that label's key and
/// a key the blob bears that its links named.
fn check_gone(w: &World, before: &[BTreeSet<(Thing, Pid)>]) {
    for (pid, p) in w.pieces.iter().enumerate() {
        let reached = (0..w.nodes.len()).any(|n| w.held_reach(n, p.thing).contains(&pid));
        if reached {
            continue;
        }
        for (n, s) in w.nodes.iter().enumerate() {
            if !before[n].contains(&(p.thing, pid)) || !s.freed.is_empty() {
                continue;
            }
            for g in &w.labels[&p.thing] {
                if !s.labels.contains(g) || !w.entries.contains(&(*g, pid)) {
                    continue;
                }
                // a key its link named, it holds and the blob bears: walked links of it
                let links: Vec<&Link> = w.sources.iter().flat_map(|src| src.links.iter()).chain(w.pieces.iter().flat_map(|q| q.kids.iter())).filter(|l| l.piece == pid).collect();
                let could = links.iter().any(|l| l.del.iter().any(|k| s.keys.contains(k) && p.group.contains(k)));
                // only honest links (Del as the blob bears) promise the delete
                let honest = links.iter().all(|l| l.del.iter().copied().collect::<BTreeSet<_>>() == p.group);
                assert!(!(could && honest), "P2: piece {pid} of thing {} freed everywhere, walked by node {n} with the right, still under label {g}", p.thing);
            }
        }
    }
}

// Random worlds: every node drops a random subset of what it holds.
#[test]
fn freed_judgment_random_worlds() {
    let mut deletes = 0;
    let mut waits = 0;
    let mut forged = 0;
    for seed in 0..3000 {
        let (mut w, mut rng) = world(seed);
        let before: Vec<BTreeSet<(Thing, Pid)>> = (0..w.nodes.len()).map(|n| [1, 2].into_iter().flat_map(|t| w.held_reach(n, t).into_iter().map(move |p| (t, p))).collect()).collect();
        let mut drops = Vec::new();
        for (n, s) in w.nodes.iter().enumerate() {
            for src in &s.held {
                if rng.chance(60) {
                    drops.push((n, *src));
                }
            }
        }
        run(&mut w, &mut rng, &mut drops);
        check_gone(&w, &before);
        deletes += w.deleted.len();
        waits += w.nodes.iter().map(|s| s.freed.len()).sum::<usize>();
        forged += w.sources.iter().filter(|s| s.links.iter().any(|l| w.pieces[l.piece].thing != s.thing)).count();
    }
    // the generator reaches deletes, waiting judgments and forged links
    assert!(deletes > 1000 && waits > 0 && forged > 50, "coverage: {deletes} deletes, {waits} waits, {forged} forged");
}

fn piece(w: &mut World, thing: Thing, group: &[DelKey], kids: Vec<Link>) -> Link {
    let id = w.pieces.len();
    w.pieces.push(Piece { thing, group: group.iter().copied().collect(), kids });
    for g in w.labels[&thing].clone() {
        w.entries.insert((g, id));
    }
    Link { piece: id, del: group.to_vec() }
}

fn base() -> World {
    let mut w = World::default();
    w.labels.insert(1, vec![1, 2]);
    w.labels.insert(2, vec![1]);
    w
}

fn node(w: &World, held: &[usize], keys: &[DelKey], labels: &[LabelId]) -> NodeState {
    let mut s = NodeState { held: held.iter().copied().collect(), keys: keys.iter().copied().collect(), labels: labels.iter().copied().collect(), ..Default::default() };
    s.blobs = w.pieces.iter().enumerate().filter(|(_, p)| !p.kids.is_empty()).map(|(i, _)| i).collect();
    s
}

// Two authors: the second reuses the first's chunk under a new node; dropping the first body
// deletes its node, keeps the shared chunk; dropping the second then deletes the rest, the chunk
// by the first author's Del.
#[test]
fn reuse_by_another_author_keeps_the_piece_while_a_held_body_links_it() {
    let mut w = base();
    let a = [(1, 10), (2, 100)];
    let b = [(1, 10), (2, 101)];
    let c = piece(&mut w, 1, &a, vec![]);
    let n1 = piece(&mut w, 1, &a, vec![c.clone()]);
    let n2 = piece(&mut w, 1, &b, vec![c.clone()]);
    w.sources = vec![Source { thing: 1, links: vec![n1] }, Source { thing: 1, links: vec![n2] }];
    w.nodes = vec![node(&w, &[0, 1], &[(1, 10)], &[1, 2])];
    w.drop_source(0, 0);
    w.settle(&mut Rng::new(1));
    assert!(w.entries.contains(&(1, c.piece)) && !w.entries.contains(&(1, 1)) && w.entries.contains(&(1, 2)));
    w.drop_source(0, 1);
    w.settle(&mut Rng::new(1));
    assert!(w.entries.is_empty(), "{:?}", w.entries);
}

// A body dropped and held again before its links' deletes are sent keeps its pieces: the link
// is judged when its delete is sent, not at the drop.
#[test]
fn body_held_again_before_the_delete_keeps_its_pieces() {
    let mut w = base();
    let k = [(1, 10)];
    let c = piece(&mut w, 1, &k, vec![]);
    let n = piece(&mut w, 1, &k, vec![c.clone()]);
    w.sources = vec![Source { thing: 1, links: vec![n.clone()] }];
    w.nodes = vec![node(&w, &[0], &[(1, 10)], &[1, 2])];
    w.drop_source(0, 0);
    w.nodes[0].held.insert(0);
    w.settle(&mut Rng::new(1));
    assert_eq!(w.entries.len(), 4, "{:?}", w.entries);
    assert!(w.nodes[0].freed.is_empty());
}

// A writer of thing 1 links thing 2's chunk: dropping its body deletes nothing of thing 2, and
// holding it keeps nothing of thing 2 alive.
#[test]
fn forged_cross_thing_link_deletes_and_keeps_nothing() {
    let mut w = base();
    let k2 = [(1, 20)];
    let c = piece(&mut w, 2, &k2, vec![]);
    w.entries.insert((2, c.piece)); // uploaded under thing 1's other label too
    w.sources = vec![Source { thing: 2, links: vec![c.clone()] }, Source { thing: 1, links: vec![c.clone()] }];
    w.nodes = vec![node(&w, &[0, 1], &[(1, 20)], &[1, 2])];
    w.drop_source(0, 1);
    w.settle(&mut Rng::new(1));
    assert!(w.entries.contains(&(1, c.piece)), "forged link deleted the piece");
    w.drop_source(0, 0);
    w.nodes[0].held.insert(1); // the forged body held again: keeps nothing of thing 2
    w.settle(&mut Rng::new(1));
    assert!(!w.entries.contains(&(1, c.piece)));
    assert!(w.entries.contains(&(2, c.piece)), "no thing-2 commitment under thing 1's label: stays (junk a writer could upload anyway)");
}

// Thing 1 under labels 1 and 2: a node holding label 1 only deletes label 1's entry; label 2's
// stays until a holder of label 2 walks it.
#[test]
fn delete_is_per_label_entry() {
    let mut w = base();
    let k = [(1, 10)];
    let c = piece(&mut w, 1, &k, vec![]);
    w.sources = vec![Source { thing: 1, links: vec![c.clone()] }];
    w.nodes = vec![node(&w, &[0], &[(1, 10)], &[1]), node(&w, &[0], &[(1, 10)], &[2])];
    w.drop_source(0, 0);
    w.settle(&mut Rng::new(1));
    assert_eq!(w.entries, BTreeSet::from([(2, c.piece)]));
    w.drop_source(1, 0);
    w.settle(&mut Rng::new(1));
    assert!(w.entries.is_empty());
}

// A deleter lacking a freed node fetches it, then deletes below it; with no copy anywhere its
// subtree waits.
#[test]
fn deleter_missing_a_node_fetches_it_or_waits() {
    let mut w = base();
    let k = [(1, 10)];
    let c = piece(&mut w, 1, &k, vec![]);
    let n = piece(&mut w, 1, &k, vec![c.clone()]);
    w.sources = vec![Source { thing: 1, links: vec![n.clone()] }];
    let mut s = node(&w, &[0], &[(1, 10)], &[1, 2]);
    s.blobs.clear();
    w.nodes = vec![s];
    let mut lost = w.clone();
    w.drop_source(0, 0);
    w.settle(&mut Rng::new(1));
    assert!(w.entries.is_empty(), "fetched from the host, then deleted");
    // every copy of the node gone: the chunk below it stays, the link waits
    lost.entries.retain(|e| e.1 != n.piece);
    lost.drop_source(0, 0);
    lost.settle(&mut Rng::new(1));
    assert!(lost.entries.contains(&(1, c.piece)) && lost.nodes[0].freed.len() == 1);
}
