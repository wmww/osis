//! Holder access (notes/holder-access-study.md, The model), held_model::closure::keys:
//! properties (i) to (v) and the fixpoint's own over an exhaustive small family and random
//! histories, for the design and each control; the hand worlds. spec: none (modelled before any
//! spec).
use crate::util::{env, par_map};
use held_model::closure::keys::*;
use held_model::closure::{Role, Set, T};
use held_model::gen::Rng;
use std::collections::{BTreeMap, BTreeSet};
use Role::*;

/// The account: the node's one own actor.
const ME: T = 0;

fn set(xs: &[T]) -> Set {
    xs.iter().copied().collect()
}
fn me() -> Set {
    set(&[ME])
}

/// A world as written: grants in the order made (those in `outside` from outside their holder),
/// the holders taking grants from outside, strongs inside things and root strongs.
#[derive(Clone, Debug, Default)]
struct Spec {
    things: usize,
    grants: Vec<(T, T, Role)>,
    outside: Vec<(T, T)>,
    grantable: Vec<T>,
    strongs: Vec<(T, T)>,
    roots: Vec<T>,
}

fn build(s: &Spec, perm: &dyn Fn(T) -> T) -> (Keys, Node) {
    let mut k = Keys::new(s.things);
    for &h in &s.grantable {
        k.set_grantable(perm(h), true);
    }
    for &(g, t, r) in &s.grants {
        let from = if s.outside.contains(&(g, t)) { From::Outside } else { From::Writer };
        k.grant_from(perm(g), perm(t), r, from);
    }
    for &(a, b) in &s.strongs {
        k.strong(perm(a), perm(b));
    }
    let mut n = Node::new(&me());
    n.roots = s.roots.iter().map(|&t| perm(t)).collect();
    (k, n)
}
fn id(x: T) -> T {
    x
}
fn map_set(s: &Set, p: &dyn Fn(T) -> T) -> Set {
    s.iter().map(|&x| p(x)).collect()
}
fn map_seen(s: &Seen, p: &dyn Fn(T) -> T) -> Seen {
    let mut o = Seen::default();
    let (a, b) = (&s.closure, &mut o.closure);
    (b.read, b.stored, b.held, b.carried, b.keys, b.synced, b.for_keys) =
        (map_set(&a.read, p), map_set(&a.stored, p), map_set(&a.held, p), map_set(&a.carried, p), map_set(&a.keys, p), map_set(&a.synced, p), map_set(&a.for_keys, p));
    o.roles = s.roles.iter().map(|(&t, &r)| (p(t), r)).collect();
    o
}
/// What a user observes of a node: what it reads, keeps and may do.
fn shows(s: &Seen) -> (&Set, &Set, &Set, &BTreeMap<T, Role>) {
    (&s.closure.read, &s.closure.stored, &s.closure.held, &s.roles)
}

const P1: Rule = Rule::DESIGN;
const EVERY: Rule = Rule { taking: Taking::Every, ..P1 };

/// The design, then the controls.
fn variants() -> Vec<(&'static str, Rule)> {
    vec![
        ("design", P1),
        ("control held edges", Rule { roles: RolesBy::HeldEdges, ..P1 }),
        ("control every grant", EVERY),
        ("control chosen path", Rule { paths: Paths::Chosen, ..P1 }),
        ("control whole boxes", Rule { boxes: Boxes::Whole, ..P1 }),
    ]
}

/// A grant written from outside its holder, the world without it, and the holder enabling it.
struct Flip {
    edge: (T, T),
    untaken: Keys,
    without: Keys,
    enabled: Keys,
}

/// A world with what every variant is checked against: the oracle, the same world relabelled,
/// each grant flipped to come from outside, grants of another thing's on no path (taken, and
/// from outside not taken), each revocation with the oracle after it.
struct Case {
    things: usize,
    k: Keys,
    node: Node,
    want: Seen,
    relabelled: (Keys, Node, Seen),
    flips: Vec<Flip>,
    off_path: Vec<(Keys, Keys)>,
    revoked: Vec<((T, T), Keys, Seen)>,
}

fn relabel(things: usize) -> impl Fn(T) -> T {
    move |x: T| if x == ME { ME } else { x % (things - 1) + 1 }
}

fn case(s: &Spec) -> Case {
    let (k, node) = build(s, &id);
    let want = oracle(&k, &me(), &node.roots);
    let synced = want.synced();
    let (kp, np) = build(s, &relabel(s.things));
    let wantp = oracle(&kp, &me(), &np.roots);
    let mut flips = vec![];
    for (i, &(g, t, _)) in s.grants.iter().enumerate() {
        let mut o = s.clone();
        o.outside.push((g, t));
        let mut w = s.clone();
        w.grants.remove(i);
        let mut e = o.clone();
        e.grantable.push(g);
        flips.push(Flip { edge: (g, t), untaken: build(&o, &id).0, without: build(&w, &id).0, enabled: build(&e, &id).0 });
    }
    // (ii) a grant naming the account, a holder or a synced thing, on a thing on no path to a
    // synced thing: taken (its holder's writer's, the stated cost of reading lists), and from
    // outside, not taken
    let mut off_path = vec![];
    for &h in [ME].iter().chain(&want.closure.for_keys).chain(&synced) {
        for x in 1..s.things {
            if x == h || synced.contains(&x) || k.world.grants.contains_key(&(h, x)) {
                continue;
            }
            let (mut taken, mut outside) = (k.clone(), k.clone());
            taken.grant(h, x, Admin);
            outside.grant_from(h, x, Admin, From::Outside);
            if on_paths(&taken.keyed_edges(), &set(&[x]), &synced).1.is_empty() && oracle(&taken, &me(), &node.roots) == want {
                off_path.push((taken, outside));
            }
        }
    }
    let mut revoked = vec![];
    for &(g, t, _) in &s.grants {
        let mut k2 = k.clone();
        k2.revoke(g, t);
        // a keyless grant become a path may need more fetched: not this property's case
        if k2.keyed_edges().is_subset(&k.keyed_edges()) {
            let want2 = oracle(&k2, &me(), &node.roots);
            revoked.push(((g, t), k2, want2));
        }
    }
    Case { things: s.things, k, node, want, relabelled: (kp, np, wantp), flips, off_path, revoked }
}

fn key_items(n: &Node) -> BTreeSet<Item> {
    n.got.iter().copied().filter(|i| !matches!(i, Item::List(..))).collect()
}

/// The properties a world fails under `rule`, by name.
fn check(case: &Case, rule: &Rule) -> BTreeSet<&'static str> {
    let Case { things, k, want, .. } = case;
    let all = Source::all();
    let mut bad = BTreeSet::new();
    let mut n = case.node.clone();
    n.sync(k, rule, &all);
    if n.unsettled {
        bad.insert("settles");
    }
    // (i) roles and what is held are the oracle's: a function of strongs and chains
    if shows(&n.seen) != shows(want) {
        bad.insert("i roles");
    } else if n.seen.closure.for_keys != want.closure.for_keys {
        bad.insert("i for_keys");
    }
    // (i) whatever else it holds: a certificate of every grant not standing
    let mut c = case.node.clone();
    for a in 0..*things {
        for b in 1..*things {
            if a != b && !k.world.grants.contains_key(&(a, b)) {
                c.certs.insert((a, b), Admin);
            }
        }
    }
    c.sync(k, rule, &all);
    if c.seen != n.seen {
        bad.insert("i certificates");
    }
    // (i) under relabelling
    let perm = relabel(*things);
    let (kp, np, wantp) = &case.relabelled;
    let mut np = np.clone();
    np.sync(kp, rule, &all);
    if np.seen != map_seen(&n.seen, &perm) || *wantp != map_seen(want, &perm) {
        bad.insert("i relabel");
    }
    // (iii) nothing of a thing it does not sync but its key part
    let synced = want.synced();
    if n.got.iter().any(|i| matches!(i, Item::Content(x, _) if !synced.contains(x))) {
        bad.insert("iii content");
    }
    // a second sync fetches nothing
    let mut again = n.clone();
    again.sync(k, rule, &all);
    if again.got != n.got || again.seen != n.seen {
        bad.insert("settles");
    }
    // (v) a content change of what it does not sync downloads nothing
    let mut k2 = k.clone();
    for x in 1..*things {
        if !synced.contains(&x) {
            k2.edit(x);
        }
    }
    let mut n2 = n.clone();
    n2.sync(&k2, rule, &all);
    if n2.got != n.got {
        bad.insert("v content");
    }
    // (ii) a grant from outside its holder's admins did not enable is as if never written (but
    // as a roster entry of a thing read); enabled, it is a grant like a writer's
    for f in &case.flips {
        let mut u = case.node.clone();
        u.sync(&f.untaken, rule, &all);
        let mut w = case.node.clone();
        w.sync(&f.without, rule, &all);
        let roster = |i: &Item| matches!(*i, Item::Edge(h, x, _) if (h, x) == f.edge);
        if u.seen != w.seen {
            bad.insert("ii untaken roles");
        }
        if u.got.iter().filter(|i| !roster(i)).ne(w.got.iter().filter(|i| !roster(i))) {
            bad.insert("ii untaken fetch");
        }
        let mut e = case.node.clone();
        e.sync(&f.enabled, rule, &all);
        if e.seen != n.seen || e.got != n.got {
            bad.insert("ii enabled");
        }
    }
    // (ii) a taken grant on a thing on no path changes no role and no key part (its list entries
    // are the stated cost); the same from outside, not taken, changes nothing
    for (taken, outside) in &case.off_path {
        let mut t = case.node.clone();
        t.sync(taken, rule, &all);
        if t.seen != n.seen {
            bad.insert("ii roles");
        }
        if key_items(&t) != key_items(&n) {
            bad.insert("ii key parts");
        }
        let mut o = case.node.clone();
        o.sync(outside, rule, &all);
        if o.seen != n.seen || o.got != n.got {
            bad.insert("ii untaken fetch");
        }
    }
    // (iv) a path revoked: what stays writable is writable on hearing it, with no holder newly
    // opened (its sources: what it syncs and the key parts it held); a thing with no path left
    // loses its secrets
    let held = Source { units: Some(synced.clone()), parts: Some(want.closure.for_keys.union(&me()).copied().collect()) };
    for ((g, t), k2, want2) in &case.revoked {
        let (mut k2, mut n2) = (k2.clone(), n.clone());
        n2.hear(&k2, rule, *g, *t);
        for rotated in [false, true] {
            if rotated {
                k2.rotate_stale();
            }
            n2.sync(&k2, rule, &held);
            if want2.roles.iter().any(|(&x, &r)| r >= Write && want.roles.get(&x).is_some_and(|&r| r >= Write) && !n2.can_write(&k2, x)) {
                bad.insert("iv writable");
            }
            if n2.have.keys().any(|x| !n.have.contains_key(x)) {
                bad.insert("iv fetch outstanding");
            }
            if synced.iter().any(|x| !want2.roles.contains_key(x) && (n2.seen.synced().contains(x) || n2.have.contains_key(x) && !want2.closure.for_keys.contains(x))) {
                bad.insert("iv lost access");
            }
        }
        n2.sync(&k2, rule, &all);
        if shows(&n2.seen) != shows(want2) || n2.seen.closure.for_keys != want2.closure.for_keys {
            bad.insert("iv then the oracle's");
        }
        // (i) the node that was there before shows what one arriving now with its strongs shows
        let mut late = case.node.clone();
        late.sync(&k2, rule, &all);
        if late.seen != n2.seen {
            bad.insert("i as a late node");
        }
    }
    // the fixpoint: no strong, nothing held for keys
    let mut n3 = n.clone();
    n3.roots.clear();
    n3.sync(k, rule, &all);
    if !(n3.seen.closure.for_keys.is_empty() && n3.have.is_empty() && n3.edges.is_empty()) {
        bad.insert("fixpoint drop");
    }
    bad
}

/// Every set of at most `max` grants among the account and `things` things, each of `roles`.
fn grant_sets(things: usize, roles: &[Role], max: usize) -> Vec<Vec<(T, T, Role)>> {
    let cand: Vec<(T, T)> = (0..=things).flat_map(|a| (1..=things).filter(move |&b| b != a).map(move |b| (a, b))).collect();
    fn go(cand: &[(T, T)], roles: &[Role], max: usize, cur: &mut Vec<(T, T, Role)>, out: &mut Vec<Vec<(T, T, Role)>>) {
        let Some((&(a, b), rest)) = cand.split_first() else {
            out.push(cur.clone());
            return;
        };
        go(rest, roles, max, cur, out);
        if cur.len() < max {
            for &r in roles {
                cur.push((a, b, r));
                go(rest, roles, max, cur, out);
                cur.pop();
            }
        }
    }
    let mut out = vec![];
    go(&cand, roles, max, &mut vec![], &mut out);
    out
}

/// The worlds over one grant set, every grant its holder's writer's: root strongs to thing 1 or
/// to 1 and 2 (every other choice is a relabelling), no strong inside a thing or one. Grants from
/// outside are each grant flipped (`Case::flips`).
fn worlds(things: usize, grants: &[(T, T, Role)]) -> Vec<Spec> {
    let inner: Vec<Option<(T, T)>> = std::iter::once(None).chain((1..=things).flat_map(|a| (1..=things).filter(move |&b| b != a).map(move |b| Some((a, b))))).collect();
    let mut out = vec![];
    for rs in [vec![1], vec![1, 2]] {
        for &i in &inner {
            out.push(Spec { things: things + 1, grants: grants.to_vec(), strongs: i.into_iter().collect(), roots: rs.clone(), ..Spec::default() });
        }
    }
    out
}

/// Per variant and property: the worlds failing it and the smallest (fewest grants, then things).
type Tally = BTreeMap<(&'static str, &'static str), (usize, (usize, usize), String)>;

fn tally(sets: &[(usize, Vec<(T, T, Role)>)], vs: &[(&'static str, Rule)]) -> (usize, Tally) {
    let parts = par_map(sets, |(things, grants)| {
        let mut t = Tally::new();
        let ws = worlds(*things, grants);
        for (i, s) in ws.iter().enumerate() {
            let c = case(s);
            // the controls on every fourth world
            for (name, rule) in vs.iter().filter(|v| i % 4 == 0 || !v.0.starts_with("control")) {
                for prop in check(&c, rule) {
                    let size = (s.grants.len(), s.things);
                    let e = t.entry((name, prop)).or_insert((0, size, format!("{s:?}")));
                    e.0 += 1;
                }
            }
        }
        (ws.len(), t)
    });
    let mut out = Tally::new();
    let mut n = 0;
    for (w, t) in parts {
        n += w;
        for (key, (c, size, s)) in t {
            let e = out.entry(key).or_insert((0, size, s.clone()));
            e.0 += c;
            if size < e.1 {
                (e.1, e.2) = (size, s);
            }
        }
    }
    (n, out)
}

/// The small family, as sets of grants among the account and its things: three things with every
/// grant absent, read or admin, and with at most four grants one of which is write; four things
/// with at most six grants at admin, and with at most three one of which is read. `stride`: every
/// how-manyth set.
fn family(stride: usize) -> Vec<(usize, Vec<(T, T, Role)>)> {
    let has = |r: Role| move |g: &Vec<(T, T, Role)>| g.iter().any(|x| x.2 == r);
    let three = grant_sets(3, &[Read, Admin], usize::MAX).into_iter();
    let write = grant_sets(3, &[Read, Write, Admin], 4).into_iter().filter(has(Write));
    let four = grant_sets(4, &[Admin], 6).into_iter();
    let read = grant_sets(4, &[Read, Admin], 3).into_iter().filter(has(Read));
    three.chain(write).map(|g| (3, g)).chain(four.chain(read).map(|g| (4, g))).step_by(stride).collect()
}

fn print(what: &str, worlds: usize, t: &Tally) {
    eprintln!("{what}: {worlds} worlds");
    for ((v, p), (c, size, s)) in t {
        eprintln!("{v:22} {p:20} {c:9} worlds; smallest ({} grants, {} things): {s}", size.0, size.1.saturating_sub(1));
    }
}

/// The design passes everything; each control fails its property.
fn judge(t: &Tally, worlds: usize) {
    let fails = |v: &str, p: &str| t.iter().find(|(k, _)| k.0 == v && k.1 == p).map_or(0, |(_, x)| x.0);
    if let Some((k, x)) = t.iter().find(|(k, _)| k.0 == "design") {
        panic!("the design fails {} in {} worlds, smallest {}", k.1, x.0, x.2);
    }
    for (v, p) in [
        ("control held edges", "i certificates"),
        ("control every grant", "ii untaken roles"),
        ("control every grant", "ii untaken fetch"),
        ("control chosen path", "iv fetch outstanding"),
    ] {
        assert!(fails(v, p) > 0, "{v} never fails {p} in {worlds} worlds");
    }
}

#[test]
fn holder_access_small_family() {
    let (n, t) = tally(&family(2003), &variants());
    judge(&t, n);
}

#[test]
#[ignore = "property"]
fn holder_access_small_family_plain() {
    let (n, t) = tally(&family(env("OSIS_HOLDERS_STRIDE", 151)), &variants());
    print("small family", n, &t);
    judge(&t, n);
}

// ---- Random histories ----

/// A random history under `rule`: grants (some from outside their holder), revocations,
/// rotations owed, content changes, strongs added and dropped, a stranger granting the account or
/// a holder (from outside) a thing it builds, holders' admins enabling and disabling grants from
/// outside; three nodes with the same strongs syncing at random moments from random sources, and
/// two more that after half the steps reach only a store keeping what they sync unread, with every
/// key part configured there or none. The properties failed, and whether the store without key
/// parts left its node behind (the availability gap).
fn history(seed: u64, rule: &Rule, steps: usize) -> (BTreeSet<&'static str>, bool) {
    let mut r = Rng::new(seed);
    let base = 7;
    let mut k = Keys::new(base);
    let mut nodes: Vec<Node> = (0..5).map(|_| Node::new(&me())).collect();
    let all = Source::all();
    let mut bad = BTreeSet::new();
    for step in 0..steps {
        let (a, b) = (r.below(base as u64) as T, 1 + r.below(base as u64 - 1) as T);
        match r.below(13) {
            0..=3 if a != b => {
                let from = if r.chance(25) { From::Outside } else { From::Writer };
                k.grant_from(a, b, r.pick(&[Sync, Read, Write, Write, Admin, Admin]), from)
            }
            4 | 5 => {
                let gs: Vec<(T, T)> = k.world.grants.keys().copied().collect();
                if !gs.is_empty() {
                    let (g, t) = r.pick(&gs);
                    k.revoke(g, t);
                }
            }
            6 => {
                if let Some(&x) = k.stale.iter().next() {
                    k.rotate(x);
                }
            }
            7 => k.edit(b),
            8 if a != b && a != ME => match k.strongs.contains(&(a, b)) {
                true => k.unstrong(a, b),
                false => k.strong(a, b),
            },
            9 | 10 => {
                for n in &mut nodes {
                    if !n.roots.remove(&b) {
                        n.roots.insert(b);
                    }
                }
            }
            11 => {
                // a stranger's thing, granted from outside to the account or a thing, holding a
                // thing of its own
                let (x, y) = (k.thing(), k.thing());
                k.grant_from(a, x, Write, From::Outside);
                k.grant(x, y, Admin);
            }
            _ => {
                let on = !k.grantable.contains(&a);
                k.set_grantable(a, on);
            }
        }
        for (i, n) in nodes.iter_mut().enumerate() {
            let synced = oracle(&k, &me(), &n.roots).synced();
            let src = match i {
                3 | 4 if step == steps / 2 => all.clone(),
                3 if step > steps / 2 => Source { units: Some(synced), parts: None },
                4 if step > steps / 2 => Source { units: Some(synced), parts: Some(Set::new()) },
                _ if r.chance(60) => continue,
                _ if r.chance(50) => all.clone(),
                _ => Source { units: Some((0..k.epoch.len()).filter(|_| r.chance(50)).collect()), parts: Some((0..k.epoch.len()).filter(|_| r.chance(50)).collect()) },
            };
            n.sync(&k, rule, &src);
        }
    }
    k.rotate_stale();
    let want = oracle(&k, &me(), &nodes[0].roots);
    let ok = |n: &Node| shows(&n.seen) == shows(&want) && n.seen.closure.for_keys == want.closure.for_keys && want.synced().iter().all(|&x| n.have.get(&x) == Some(&k.epoch[x]));
    for n in &mut nodes[..3] {
        n.sync(&k, rule, &all);
        n.sync(&k, rule, &all);
        if n.unsettled {
            bad.insert("settles");
        }
    }
    if !nodes[..3].iter().all(|n| n.seen == nodes[0].seen) {
        bad.insert("i orders");
    }
    if !nodes[..3].iter().all(ok) {
        bad.insert("i history");
    }
    let store = |parts: Option<Set>| Source { units: Some(want.synced()), parts };
    nodes[3].sync(&k, rule, &store(None));
    nodes[3].sync(&k, rule, &store(None));
    if !ok(&nodes[3]) {
        bad.insert("store with key parts");
    }
    nodes[4].sync(&k, rule, &store(Some(Set::new())));
    (bad, !ok(&nodes[4]))
}

fn histories(start: u64, seeds: u64, vs: &[(&'static str, Rule)]) -> BTreeMap<(&'static str, &'static str), (usize, u64)> {
    let jobs: Vec<u64> = (start..start + seeds).collect();
    let mut out = BTreeMap::new();
    for part in par_map(&jobs, |&seed| {
        let mut v = vec![];
        for (name, rule) in vs {
            let (bad, gap) = history(seed, rule, 40);
            v.extend(bad.into_iter().map(|p| (*name, p)));
            if gap {
                v.push((*name, "(the gap: store without key parts)"));
            }
        }
        (seed, v)
    }) {
        for key in part.1 {
            out.entry(key).or_insert((0, part.0)).0 += 1;
        }
    }
    out
}

fn judge_histories(seeds: u64) {
    let start = env("OSIS_HELD_START", 0u64);
    let t = histories(start, seeds, &variants());
    eprintln!("histories: {seeds} seeds from {start}");
    for ((v, p), (c, first)) in &t {
        eprintln!("{v:22} {p:36} {c:6} histories, first seed {first}");
    }
    for ((v, p), (c, first)) in &t {
        assert!(!(*v == "design" && !p.starts_with('(')), "{v} fails {p} in {c} histories, first seed {first}");
    }
    // the gap is reached, and is the store's lack alone
    assert!(t.get(&("design", "(the gap: store without key parts)")).is_some_and(|x| x.0 > 0), "no history reaches the gap");
    assert!(t.get(&("control every grant", "i history")).is_some_and(|x| x.0 > 0), "no history takes a grant from outside");
}

#[test]
fn holder_access_histories() {
    judge_histories(60);
}

#[test]
#[ignore = "property"]
fn holder_access_histories_plain() {
    judge_histories(env("OSIS_HELD_SEEDS", 600));
}

// ---- Hand worlds ----

fn spec(things: usize, grants: &[(T, T, Role)], roots: &[T]) -> Spec {
    Spec { things, grants: grants.to_vec(), roots: roots.to_vec(), ..Spec::default() }
}
fn synced(s: &Spec, rule: &Rule) -> (Keys, Node) {
    let (k, mut n) = build(s, &id);
    n.sync(&k, rule, &Source::all());
    assert!(!n.unsettled);
    (k, n)
}
/// What a node fetched between two ledgers.
fn delta(after: &Node, before: &Node) -> Ledger {
    Ledger::of(after.got.difference(&before.got))
}

// 1. (iii) A to B to C, the node syncing C alone: it reads and writes C, holds A and B for keys,
// and fetches three edge pieces, one box and one keyset per thing, and no content but C's.
#[test]
fn hw1_a_chain_is_used_without_its_holders_content() {
    let (a, b, c) = (1, 2, 3);
    let s = spec(4, &[(ME, a, Write), (a, b, Admin), (b, c, Admin)], &[c]);
    let (mut k, n) = synced(&s, &P1);
    assert_eq!(n.seen, oracle(&k, &me(), &set(&[c])));
    assert_eq!((n.seen.roles.get(&c), &n.seen.closure.read, &n.seen.closure.for_keys), (Some(&Write), &set(&[c]), &set(&[a, b])));
    assert!(n.can_write(&k, c));
    let l = n.ledger();
    assert_eq!((l.edges, l.keysets, l.boxes, l.content), (3, 3, 3, 1));
    assert!(n.got.contains(&Item::Content(c, 0)));
    // (v) the holders' content changes: nothing downloaded
    k.edit(a);
    k.edit(b);
    let mut m = n.clone();
    m.sync(&k, &P1, &Source::all());
    assert_eq!(m.got, n.got);
}

// 2. (iv) A to C and D to C. A revoked on C: C is writable on hearing it, D's key part already
// held. Then D revoked: C's secrets go. Holding only the path a write picks fails the first.
#[test]
fn hw2_a_revoked_path_leaves_the_other_usable_at_once() {
    let (a, d, c) = (1, 2, 3);
    let s = spec(4, &[(ME, a, Write), (ME, d, Write), (a, c, Write), (d, c, Write)], &[c]);
    for (rule, design) in [(P1, true), (Rule { paths: Paths::Chosen, ..P1 }, false)] {
        let (mut k, mut n) = synced(&s, &rule);
        assert_eq!(n.seen.closure.for_keys.contains(&d), design);
        let held = Source { units: Some(set(&[c])), parts: Some(n.seen.closure.for_keys.union(&me()).copied().collect()) };
        let before = n.clone();
        k.revoke(a, c);
        n.sync(&k, &rule, &held);
        let no_fetch = n.have.keys().all(|x| before.have.contains_key(x));
        assert_eq!(n.can_write(&k, c) && no_fetch, design, "{rule:?}");
        if design {
            assert_eq!(delta(&n, &before), Ledger { edges: 1, keysets: 1, boxes: 1, ..Ledger::default() }, "the removal, C's rotation, its box to D");
            assert_eq!(n.seen.closure.for_keys, set(&[d]));
            k.revoke(d, c);
            n.sync(&k, &rule, &held);
            assert!(n.have.is_empty() && n.seen.roles.is_empty() && n.seen.closure.held.is_empty(), "lost access: C's secrets go");
        }
    }
}

/// World 3: the account reaches C through A; a stranger's X, holding roles on `n` things the
/// stranger builds, grants the account write from outside (`granted`), taken iff the account
/// enables grants from outside (`enabled`). X is on no path to C.
fn stranger(n: usize, granted: bool, enabled: bool) -> Spec {
    let (a, c, x) = (1, 2, 3);
    let mut s = spec(4 + n, &[(ME, a, Write), (a, c, Admin)], &[c]);
    if granted {
        s.grants.push((ME, x, Write));
        s.outside.push((ME, x));
        s.grants.extend((0..n).map(|i| (x, 4 + i, Admin)));
    }
    if enabled {
        s.grantable.push(ME);
    }
    s
}

// 3. (ii) A stranger's grant the account did not enable: nothing read at all. Enabled, it is a
// taken grant on no path: no role and no key part, its lists read (one entry per thing the
// stranger built: the stated cost of taking it). Following every grant reads them untaken too.
#[test]
fn hw3_a_strangers_grant_changes_no_fetch() {
    for (rule, enabled, lists) in [(P1, false, [0, 0]), (P1, true, [6, 51]), (EVERY, false, [6, 51])] {
        let (_, plain) = synced(&stranger(0, false, enabled), &rule);
        let reads: Vec<usize> = [5, 50]
            .iter()
            .map(|&n| {
                let (_, with) = synced(&stranger(n, true, enabled), &rule);
                assert_eq!(with.seen, plain.seen);
                assert_eq!(key_items(&with), key_items(&plain), "{rule:?}");
                with.ledger().lists - plain.ledger().lists
            })
            .collect();
        assert_eq!(reads, lists, "{rule:?} enabled {enabled}");
    }
}

// 4. The stranger's X granted a role on C by C's admin, a grant from outside X: not taken, X is on
// no path. X's admins enable grants from outside: X is held for keys; revoked, let go.
#[test]
fn hw4_a_thing_on_a_path_is_held_for_keys_and_let_go() {
    let (a, c, x) = (1, 2, 3);
    let (mut k, mut n) = synced(&stranger(3, true, true), &P1);
    assert_eq!(n.seen.closure.for_keys, set(&[a]));
    k.grant_from(x, c, Write, From::Outside);
    n.sync(&k, &P1, &Source::all());
    assert_eq!(n.seen.closure.for_keys, set(&[a]), "not taken");
    k.set_grantable(x, true);
    n.sync(&k, &P1, &Source::all());
    assert_eq!(n.seen.closure.for_keys, set(&[a, x]));
    assert!(n.have.contains_key(&x));
    k.revoke(x, c);
    n.sync(&k, &P1, &Source::all());
    assert_eq!(n.seen.closure.for_keys, set(&[a]));
    assert!(!n.have.contains_key(&x) && n.can_write(&k, c));
}

// 5. The strong to C dropped: A and B are no longer held for keys, every secret goes.
#[test]
fn hw5_dropping_the_strong_lets_the_holders_go() {
    let (a, b, c) = (1, 2, 3);
    let s = spec(4, &[(ME, a, Write), (a, b, Admin), (b, c, Admin)], &[c]);
    let (k, mut n) = synced(&s, &P1);
    n.roots.clear();
    n.sync(&k, &P1, &Source::all());
    assert!(n.seen.roles.is_empty() && n.seen.closure.held.is_empty() && n.seen.closure.for_keys.is_empty() && n.have.is_empty() && n.edges.is_empty());
}

/// World 6: A with `m` members holds admin on `k` things, C the first; the node syncs C through
/// A. What it fetches at first, when A's content changes, when a member of A is removed, and when
/// the things below A then rotate.
fn churn(rule: &Rule, m: usize, things: usize) -> [Ledger; 4] {
    let (a, c) = (1, 2);
    let mut s = spec(2 + things + m, &[(ME, a, Write)], &[c]);
    s.grants.extend((0..things).map(|i| (a, c + i, Admin)));
    s.grants.extend((0..m).map(|i| (c + things + i, a, Read)));
    let (mut k, n0) = synced(&s, rule);
    assert_eq!((n0.seen.roles.get(&c), &n0.seen.closure.for_keys), (Some(&Write), &set(&[a])));
    let all = Source::all();
    let mut n = n0.clone();
    let step = |k: &Keys, n: &mut Node| {
        let before = n.clone();
        n.sync(k, rule, &all);
        delta(n, &before)
    };
    k.edit(a);
    let content = step(&k, &mut n);
    k.revoke(c + things, a);
    let removed = step(&k, &mut n);
    k.rotate_stale();
    let below = step(&k, &mut n);
    assert!(n.can_write(&k, c));
    [n0.ledger(), content, removed, below]
}

// 6. (v) A's content changes: nothing. A member of A removed: the node's own box of A's rotation
// and its keyset, then its own box of C's rotation, whatever A's roster and however many things
// A holds. Fetching whole box sets grows with both. The search reads A's list: k entries.
#[test]
fn hw6_a_holders_churn_costs_its_own_boxes() {
    let one = Ledger { keysets: 1, boxes: 1, ..Ledger::default() };
    let sizes = [(10, 1), (100, 1), (10, 10), (100, 10)];
    let runs: Vec<[Ledger; 4]> = sizes.iter().map(|&(m, k)| churn(&P1, m, k)).collect();
    for r in &runs {
        assert_eq!(r[1], Ledger::default(), "content");
        assert_eq!(r[3], one, "C's rotation");
        assert_eq!((r[0].keysets, r[0].boxes, r[0].content), (2, 2, 1), "first sync");
        assert_eq!(r[2], one, "a member removed");
    }
    // what the search read at first beyond the two edge pieces of the path
    let first: Vec<usize> = runs.iter().map(|r| r[0].lists + r[0].edges - 2).collect();
    assert_eq!(first, [2, 2, 11, 11]);
    let whole = Rule { boxes: Boxes::Whole, ..P1 };
    let boxes: Vec<(usize, usize)> = sizes.iter().map(|&(m, k)| churn(&whole, m, k)).map(|r| (r[2].boxes, r[3].boxes)).collect();
    assert_eq!(boxes, [(10, 1), (100, 1), (10, 10), (100, 10)], "every remaining box of A's rotation; every thing below A");
}

// 7. A read hop: the account admin on A, A read on B, B admin on C: read on C, no write.
#[test]
fn hw7_a_read_hop_gives_read() {
    let (a, b, c) = (1, 2, 3);
    let s = spec(4, &[(ME, a, Admin), (a, b, Read), (b, c, Admin)], &[c]);
    let (k, n) = synced(&s, &P1);
    assert_eq!(n.seen.roles.get(&c), Some(&Read));
    assert!(n.seen.closure.read.contains(&c) && !n.can_write(&k, c));
}

// 8. A cycle: A holds a role on B and B on A, both above C. The second grant of the cycle reads
// nothing (keyless), and the walk ends either way.
#[test]
fn hw8_a_cycle_of_holders_ends() {
    let (a, b, c) = (1, 2, 3);
    let s = spec(4, &[(ME, a, Write), (a, b, Admin), (b, a, Admin), (a, c, Read), (b, c, Admin)], &[c]);
    for raw in [false, true] {
        let mut k = Keys::new(s.things);
        k.raw_cycles = raw;
        for &(g, t, r) in &s.grants {
            k.grant(g, t, r);
        }
        assert_eq!(k.world.keyless.contains(&(b, a)), !raw);
        let (_, mut n) = build(&s, &id);
        n.sync(&k, &P1, &Source::all());
        assert!(!n.unsettled);
        assert_eq!(n.seen, oracle(&k, &me(), &set(&[c])), "raw {raw}");
        assert_eq!((n.seen.roles.get(&c), &n.seen.closure.for_keys), (Some(&Write), &set(&[a, b])));
    }
}

// 9. The node also syncs A whole: A is held whole, not for keys too, and nothing is fetched twice.
#[test]
fn hw9_held_whole_and_for_keys_is_held_whole() {
    let (a, b, c) = (1, 2, 3);
    let grants = [(ME, a, Write), (a, b, Admin), (b, c, Admin)];
    let (k, both) = synced(&spec(4, &grants, &[c, a]), &P1);
    let (_, only_c) = synced(&spec(4, &grants, &[c]), &P1);
    let (_, only_a) = synced(&spec(4, &grants, &[a]), &P1);
    assert_eq!(both.seen, oracle(&k, &me(), &set(&[a, c])));
    assert_eq!((&both.seen.closure.for_keys, &both.seen.closure.read), (&set(&[b]), &set(&[a, c])));
    assert_eq!(key_items(&both), key_items(&only_c).union(&key_items(&only_a)).copied().collect());
}

// 10. The old class. A certificate naming G on H that arrived with another write gives nothing
// where G is on no path from the account. A grant on T1 seen only through certificates counts iff
// the path stands: standing, with or without the certificate; revoked, never, though a node that
// counted every held role commit would count it while it held the certificate.
#[test]
fn hw10_a_role_never_hangs_on_what_happens_to_be_held() {
    let (a, c, g, h, t1) = (1, 2, 3, 4, 5);
    let held_edges = Rule { roles: RolesBy::HeldEdges, ..P1 };
    let base = [(ME, a, Read), (a, c, Read), (h, c, Admin), (t1, c, Admin)];
    let run = |grants: &[(T, T, Role)], certs: &[(T, T)], rule: &Rule| {
        let (k, mut n) = build(&spec(6, grants, &[c]), &id);
        n.certs = certs.iter().map(|&e| (e, Admin)).collect();
        n.sync(&k, rule, &Source::all());
        assert_eq!(n.seen.closure.for_keys.contains(&t1), k.world.grants.contains_key(&(ME, t1)));
        n.seen.roles.get(&c).copied()
    };
    for rule in [P1, held_edges] {
        assert_eq!(run(&base, &[(g, h)], &rule), Some(Read), "G on no path: {rule:?}");
        let standing: Vec<_> = base.iter().copied().chain([(ME, t1, Write)]).collect();
        assert_eq!(run(&standing, &[], &rule), Some(Write));
        assert_eq!(run(&standing, &[(ME, t1)], &rule), Some(Write));
        assert_eq!(run(&base, &[], &rule), Some(Read));
        let stale = run(&base, &[(ME, t1)], &rule);
        assert_eq!(stale, Some(if rule == held_edges { Admin } else { Read }), "a revoked grant's certificate: {rule:?}");
    }
}

// 11. The availability gap. The node acts on C through A and reaches only a store keeping C
// unread. A member of A is removed and C rotates: without A's key part at the store the node gets
// C's rotation and cannot open it; with it configured there, it writes.
#[test]
fn hw11_a_store_without_the_holders_key_part_leaves_the_node_behind() {
    let (a, c, other) = (1, 2, 3);
    let s = spec(4, &[(ME, a, Write), (a, c, Admin), (other, a, Read)], &[c]);
    for configured in [false, true] {
        let (mut k, mut n) = synced(&s, &P1);
        let store = Source { units: Some(set(&[c])), parts: Some(if configured { set(&[a]) } else { Set::new() }) };
        k.edit(c);
        k.revoke(other, a);
        k.rotate_stale();
        n.sync(&k, &P1, &store);
        assert_eq!(n.can_write(&k, c), configured);
        assert_eq!(n.have.get(&c) == Some(&k.epoch[c]), configured);
        assert!(n.got.contains(&Item::Content(c, 1)) == configured, "C's new content is sealed to the epoch it cannot open");
        n.sync(&k, &P1, &Source::all());
        assert!(n.can_write(&k, c));
    }
}

// 12. The switch turned off: the account reaches C only through A, its grant on A from outside.
// While the account enables grants from outside it writes C; disabled, the grant is no longer
// taken and C's secrets go with no rotation anywhere; enabled again, it writes C at once.
#[test]
fn hw12_disabling_grants_from_outside_drops_their_paths() {
    let (a, c) = (1, 2);
    let mut s = spec(3, &[(ME, a, Write), (a, c, Admin)], &[c]);
    s.outside.push((ME, a));
    s.grantable.push(ME);
    let (mut k, mut n) = synced(&s, &P1);
    assert!(n.can_write(&k, c) && n.seen.closure.for_keys == set(&[a]));
    let epochs = k.epoch.clone();
    k.set_grantable(ME, false);
    n.sync(&k, &P1, &Source::all());
    assert_eq!(n.seen, oracle(&k, &me(), &set(&[c])));
    assert!(n.seen.roles.is_empty() && n.have.is_empty() && n.edges.is_empty() && k.epoch == epochs);
    k.set_grantable(ME, true);
    n.sync(&k, &P1, &Source::all());
    assert!(n.can_write(&k, c));
}
