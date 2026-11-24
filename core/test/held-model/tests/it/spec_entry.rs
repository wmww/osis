//! First entry and the node thing / node root split (held_model::closure::entry; spec/sync-set.md
//! §1, §2 First entry; spec/permissions.md §4 Key part, §8 Accounts). Findings:
//! notes/accounts-switch-brief.md, Models.
use held_model::closure::entry::{Fix, Held, Net, Node, Rule, S};
use held_model::closure::{keyless_of, unit, Kind, Role, Set, World, T};

const N1: T = 0;
const R1: T = 1;
const N2: T = 2;
const R2: T = 3;
const A: T = 4;
const D: T = 5;
const INBOX: T = 6;
const PROFILE: T = 7;
const B: T = 8;
const C: T = 9;

fn set(x: &[T]) -> Set {
    x.iter().copied().collect()
}

/// An account A made by node 1 (A minted with admin N1, independent; its dependent D, inbox and
/// profile held by strongs from A), node 2 paired (its grant on A at `paired`, its root's strong
/// to A) or not, and `more` independent things beyond.
fn account(paired: Option<Role>, more: usize) -> Net {
    use Kind::*;
    let mut kinds = vec![Independent, Dependent(N1), Independent, Dependent(N2), Independent, Dependent(A), Independent, Independent];
    kinds.extend(std::iter::repeat(Independent).take(more));
    let mut net = Net { w: World { kinds, ..World::default() }, nodes: vec![Node { thing: N1, root: R1, offers: Set::new() }, Node { thing: N2, root: R2, offers: Set::new() }], ..Net::default() };
    for (m, x) in [(N1, A), (A, INBOX), (A, PROFILE)] {
        net.w.grants.insert((m, x), Role::Admin);
        net.records.insert((m, x));
    }
    net.strongs = [(R1, N1), (R1, A), (A, D), (A, INBOX), (A, PROFILE), (R2, N2)].into_iter().collect();
    if let Some(r) = paired {
        net.w.grants.insert((N2, A), r);
        net.strongs.insert((R2, A));
    }
    net
}

fn held(net: &Net, i: usize, rule: Rule) -> Set {
    net.held(i, rule).held
}

// spec/sync-set.md §1: the node thing's sync unit is itself alone; with the node's strongs on it
// (the split undone) its unit is the node's whole readable closure, logged once more under its own
// sync ID.
#[test]
fn the_node_things_unit_is_itself() {
    let net = account(Some(Role::Admin), 0);
    for (n, rule) in [(N1, Rule::FIXED), (N2, Rule::FIXED)] {
        assert_eq!(unit(&net.w, n, &net.edges(rule)), set(&[n]));
    }
    let merged = Rule { merged: true, ..Rule::FIXED };
    assert_eq!(unit(&net.w, N1, &net.edges(merged)), set(&[N1, A, D, INBOX, PROFILE]), "control: the merged node thing carries the account");
    // held alike either way: the split changes what N's sync ID carries, not what the node holds
    let split = held(&net, 0, Rule::FIXED);
    assert_eq!(held(&net, 0, merged), &split - &set(&[R1]));
}

// spec/permissions.md §8 Making, §4 Key part, spec/sync-set.md §2 First entry: A is minted with
// admin N1 and held by a strong from N1's root. No unit N1 syncs carries A (N1's unit is N1), N1
// holds no offer of A, and N1's key part indexes edge pieces by edge writes: the record edge has
// none. So the node that made the account never enters it, and Making refuses A. Indexing every
// edge the holder holds, the record edge included, lets it in.
#[test]
fn hole_the_making_node_never_enters_its_account() {
    let net = account(None, 0);
    assert_eq!(held(&net, 0, Rule::SPEC), set(&[N1, R1]), "the spec as written: A is not entered");
    let fixed = Rule { record_pieces: true, ..Rule::SPEC };
    let h: Held = net.held(0, fixed);
    assert_eq!(h.held, set(&[N1, R1, A, D, INBOX, PROFILE]));
    assert_eq!(h.sync_set, set(&[N1, A, INBOX, PROFILE]));
}

// Pairing (spec/permissions.md §8): node 2 enters A by the offer handed over the channel, then by
// its own edge piece on A (a grant: an edge write) once the offer is gone; it holds what node 1
// holds, and neither holds the other's node thing for keys. Removing node 2's grant takes A away.
#[test]
fn one_and_two_node_accounts_pairing_and_removal() {
    for role in [Role::Admin, Role::Write] {
        let mut net = account(Some(role), 0);
        net.nodes[1].offers = set(&[A]);
        let with_offer = net.held(1, Rule::FIXED);
        net.nodes[1].offers.clear();
        let after = net.held(1, Rule::FIXED);
        assert_eq!(with_offer, after);
        assert_eq!(after.held, set(&[N2, R2, A, D, INBOX, PROFILE]));
        assert_eq!(after.sync_set, set(&[N2, A, INBOX, PROFILE]), "N1 is held for nothing at node 2");
        assert_eq!(net.held(0, Rule::FIXED).sync_set, set(&[N1, A, INBOX, PROFILE]));
        // the spec as written: the second node is in, the first is out
        assert_eq!(held(&net, 1, Rule::SPEC), after.held);
        assert_eq!(held(&net, 0, Rule::SPEC), set(&[N1, R1]));
        // removal: the grant goes (its piece stays, with the removal); node 2 holds itself alone
        net.w.grants.remove(&(N2, A));
        assert_eq!(held(&net, 1, Rule::FIXED), set(&[N2, R2]));
        assert_eq!(held(&net, 0, Rule::FIXED), set(&[N1, R1, A, D, INBOX, PROFILE]));
    }
}

/// The account reaching C through B: A holds read on B, B `last` on C, A strongs C.
fn far(last: Role) -> Net {
    let mut net = account(Some(Role::Admin), 2);
    net.w.grants.insert((A, B), Role::Read);
    net.w.grants.insert((B, C), last);
    net.strongs.insert((A, C));
    net
}

// spec/sync-set.md §2 First entry; notes/stubs.md rule 2. A references C, which it holds read
// on through B: C is in A's unit, whole, at both nodes, with no record of B's grants anywhere.
// Held sync alone through B, C is in no unit (A's keys do not open it) and B's key part is held
// only once C is synced (keys are found up): neither node enters C, though A holding sync on C
// directly enters it at both by A's own edge piece. A unit carrying the stub of what its thing
// holds sync on enters C either way.
#[test]
fn hole_a_far_thing_held_sync_through_a_holder_is_never_entered() {
    let fix_records = Rule { record_pieces: true, ..Rule::SPEC };
    let net = far(Role::Read);
    for i in 0..2 {
        let h = net.held(i, fix_records);
        assert!(h.s.read.contains(&C) && !h.s.read.contains(&B), "C whole in A's unit, B held for keys: {h:?}");
    }
    let net = far(Role::Sync);
    let mut direct = account(Some(Role::Admin), 2);
    direct.w.grants.insert((A, C), Role::Sync);
    direct.strongs.insert((A, C));
    for i in 0..2 {
        assert!(!held(&net, i, fix_records).contains(&C), "the spec: never entered");
        assert!(held(&direct, i, fix_records).contains(&C), "direct: entered by A's piece");
        let h = net.held(i, Rule::FIXED);
        assert!(h.s.kept.contains(&C) && h.held.contains(&C), "stub at sync: kept unread {h:?}");
    }
}

// The node root's strongs are no unit: a far thing (A read on B, B read on C) referenced only from
// node 1's root is entered only while an offer of it is held. The greatest-fixpoint reading (C
// entered because its own unit, or B's key part held because C is synced, carries it) enters it with no
// offer at either node: a walk down every opened holder's key part, the per-holder list the design
// removed; first entry off does the same.
#[test]
fn a_far_thing_referenced_from_the_root_needs_an_offer() {
    let mut net = account(Some(Role::Admin), 2);
    net.w.grants.insert((A, B), Role::Read);
    net.w.grants.insert((B, C), Role::Read);
    net.strongs.insert((R1, C));
    assert!(!held(&net, 0, Rule::FIXED).contains(&C));
    assert!(held(&net, 0, Rule { fix: Fix::Greatest, ..Rule::FIXED }).contains(&C), "control: greatest fixpoint walks down");
    assert!(held(&net, 0, Rule { first_entry: false, ..Rule::FIXED }).contains(&C), "control: no first entry");
    net.nodes[0].offers = set(&[C]);
    let with = net.held(0, Rule::FIXED);
    assert!(with.held.contains(&C) && with.sync_set.contains(&B), "{with:?}");
}

// A node following changes (settling from its last state) keeps what supports itself: once C was
// entered by an offer, C's own unit carries C (and B, held for keys, carries C's piece), so C stays
// after the offer goes. A node
// recomputing from data (the least fixpoint) drops C, and the account's other node never had it:
// the held set would depend on history. An engine must drop a thing whose only support is the key
// part its own entry brought in.
#[test]
fn following_changes_keeps_a_self_supporting_entry() {
    let mut net = account(Some(Role::Admin), 2);
    net.w.grants.insert((A, B), Role::Read);
    net.w.grants.insert((B, C), Role::Read);
    net.strongs.insert((R1, C));
    net.nodes[0].offers = set(&[C]);
    let prev: S = net.held(0, Rule::FIXED).s;
    net.nodes[0].offers.clear();
    let followed = net.held_from(0, Rule::FIXED, net.settle(0, Rule::FIXED, prev));
    assert!(followed.held.contains(&C), "kept by its own support");
    assert!(!held(&net, 0, Rule::FIXED).contains(&C), "dropped by the rule");
}

/// Random worlds over the account: `more` further things (independent, or dependents of an earlier
/// one), random grants among A and them, random strongs from them and A, random root strongs
/// mirrored on both roots.
fn random(seed: u64, more: usize) -> Net {
    let mut st = seed.wrapping_mul(0x9e3779b97f4a7c15) | 1;
    let mut next = |m: u64| {
        st = st.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        (st >> 33) % m
    };
    let roles = [Role::Sync, Role::Read, Role::Write, Role::Admin];
    let mut net = account(Some([Role::Write, Role::Admin][next(2) as usize]), more);
    let things: Vec<T> = std::iter::once(A).chain(8..8 + more).collect();
    for x in 8..8 + more {
        if next(3) == 0 {
            let of = things[next((x - 8 + 1) as u64) as usize];
            if of != x && net.w.independent(of) {
                net.w.kinds[x] = Kind::Dependent(of);
            }
        }
    }
    let mut order = vec![];
    for _ in 0..next(2 * more as u64 + 2) {
        let (h, t) = (things[next(things.len() as u64) as usize], things[next(things.len() as u64) as usize]);
        if h != t && net.w.independent(t) && net.w.independent(h) && !net.w.grants.contains_key(&(h, t)) {
            net.w.grants.insert((h, t), roles[next(4) as usize]);
            order.push((h, t));
        }
    }
    net.w.keyless = keyless_of(&order);
    for _ in 0..next(2 * more as u64 + 1) {
        let (f, to) = (things[next(things.len() as u64) as usize], 8 + next(more as u64) as T);
        if f != to {
            net.strongs.insert((f, to));
        }
    }
    for x in 8..8 + more {
        if next(4) == 0 {
            net.strongs.insert((R1, x));
            net.strongs.insert((R2, x));
        }
    }
    net
}

/// Each node's held set with its own node thing and root taken out.
fn shared(net: &Net, i: usize, rule: Rule) -> Set {
    let n = &net.nodes[i];
    &held(net, i, rule) - &set(&[n.thing, n.root])
}

/// The properties the design promises, over one world, under `rule`: the failures.
fn check(net: &Net, rule: Rule) -> Vec<&'static str> {
    let mut out = vec![];
    // Making: the node that made A holds it.
    if !held(net, 0, rule).contains(&A) {
        out.push("making");
    }
    // One account, one held set: its two nodes with the same strongs hold the same things.
    if shared(net, 0, rule) != shared(net, 1, rule) {
        out.push("symmetry");
    }
    let e = net.edges(rule);
    for i in 0..2 {
        let h = net.held(i, rule);
        // By role: a strong in a read unit to a thing outside it its thing holds sync or above on
        // is held, as a direct grant of that role would be.
        for &t in &h.s.read {
            let u = unit(&net.w, t, &e);
            let roles = net.w.roles_from(t);
            for &(m, x) in &e {
                if u.contains(&m) && !u.contains(&x) && net.w.independent(x) && roles.get(&x).is_some_and(|&r| r >= Role::Sync) && !h.held.contains(&x) {
                    out.push("by role");
                }
            }
        }
        // First entry: a thing reached from the root alone, no offer held, is held only if a read
        // unit of another thing carries it (whole or by a strong from it) or an own or read thing holds an edge on
        // it. Held through the edge piece of a holder held for keys for some other synced thing
        // (founded, but on what else the node syncs) it is "incidental"; through nothing founded,
        // "first entry".
        let founded = net.held(i, Rule { fix: Fix::Least, ..rule }).s;
        for &(r, x) in &e {
            if r == net.nodes[i].root && net.w.independent(x) && x != net.nodes[i].thing && h.held.contains(&x) {
                let by_unit = h.s.read.iter().filter(|&&t| t != x).any(|&t| unit(&net.w, t, &e).contains(&x) || unit(&net.w, t, &e).iter().any(|&m| e.contains(&(m, x))));
                let edge_from = |hs: &Set| hs.iter().any(|&g| net.w.grants.contains_key(&(g, x)));
                if by_unit || edge_from(&h.s.read) {
                } else if edge_from(&founded.keyparts) {
                    out.push("incidental");
                } else {
                    out.push("first entry");
                }
            }
        }
        // Founded: what a node following changes keeps once its offers go is what the rule gives.
        let mut offered = net.clone();
        offered.nodes[i].offers = (8..net.w.kinds.len()).collect();
        let prev = offered.held(i, rule).s;
        if rule.fix == Fix::Least && net.held_from(i, rule, net.settle(i, rule, prev)).held != h.held {
            out.push("history");
        }
    }
    out.sort();
    out.dedup();
    out
}

fn sweep(rule: Rule, worlds: u64, more: usize) -> std::collections::BTreeMap<&'static str, usize> {
    let mut fails = std::collections::BTreeMap::new();
    for seed in 0..worlds {
        for f in check(&random(seed, more), rule) {
            *fails.entry(f).or_insert(0) += 1;
        }
    }
    fails
}

// The design (`Rule::FIXED`) keeps every property over random worlds but "history", the hazard of
// following changes (no rule: an engine must recompute founded support); each rule weakened fails
// its property: record pieces off fails making and symmetry, stubs at sync off fails by role, first
// entry off or the greatest fixpoint fails first entry (founded pieces off: the hand world below).
#[test]
fn entry_rules_over_random_worlds() {
    let fixed = sweep(Rule::FIXED, 1000, 5);
    assert_eq!(fixed.keys().copied().collect::<Vec<_>>(), vec!["history"], "{fixed:?}");
    for (rule, prop) in [
        (Rule { record_pieces: false, ..Rule::FIXED }, "making"),
        (Rule { stubs_at_sync: false, ..Rule::FIXED }, "by role"),
        (Rule { first_entry: false, ..Rule::FIXED }, "first entry"),
        (Rule { fix: Fix::Greatest, ..Rule::FIXED }, "first entry"),
    ] {
        let f = sweep(rule, 1000, 5);
        assert!(f.contains_key(prop), "{rule:?} should fail {prop}: {f:?}");
    }
}

// The spec's first entry takes an edge piece from any key part the node holds: A holds read on H,
// H sync on Y and on X; A references Y (kept unread, by the stub at sync), so H is held for keys,
// and H's piece on X enters X, which only the node root references. Without the strong to Y, X is
// not entered: entry by what else the node syncs. Taking pieces only from own and read things' key
// parts (notes/stubs.md rule 2's cut, `founded_pieces`) enters X in neither.
#[test]
fn incidental_entry_through_a_holder_held_for_another_thing() {
    const H: T = 8;
    const Y: T = 9;
    const X: T = 10;
    let mut net = account(Some(Role::Admin), 3);
    net.w.grants.insert((A, H), Role::Read);
    net.w.grants.insert((H, Y), Role::Sync);
    net.w.grants.insert((H, X), Role::Sync);
    net.strongs.insert((R1, X));
    let spec = Rule { founded_pieces: false, ..Rule::FIXED };
    assert!(!held(&net, 0, spec).contains(&X));
    net.strongs.insert((A, Y));
    assert!(held(&net, 0, spec).contains(&X), "entered through H, held for Y");
    assert!(held(&net, 0, Rule::FIXED).contains(&Y) && !held(&net, 0, Rule::FIXED).contains(&X));
}

// By hand: OSIS_ENTRY_WORLDS random worlds (default 20000) of OSIS_ENTRY_MORE further things
// (default 5) under each rule, printing the failures per property.
#[test]
#[ignore]
fn entry_explore() {
    let n: u64 = std::env::var("OSIS_ENTRY_WORLDS").ok().and_then(|s| s.parse().ok()).unwrap_or(20000);
    let more: usize = std::env::var("OSIS_ENTRY_MORE").ok().and_then(|s| s.parse().ok()).unwrap_or(5);
    for (name, rule) in [
        ("spec", Rule::SPEC),
        ("fixed", Rule::FIXED),
        ("no record pieces", Rule { record_pieces: false, ..Rule::FIXED }),
        ("no stubs at sync", Rule { stubs_at_sync: false, ..Rule::FIXED }),
        ("pieces of held-for-keys holders", Rule { founded_pieces: false, ..Rule::FIXED }),
        ("no first entry", Rule { first_entry: false, ..Rule::FIXED }),
        ("greatest", Rule { fix: Fix::Greatest, ..Rule::FIXED }),
    ] {
        println!("{name}: {:?}", sweep(rule, n, more));
    }
}

// By hand, the exhaustive family: A and three further independent things, every grant among them
// (A on each, each on each other) none, sync or read, and one strong to one of them from A or from
// both roots; every property under `Rule::FIXED` but "history".
#[test]
#[ignore]
fn entry_family() {
    let roles = [None, Some(Role::Sync), Some(Role::Read)];
    let (b, c, x) = (8, 9, 10);
    let pairs: Vec<(T, T)> = vec![(A, b), (A, c), (A, x), (b, c), (c, b), (b, x), (x, b), (c, x), (x, c)];
    let mut fails = std::collections::BTreeMap::new();
    let mut worlds = 0;
    for code in 0..3usize.pow(pairs.len() as u32) {
        let mut net = account(Some(Role::Admin), 3);
        let (mut k, mut order) = (code, vec![]);
        for &p in &pairs {
            if let Some(r) = roles[k % 3] {
                net.w.grants.insert(p, r);
                order.push(p);
            }
            k /= 3;
        }
        net.w.keyless = keyless_of(&order);
        for to in [b, c, x] {
            for from_root in [false, true] {
                let mut n = net.clone();
                match from_root {
                    true => n.strongs.extend([(R1, to), (R2, to)]),
                    false => {
                        n.strongs.insert((A, to));
                    }
                }
                worlds += 1;
                for f in check(&n, Rule::FIXED) {
                    *fails.entry(f).or_insert(0) += 1;
                }
            }
        }
    }
    println!("{worlds} worlds: {fails:?}");
    assert!(fails.keys().all(|&f| f == "history"), "{fails:?}");
}
