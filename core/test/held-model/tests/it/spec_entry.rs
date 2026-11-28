//! First entry under stubs (held_model::closure::entry; notes/stubs.md): hand worlds
//! for the stub rules, and the properties over random histories, each failing under its control.
use held_model::closure::entry::*;
use held_model::closure::{Kind, Role, World, T};

/// Account A (0), two nodes (things 1, 3; roots 2, 4) holding write on A, their roots strongly
/// referencing A, and things 5.. independent. Both nodes paired: A's values handed over, taken
/// in, gone.
fn account(things: usize) -> Net {
    let mut kinds = vec![Kind::Independent, Kind::Independent, Kind::Dependent(1), Kind::Independent, Kind::Dependent(3)];
    kinds.extend(std::iter::repeat_n(Kind::Independent, things));
    let mut net = Net { w: World { kinds, ..World::default() }, nodes: vec![Node { thing: 1, root: 2 }, Node { thing: 3, root: 4 }], ..Net::default() };
    for n in net.nodes.clone() {
        net.w.grants.insert((n.thing, A), Role::Write);
        net.strongs.insert((n.root, A));
    }
    let pair: Vec<Signal> = (0..2).map(|i| Signal { at: At::Node(i), holder: net.nodes[i].thing, target: A }).collect();
    net.signals.extend(pair.iter().copied());
    net.settle(Rule::SPEC);
    net.signals.clear();
    net
}

const A: T = 0;
const X: T = 5;
const R: T = 6;

fn holds(net: &Net, rule: Rule, i: usize) -> (bool, bool) {
    let h = net.held(rule, i);
    (h.whole.contains(&X), h.stubs.contains(&X))
}

/// A record grant is the thing's own data: R is X's mint admin, A holds sync on X and read on R,
/// each told, and A strongly references X. Node 0 holds X kept unread (by A's grant) and R as the
/// signal's stub (A reads its role entries): X's record names R, so node 0 reads X through R.
/// Without the record grants known (X's roster is no read of A's), it keeps X unread.
#[test]
fn entry_a_record_grant_is_known_where_its_thing_is_held() {
    for records in [true, false] {
        let mut net = account(2);
        net.w.grants.extend([((R, X), Role::Admin), ((A, X), Role::Sync), ((A, R), Role::Read)]);
        if records {
            net.w.records.insert((R, X));
        }
        net.signals.extend([Signal { at: At::Node(0), holder: A, target: X }, Signal { at: At::Node(0), holder: A, target: R }]);
        net.strongs.insert((A, X));
        net.settle(Rule::SPEC);
        let h = net.held(Rule::SPEC, 0);
        assert_eq!((h.whole.contains(&X), h.unread.contains(&X)), (records, !records), "record grants known: {records}");
        assert!(check(&net, Rule::SPEC).is_empty());
    }
}

/// Pairing: each node takes A in from the values alone and keeps it once they are gone.
#[test]
fn entry_pairing_takes_the_account_in() {
    let net = account(1);
    for i in 0..2 {
        assert!(net.held(Rule::SPEC, i).whole.contains(&A));
    }
    assert!(check(&net, Rule::SPEC).is_empty());
}

/// A grant nobody is told of holds nothing: A holds read on X, nothing references X, no signal.
/// The control (entry by grants: a reader of A holds everything A holds a role on) enters X.
#[test]
fn entry_an_unsignalled_grant_holds_nothing() {
    let mut net = account(1);
    net.w.grants.insert((A, X), Role::Read);
    net.settle(Rule::SPEC);
    assert_eq!(holds(&net, Rule::SPEC, 0), (false, false));
    let ctl = Rule { by_grants: true, ..Rule::SPEC };
    assert_eq!(holds(&net, ctl, 0), (false, true));
    assert!(check(&net, ctl).iter().any(|f| f.prop == "no grant-driven entry"));
}

/// Signal → reference → sync: node 0 holds a signal for X (granted to A), A strongly references
/// X, the signal goes. Both nodes read X (siblings): node 0 logged X's stub under A while it held
/// the signal. Logged only in node 0's local part instead (`Rule::PRIVATE`: its root's walk
/// goes through A to X), node 1 holds nothing.
#[test]
fn entry_a_signal_then_a_reference_outlives_the_signal() {
    for (rule, expect) in [(Rule::SPEC, [(true, false), (true, false)]), (Rule::PRIVATE, [(true, false), (false, false)])] {
        let mut net = account(1);
        net.w.grants.insert((A, X), Role::Read);
        let s = Signal { at: At::Node(0), holder: A, target: X };
        net.signals.insert(s);
        net.settle(rule);
        assert_eq!(holds(&net, rule, 0), (false, true), "{rule:?}: the signal alone gives the stub");
        net.strongs.insert((A, X));
        net.settle(rule);
        net.signals.remove(&s);
        net.settle(rule);
        assert_eq!([holds(&net, rule, 0), holds(&net, rule, 1)], expect, "{rule:?}");
    }
    let mut net = account(1);
    net.w.grants.insert((A, X), Role::Read);
    net.signals.insert(Signal { at: At::Node(0), holder: A, target: X });
    net.settle(Rule::PRIVATE);
    net.strongs.insert((A, X));
    net.settle(Rule::PRIVATE);
    net.signals.clear();
    net.settle(Rule::PRIVATE);
    let props: Vec<&str> = check(&net, Rule::PRIVATE).iter().map(|f| f.prop).collect();
    assert_eq!(props, ["siblings"]);
}

/// Without a reference, a signal's stub lasts as long as the signal.
#[test]
fn entry_a_signal_alone_lasts_while_held() {
    let mut net = account(1);
    net.w.grants.insert((A, X), Role::Read);
    let s = Signal { at: At::Thing(A), holder: A, target: X };
    net.signals.insert(s);
    net.settle(Rule::SPEC);
    assert_eq!([holds(&net, Rule::SPEC, 0), holds(&net, Rule::SPEC, 1)], [(false, true); 2], "an inbox's signal reaches every reader");
    net.signals.remove(&s);
    net.settle(Rule::SPEC);
    assert_eq!(holds(&net, Rule::SPEC, 0), (false, false));
}

/// A weak brings the stub, followed, and never the content.
#[test]
fn entry_a_weak_keeps_the_stub() {
    let mut net = account(1);
    net.w.grants.insert((A, X), Role::Read);
    net.signals.insert(Signal { at: At::Node(0), holder: A, target: X });
    net.weaks.insert((A, X));
    net.settle(Rule::SPEC);
    net.signals.clear();
    net.settle(Rule::SPEC);
    assert_eq!([holds(&net, Rule::SPEC, 0), holds(&net, Rule::SPEC, 1)], [(false, true); 2]);
}

/// Two hops: A reads realm R, R reads X, A references X and not R. Node 0 reads R through its own
/// root; A's unit carries X whole and R as a chain stub, so node 1 holds R's stub without any
/// reference to R. R's grant on X removed, X leaves both (the removal is in X's role entries).
#[test]
fn entry_a_two_hop_chain_brings_the_holder_stub() {
    let mut net = account(2);
    net.w.grants.insert((A, R), Role::Read);
    net.w.grants.insert((R, X), Role::Read);
    net.signals.insert(Signal { at: At::Node(0), holder: A, target: R });
    net.strongs.insert((2, R));
    net.settle(Rule::SPEC);
    net.signals.insert(Signal { at: At::Thing(R), holder: R, target: X });
    net.strongs.insert((A, X));
    net.settle(Rule::SPEC);
    net.signals.clear();
    net.settle(Rule::SPEC);
    let h1 = net.held(Rule::SPEC, 1);
    assert!(h1.whole.contains(&X) && h1.stubs.contains(&R) && !h1.whole.contains(&R), "{h1:?}");
    assert!(check(&net, Rule::SPEC).is_empty(), "{:?}", check(&net, Rule::SPEC));
    net.w.grants.remove(&(R, X));
    net.settle(Rule::SPEC);
    for i in 0..2 {
        assert_eq!(holds(&net, Rule::SPEC, i), (false, false), "node {i}");
    }
}

/// A public thing referenced: its stub (with the public's open box) opens it to every reader of
/// the unit, logged by the node that held it.
#[test]
fn entry_a_public_thing_referenced_is_read() {
    let mut net = account(1);
    net.w.public.insert(X);
    net.signals.insert(Signal { at: At::Node(0), holder: 1, target: X });
    net.strongs.insert((A, X));
    net.settle(Rule::SPEC);
    net.signals.clear();
    net.settle(Rule::SPEC);
    assert_eq!(holds(&net, Rule::SPEC, 1), (true, false));
}

/// Held at sync only through a holder: the strong keeps the thing unread by the node's own role,
/// never its content.
#[test]
fn entry_a_strong_at_sync_keeps_the_thing_unread() {
    let mut net = account(1);
    net.w.grants.insert((A, X), Role::Sync);
    net.signals.insert(Signal { at: At::Node(0), holder: A, target: X });
    net.strongs.insert((A, X));
    net.settle(Rule::SPEC);
    net.signals.clear();
    net.settle(Rule::SPEC);
    let h = net.held(Rule::SPEC, 1);
    assert!(h.unread.contains(&X) && !h.whole.contains(&X), "{h:?}");
}

/// A sync chain is learned only from a cut a roster reader logged: A holds sync on R, R sync on X,
/// A strongly references both. X's stub logged under A by entries alone teaches A's readers only
/// A's own grant (none), so nothing of X is held; logged by a reader of X's role entries, its cut
/// names R and X is kept unread.
#[test]
fn entry_a_sync_chain_is_learned_from_a_roster_readers_cut() {
    for (entry_only, unread) in [(true, false), (false, true)] {
        let mut net = account(2);
        net.w.grants.insert((A, R), Role::Sync);
        net.w.grants.insert((R, X), Role::Sync);
        net.strongs.extend([(A, R), (A, X)]);
        net.logged.extend([(A, R), (A, X)]);
        if entry_only {
            net.entry_only.insert((A, X));
        }
        let h = net.held(Rule::SPEC, 1);
        assert_eq!((h.unread.contains(&X), h.stubs.contains(&X)), (unread, false), "entry only: {entry_only}: {h:?}");
    }
}

const SEEDS: u64 = 120;
const LEN: usize = 14;

/// The properties over random histories; each control fails its property on some seed.
#[test]
fn entry_properties_hold_and_each_control_fails() {
    for seed in 0..SEEDS {
        let f = history(seed, LEN, Rule::SPEC);
        assert!(f.is_empty(), "seed {seed}: {f:?}");
    }
    let controls = [
        ("founded", Rule { fix: Fix::Greatest, ..Rule::SPEC }),
        ("readers agree", Rule { reader_view: true, ..Rule::SPEC }),
        ("no grant-driven entry", Rule { by_grants: true, ..Rule::SPEC }),
        ("siblings", Rule::PRIVATE),
        ("chains", Rule { chains: Chains::Up, ..Rule::SPEC }),
        ("signal lifetime", Rule { keep_fetched: true, ..Rule::SPEC }),
    ];
    for (prop, rule) in controls {
        assert!((0..SEEDS).any(|s| history(s, LEN, rule).iter().any(|(_, f)| f.prop == prop)), "control of {prop}");
    }
}

