//! Connection-lived things (issues/connection-lived-data.md): the protocol at quiescence against
//! the rule settled on the connection graph. spec: none yet (design).
use held_model::connlived::*;
use held_model::gen::Rng;

fn sweep(blind: Blind, unread_pct: u64, runs: u64, settled: bool, alt: bool) -> Vec<(u64, Diff, &'static str)> {
    let mut out = Vec::new();
    for seed in 0..runs {
        let mut r = Rng::new(seed);
        let w = world(&mut r, 6, 3, 4, blind, unread_pct);
        let h = history(&mut r, &w, 40);
        if let Err((d, what)) = run(&w, &h, &mut r, settled, alt) {
            out.push((seed, d, what));
        }
    }
    out
}

/// The rule holds over random histories with the protocol that tells each neighbour the best route
/// avoiding it, where nodes keeping a thing unread judge its keepers too.
#[test]
fn random_histories_hold_by_the_rule() {
    for u in [0, 30] {
        let f = sweep(Blind::Judges, u, 200, false, true);
        assert!(f.is_empty(), "{:?}", f.first());
    }
}

/// Failure counts of every variant (by hand: the findings in issues/connection-lived-data.md).
#[test]
#[ignore]
fn explore() {
    for (settled, alt) in [(false, false), (false, true), (true, false)] {
        for (b, u) in [(Blind::Judges, 0), (Blind::Judges, 30), (Blind::Keeps, 30), (Blind::Relays, 30)] {
            let f = sweep(b, u, 2000, settled, alt);
            eprintln!("settled {settled} alt {alt} {b:?} unread {u}%: {} of 2000 fail; first {:?}", f.len(), f.first());
        }
    }
}

fn w(account: &[A], keepers: &[&[A]], creator: &[N], share: &[&[Share]], blind: Blind) -> World {
    World {
        account: account.to_vec(),
        keepers: keepers.iter().map(|k| k.iter().copied().collect()).collect(),
        creator: creator.to_vec(),
        share: share.iter().map(|s| s.to_vec()).collect(),
        blind,
    }
}

fn play(w: &World, h: &[Event], alternates: bool) -> (Oracle, Net) {
    let mut r = Rng::new(0);
    let (mut o, mut net) = (Oracle::new(w), Net::new(w));
    net.alternates = alternates;
    for &e in h {
        o.apply(w, e);
        net.apply(w, e);
        net.drain(w, &mut r);
    }
    (o, net)
}

use Event::*;
use Share::*;

/// A keeper leaving drops the thing at every node at once, a loop of readers included: no node
/// keeps it alive for another.
#[test]
fn a_departed_keeper_drops_its_things_through_a_loop() {
    // Node 0 (account 0) makes t; readers 1, 2, 3 (account 1) in a triangle, 1 connected to 0.
    let w = w(&[0, 1, 1, 1], &[&[0]], &[0], &[&[Reads], &[Reads], &[Reads], &[Reads]], Blind::Judges);
    let h = [Connect(1, 2), Connect(2, 3), Connect(3, 1), Create(0), Connect(0, 1)];
    let (_, net) = play(&w, &h, true);
    assert!((1..4).all(|n| net.has[n].contains(&0)));
    let (o, net) = play(&w, &[&h[..], &[Disconnect(0, 1)]].concat(), true);
    assert!((1..4).all(|n| !net.has[n].contains(&0) && !o.has[n].contains(&0)));
    assert!(net.has[0].contains(&0));
}

/// A route withdrawn while another path to the keeper stays drops a copy the rule keeps, when the
/// protocol tells every neighbour one best table: node 3's best route to account 1 runs through
/// node 0, so node 0 learns no alternative and drops t when node 5 goes; node 3 does not share t,
/// so nothing brings it back. Told the best route avoiding it, node 0 keeps t.
#[test]
fn a_withdrawn_route_with_an_alternative_drops_nothing() {
    // Accounts: node 0 -> 0, 1 -> 1, 2 -> 2, 3 -> 2, 5 -> 1 (node 4 unused). t kept by account 1.
    let share: &[&[Share]] = &[&[Reads], &[Reads], &[Reads], &[No], &[No], &[Reads]];
    let w = w(&[0, 1, 2, 2, 2, 1], &[&[1]], &[1], share, Blind::Judges);
    let h = [Create(0), Connect(1, 5), Connect(5, 0), Connect(0, 3), Connect(3, 2), Connect(2, 1), Restart(5)];
    let (o, plain) = play(&w, &h, false);
    assert!(o.has[0].contains(&0));
    assert!(!plain.has[0].contains(&0), "the plain protocol drops it");
    let (_, alt) = play(&w, &h, true);
    assert!(alt.has[0].contains(&0));
}

/// A node keeping t unread that holds its copy until it restarts brings t back after the keeper
/// left: the keeper's node restarts (losing t), reader 2 drops it, node 1 keeps it, and the
/// keeper's node coming back takes it from node 1 and so does reader 2.
#[test]
fn an_unread_copy_kept_without_keepers_comes_back() {
    let share: &[&[Share]] = &[&[Reads], &[Unread], &[Reads]];
    let h = [Create(0), Connect(0, 1), Connect(1, 2), Restart(0), Connect(0, 1)];
    let keeps = w(&[0, 1, 2], &[&[0]], &[0], share, Blind::Keeps);
    let (o, net) = play(&keeps, &h, true);
    assert!(!o.has[0].contains(&0) && !o.has[2].contains(&0));
    assert!(net.has[0].contains(&0) && net.has[2].contains(&0), "resurrected");
    let judges = World { blind: Blind::Judges, ..keeps };
    let (_, net) = play(&judges, &h, true);
    assert!(!net.has[0].contains(&0) && !net.has[2].contains(&0));
}

/// A node keeping t unread that holds nothing (passing copies on like a relay-only signal) leaves
/// a reader joining behind it without t while the keeper is connected.
#[test]
fn a_relaying_unread_node_starves_a_late_reader() {
    let share: &[&[Share]] = &[&[Reads], &[Unread], &[Reads]];
    let h = [Create(0), Connect(0, 1), Connect(1, 2)];
    let relays = w(&[0, 1, 2], &[&[0]], &[0], share, Blind::Relays);
    let (o, net) = play(&relays, &h, true);
    assert!(o.has[2].contains(&0));
    assert!(!net.has[2].contains(&0));
}

/// The connected set's cost: a hub (node 0) with n leaves of n accounts, one more leaf connecting.
/// Route entries sent grow with n squared (every leaf hears the newcomer, and the newcomer every
/// account); things judged are those kept by an account that came, here one.
#[test]
fn a_connect_at_a_hub_costs_n_squared_route_entries() {
    let cost = |n: usize| {
        let account: Vec<A> = (0..n + 2).collect();
        let keepers: Vec<&[A]> = vec![&[1]];
        let share: Vec<Vec<Share>> = (0..n + 2).map(|_| vec![Reads]).collect();
        let share: Vec<&[Share]> = share.iter().map(|s| &s[..]).collect();
        let w = w(&account, &keepers, &[1], &share, Blind::Judges);
        let mut h: Vec<Event> = (1..=n).map(|l| Connect(0, l)).collect();
        h.insert(0, Create(0));
        let (_, mut net) = play(&w, &h, true);
        let before = net.work.clone();
        net.apply(&w, Connect(0, n + 1));
        net.drain(&w, &mut Rng::new(0));
        (net.work.route_msgs - before.route_msgs, net.work.route_entries - before.route_entries, net.work.judged - before.judged)
    };
    let (small, large) = (cost(5), cost(50));
    eprintln!("connect at a hub of 5: {small:?}; of 50: {large:?}");
    assert_eq!((small.0, large.0), (2 + 5, 2 + 50));
    assert!(large.1 >= 50 * 50, "{large:?}");
}
