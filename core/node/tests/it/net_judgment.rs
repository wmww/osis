//! J and credentials (issues/net-shared-set.md, Words, step 3): holder/departed by proven key
//! actor over the rosters held; a proven account reaches nothing until a removal rotates the
//! account; `credentials(L)` by class.

use crate::net;
use net::*;
use osis_base::{LabelId, Role, Tid};
use osis_crypto::{Secret32, SigningSecret};
use osis_engine::flows::LinkSpec;
use osis_node::labeling::Judgment;
use osis_node::sync::credentials::{Credential, head_credentials};
use osis_node::sync::{Action, ConnId, Event};
use osis_node::identity::Identity;
use osis_engine::Mutation;
use osis_proto::{ClientConfig, ClientEvent, ClientInput, ClientOutput, ClientSession, Command, Prover};

const LISTENER: [u8; 32] = [0x42; 32];

/// Dials node `n` and proves `provers` on the connection; the Proved answer's actors.
fn prove(net: &mut Net, n: usize, provers: Vec<Prover>) -> (ConnId, usize) {
    let (conn, acts) = net.sync(n).accept(LISTENER, [0x43; 32]);
    let mut cs = ClientSession::new(ClientConfig { peer_static_key: LISTENER, challenge: [7; 32] });
    let now = net.now();
    let mut outs = cs.handle(now, ClientInput::Start);
    let mut acts = acts;
    let mut answered = 0;
    let mut proved_sent = false;
    loop {
        let mut moved = false;
        for o in std::mem::take(&mut outs) {
            match o {
                ClientOutput::Send(b) => {
                    acts.extend(net.sync(n).handle(Event::Bytes { conn, bytes: b }));
                    moved = true;
                }
                ClientOutput::Event(ClientEvent::Proved { proofs }) => answered = proofs.len(),
                _ => {}
            }
        }
        for a in std::mem::take(&mut acts) {
            if let Action::Send { conn: c, bytes } = a
                && c == conn
            {
                outs.extend(cs.handle(now, ClientInput::Bytes(bytes)));
                moved = true;
            }
        }
        if !moved {
            if proved_sent {
                return (conn, answered);
            }
            proved_sent = true;
            outs.extend(cs.handle(now, ClientInput::Command(Command::Prove(provers.clone()))));
        }
    }
}

pub(crate) fn account_node(net: &mut Net, seed: u64, host: usize) -> (usize, Tid) {
    let n = net.node(seed, &[host]);
    let addr = net.address(host);
    let (p, done) = net.engine(n).create_account(std::slice::from_ref(&addr)).unwrap();
    let acts = net.sync(n).carry_out(done).unwrap();
    net.actions(n, acts);
    net.run();
    (n, p.account)
}

/// A link on a fresh target of node `n`'s account: (k, k's label, the link's key actor).
pub(crate) fn link(net: &mut Net, n: usize, account: Tid) -> (Tid, LabelId, Tid, Secret32) {
    let e = net.engine(n);
    let mut m = Mutation::new();
    let target = e.new_thing(&mut m, account);
    e.commit(m).unwrap();
    let spec = LinkSpec { target, role: Role::Read, until: None, hosts: vec![], peers: vec![], single_use: false };
    let (l, _, done) = net.engine(n).create_link(&account, &spec).unwrap();
    let acts = net.sync(n).carry_out(done).unwrap();
    net.actions(n, acts);
    net.run();
    let actor = Identity::from_seed(l.seed.clone()).tid();
    (l.k, l.k_label, actor, l.seed)
}

fn one(net: &mut Net, n: usize, conn: ConnId, l: LabelId) -> Judgment {
    net.sync(n).judgments(conn, &[l]).unwrap()[&l]
}

fn static_entries(c: &[Credential]) -> Vec<[u8; 32]> {
    c.iter().filter_map(|x| if let Credential::StaticEntry(e) = x { Some(*e) } else { None }).collect()
}

fn entry_of(l: &LabelId, seed: &Secret32) -> [u8; 32] {
    osis_crypto::static_entry(l, &Identity::from_seed(seed.clone()).keys().signing.verifying_key())
}

// spec/sync.md §10, issues/net-shared-set.md Words (J, key actor listed by static entry): a link key on K's roster
// is a holder of K by its own proof; once removed from K it is departed, not unknown, and a
// peer that never held K is unknown; the gate follows: a holder is known, a departed actor is not
#[test]
fn key_actor_holder_then_departed_unknown_never_held_spec_sync_10() {
    let mut net = Net::new();
    let host = net.add_host();
    let (a, account) = account_node(&mut net, 1, host);
    let (k, label, l, seed) = link(&mut net, a, account);
    let b = net.node(2, &[host]);
    net.engine(b).hold_key_actor(seed.clone()).unwrap();
    let provers: Vec<Prover> = net.sync(b).provers().unwrap().into_iter().filter(|p| p.record.tid() == l).collect();
    let (conn, answered) = prove(&mut net, a, provers.clone());
    assert_eq!(one(&mut net, a, conn, label), Judgment::Holder, "L on K's roster");
    assert!(answered > 0, "a holder is known: proofs are shown");

    let done = net.engine(a).finalize_link(&k, &l).unwrap();
    let acts = net.sync(a).carry_out(done).unwrap();
    net.actions(a, acts);
    net.run();
    assert_eq!(one(&mut net, a, conn, label), Judgment::Departed, "removed from K");
    let (conn2, answered) = prove(&mut net, a, provers);
    assert_eq!(one(&mut net, a, conn2, label), Judgment::Departed, "a new connection too");
    assert_eq!(answered, 0, "a departed actor is not known");

    let stranger = SigningSecret::from_seed(&Secret32::from_bytes([0x55; 32]));
    let record = osis_base::CreationRecord::KeyActor { alg: 1, public_key: stranger.verifying_key().to_bytes().to_vec(), nonce: [1; 32], account: false };
    let (conn3, answered) = prove(&mut net, a, vec![Prover { key: stranger, record }]);
    assert_eq!(one(&mut net, a, conn3, label), Judgment::Unknown, "no path seen");
    assert_eq!(answered, 0, "an actor on no roster is unknown");
}

// spec/sync.md §10, issues/net-shared-set.md Words: departed is by path: a key actor on a team that is removed
// from the thing has left it too; it never counts a thing whose secrets are not its own actor's
#[test]
fn departed_through_a_roster_path_spec_sync_10() {
    let mut net = Net::new();
    let a = net.node(1, &[]);
    let me = net.tid(a);
    let actor = Tid::from_bytes([9; 15]);
    let team = {
        let e = net.engine(a);
        let mut m = Mutation::new();
        let t = e.new_thing(&mut m, me);
        e.commit(m).unwrap();
        set_edge(e, t, actor, Role::Admin);
        t
    };
    let g = net.group_at(a, &[], vec![]);
    set_edge(net.engine(a), g, team, Role::Read);
    assert_eq!(net.engine(a).core.judge([actor]).of(&g), Judgment::Holder, "through the team");
    let rec = recipients_of(net.engine(a), &[(me, Role::Admin)]);
    remove_holder(net.engine(a), g, team, &rec, 90);
    assert_eq!(net.engine(a).core.judge([actor]).of(&g), Judgment::Departed, "the team left g");

    set_edge(net.engine(a), g, team, Role::Read);
    assert_eq!(net.engine(a).core.judge([actor]).of(&g), Judgment::Holder, "a grant after the removal stands");

    // the other end of the path: the actor removed from a roster that still holds the thing
    let team2 = net.group_seeded(a, &[], vec![], 3);
    set_edge(net.engine(a), team2, actor, Role::Admin);
    let g2 = net.group_seeded(a, &[], vec![], 4);
    set_edge(net.engine(a), g2, team2, Role::Read);
    assert_eq!(net.engine(a).core.judge([actor]).of(&g2), Judgment::Holder, "through its roster");
    let rec = recipients_of(net.engine(a), &[(me, Role::Admin)]);
    remove_holder(net.engine(a), team2, actor, &rec, 91);
    assert_eq!(net.engine(a).core.judge([actor]).of(&g2), Judgment::Departed, "off the roster that holds g2");
}

// issues/net-shared-set.md step 3 (security rule), spec/sync.md §10: a node's own key reaches
// what the rosters HELD here say: a node on its devices actor's roster is a holder of what the
// roster's owner holds only once that roster is held here
#[test]
fn node_key_reaches_only_through_rosters_held_spec_sync_10() {
    let mut net = Net::new();
    let host = net.add_host();
    let (a, _) = account_node(&mut net, 1, host);
    let (s, account) = account_node(&mut net, 3, host);
    let ts = net.node_tid(s);
    let g = net.group_at(a, &[], vec![]);
    set_edge(net.engine(a), g, account, Role::Read);
    assert_eq!(net.engine(a).core.judge([ts]).of(&g), Judgment::Unknown, "the node's link to its account is not held");
    let _ = account;
}

// spec/sync.md §2, issues/net-shared-set.md Words: an account on a roster has no static entry
#[test]
fn an_account_on_the_roster_has_no_static_entry_spec_sync_2() {
    let mut net = Net::bare();
    let host = net.add_host();
    let (a, _) = account_node(&mut net, 1, host);
    let addr = net.address(host);
    let (created, done) = net.engine(a).create_account(std::slice::from_ref(&addr)).unwrap();
    let acts = net.sync(a).carry_out(done).unwrap();
    net.actions(a, acts);
    let g = net.group_at(a, &[], vec![]);
    set_edge(net.engine(a), g, created.account, Role::Read);
    let gl = net.group_labels(a).iter().find(|(x, _)| *x == g).unwrap().1.id;
    assert!(net.engine(a).core.is_key_actor(&created.account));
    assert!(static_entries(&net.sync(a).credentials(&[gl]).unwrap().remove(&gl).unwrap()).is_empty());
}

// spec/sync.md §10: an account proved at an epoch open here is judged by its roles: J knows it on a
// thing it holds here, and the prover gets a proof back
#[test]
fn proven_account_is_judged_by_its_roles_spec_sync_10() {
    let mut net = Net::new();
    let host = net.add_host();
    let (a, _) = account_node(&mut net, 1, host);
    let (s, account) = account_node(&mut net, 3, host);
    let ts = net.tid(s);
    let g = net.group_at(a, &[], vec![]);
    set_edge(net.engine(a), g, account, Role::Read);
    let label = net.group_labels(a).iter().find(|(x, _)| *x == g).unwrap().1.id;
    assert_eq!(net.engine(a).core.judge([account]).of(&g), Judgment::Holder, "the account is on g's roster: J reads it");
    let provers = net.sync(s).provers().unwrap();
    let (conn, answered) = prove(&mut net, a, provers);
    let proven = net.sync(a).proven(conn).unwrap();
    assert!(proven.contains(&account) && proven.contains(&ts), "reported: {proven:?}");
    assert_eq!(one(&mut net, a, conn, label), Judgment::Holder, "J reads the proven account's role");
    assert!(answered > 0, "a known actor gets a proof back");
}

// spec/sync.md §2, issues/net-shared-set.md Words, credentials table: a reader holds a read secret per current
// epoch and a static entry per key actor on the roster; adding and removing a key actor, and a
// rotation, change the credentials
#[test]
fn credentials_follow_the_roster_spec_sync_2() {
    let mut net = Net::new();
    let host = net.add_host();
    let (a, account) = account_node(&mut net, 1, host);
    let (k, label, l, seed) = link(&mut net, a, account);
    let entry = entry_of(&label, &seed);
    let before = net.sync(a).credentials(&[label]).unwrap().remove(&label).unwrap();
    let values: Vec<[u8; 32]> = before.iter().map(Credential::match_value).collect();
    assert!(static_entries(&before).contains(&entry), "L's static entry: {values:x?}");
    assert!(before.iter().any(|c| matches!(c, Credential::ReadSecret(_))), "the read secret");
    let done = net.engine(a).finalize_link(&k, &l).unwrap();
    let acts = net.sync(a).carry_out(done).unwrap();
    net.actions(a, acts);
    net.run();
    let after = net.sync(a).credentials(&[label]).unwrap().remove(&label).unwrap();
    assert!(!static_entries(&after).contains(&entry), "removed: L's entry goes");
    let after_values: Vec<[u8; 32]> = after.iter().map(Credential::match_value).collect();
    assert_ne!(values, after_values, "the set changed");

    // a node on the roster has a claim key, not a static entry
    let b = net.node(2, &[host]);
    let g = net.group_at(a, &[(b, Role::Read)], vec![]);
    let gl = net.group_labels(a).iter().find(|(x, _)| *x == g).unwrap().1.id;
    assert!(static_entries(&net.sync(a).credentials(&[gl]).unwrap().remove(&gl).unwrap()).is_empty(), "a node has no static entry");
    let values = |net: &mut Net| net.sync(a).credentials(&[gl]).unwrap().remove(&gl).unwrap().iter().map(Credential::match_value).collect::<Vec<_>>();
    let before_rotation = values(&mut net);
    let me = net.tid(a);
    let rec = recipients_of(net.engine(a), &[(me, Role::Admin)]);
    rotation(net.engine(a), g, &rec, 77, false);
    let rotated = values(&mut net);
    assert_eq!(rotated.len(), before_rotation.len(), "one current epoch again");
    assert_ne!(rotated, before_rotation, "the rotation's secret");
}

// spec/sync.md §2, issues/net-shared-set.md Words, a peer that cannot read: a served head's credentials are its
// sync and deposit keys and every claim of its claim set
#[test]
fn head_credentials_are_sync_deposit_and_claims_spec_sync_2() {
    let f = osis_proto::examples::Fixture::new(1);
    let (step, claims) = (f.genesis, f.genesis_claims);
    let c = head_credentials(&step, &claims);
    assert!(matches!(c[0], Credential::SyncKey(k) if k == step.keys.sync.to_bytes()));
    assert!(matches!(c[1], Credential::DepositKey(k) if k == step.keys.deposit.to_bytes()));
    assert_eq!(c.len(), 2 + claims.claims.len());
}

// spec/sync.md §10, issues/net-shared-set.md Costs: J counts one pass of the history per actor per use, whatever number
// of things is asked about
#[test]
fn judgment_work_does_not_grow_with_things_asked_spec_sync_10() {
    let run = |n: usize| {
        let mut net = Net::new();
        let a = net.node(1, &[]);
        let actor = Tid::from_bytes([7; 15]);
        let mut things = Vec::new();
        for i in 0..n {
            let g = net.group_seeded(a, &[], vec![], i as u64 + 1);
            set_edge(net.engine(a), g, actor, Role::Read);
            things.push(g);
        }
        let other = Tid::from_bytes([8; 15]);
        let lone = net.group_seeded(a, &[], vec![], n as u64 + 1);
        set_edge(net.engine(a), lone, other, Role::Read);
        // the actor holds every thing; nothing departed
        let tl = net.engine(a).core.timelines.get(&things[0]).unwrap();
        let (r0, e0) = (tl.roles_walks(), tl.ever_walks());
        let core = &net.engine(a).core;
        let mut j = core.judge([actor]);
        assert!(things.iter().all(|t| j.of(t) == Judgment::Holder));
        assert_eq!(j.of(&lone), Judgment::Unknown, "not reached");
        // what it does not hold: the ended-path walk runs once, not per thing
        assert!((0..n).all(|i| j.of(&Tid::from_bytes([(i & 255) as u8, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3])) == Judgment::Unknown));
        let tl = core.timelines.get(&things[0]).unwrap();
        (tl.roles_walks() - r0, tl.ever_walks() - e0)
    };
    let (small, big) = (run(8), run(80));
    assert_eq!(small, big, "work at n and 10n");
    assert!(small.0 <= 1 && small.1 <= 1, "one walk of the actor, once: {small:?}");
}
