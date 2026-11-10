#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Deposit items between readers (issues/net-shared-set.md, Deposits; spec/sync.md §10 Shared
//! set, spec/wire.md §11.2 Offer): an inbox blob goes as an Offer item to a connected node the
//! depositor judges a holder of the inbox, with no host and no third node.

use crate::connection_proofs::CHALLENGE;
use crate::net;
use crate::peers::reach_ed;
use crate::shared::{dial_as, offer, send};
use net::*;
use osis_base::{LabelId, Role, Tid};
use osis_node::sync::SyncConfig;
use osis_proto::{Code, Message};
use osis_proto::msg::OfferItem;

/// Two nodes of accounts that know each other (a group in common), connected directly, no host;
/// `b` with `cfg`.
fn known_pair(net: &mut Net, cfg: SyncConfig) -> (usize, usize) {
    let a = net.node(1, &[]);
    let b = net.add_node(2, cfg);
    reach_ed(net, b);
    net.group_at(a, &[(b, Role::Write)], vec![]);
    net.run();
    (a, b)
}

/// A group of `a`'s with one item, granted to `to` (a delivery to `to`'s inbox): the group and
/// the item.
fn granted(net: &mut Net, a: usize, to: Tid, rng: u64) -> (Tid, Tid) {
    let t = net.group_seeded(a, &[], vec![], rng);
    let item = net.item(a, t, t, "granted");
    net.run();
    net.grant(a, t, to, Role::Read);
    (t, item)
}

// issues/net-shared-set.md Tests: a grant between accounts that know each other arrives over
// their direct connection with no host or third node: the inbox blob goes as a Deposit item, the
// recipient's node takes it, opens the granted group's sync ID by the read secret it boxed, and
// the delivery leaves the granter's pending set
#[test]
fn a_grant_between_known_accounts_lands_over_a_direct_link_spec_sync_10() {
    let mut net = Net::new();
    let (a, b) = known_pair(&mut net, SyncConfig::default());
    let tb = net.tid(b);
    let (_, item) = granted(&mut net, a, tb, 2);
    net.run();
    assert_eq!(net.sync(a).pass_stats().deposits_sent, 1, "one Deposit item");
    assert_eq!(net.sync(a).deliveries_pending(), 0, "taken");
    assert_eq!(net.read(b, item), Some(s("granted")), "the grant reached b and its group opened");
}

// issues/net-shared-set.md Deposits: a depositor sends a Deposit item only where it judged the
// peer a holder of the inbox; a grant to an account no connected node proved stays pending and
// shown (one-way knowledge: the recipient's nodes do not know the granter), whatever time passes
#[test]
fn a_deposit_goes_to_no_peer_not_proved_a_holder_and_stays_pending_spec_sync_10() {
    let mut net = Net::new();
    let (a, _b) = known_pair(&mut net, SyncConfig::default());
    // c's records reach a (a holds c's card and inbox), c knows nothing of a
    let c = net.node(3, &[]);
    reach_ed(&mut net, c);
    net.pair(c, a);
    net.run();
    let tc = net.tid(c);
    let (t, item) = granted(&mut net, a, tc, 2);
    net.run();
    for _ in 0..3 {
        net.advance(3_600_000);
        net.run();
    }
    assert!(net.sync(a).proven_connections().iter().any(|(_, p)| p.is_empty()), "connected to c, which proved nothing to a");
    assert_eq!(net.sync(a).pass_stats().deposits_sent, 0, "no Deposit item to b, which proved no holder of c's inbox");
    assert_eq!(net.sync(a).deliveries_pending(), 1, "pending");
    assert!(net.sync(a).pending_about().iter().any(|x| x.contains(&t)), "shown as about the granted group");
    assert_eq!(net.read(c, item), None);
}

// spec/wire.md §11.2 Offer: a Deposit item is taken (0) only for an inbox the receiver proved an
// actor holding, signed by its head's deposit key; a sync ID it does not hold and a bad
// signature get the same 14
#[test]
fn a_deposit_item_is_taken_only_signed_for_a_held_inbox_spec_wire_11_2() {
    let mut net = Net::new();
    let (a, b) = known_pair(&mut net, SyncConfig::default());
    let tb = net.tid(b);
    let (inbox_actor, inbox) = net.engine(a).inbox_of_actor(&tb).unwrap().unwrap();
    let seed = net.engine(a).get_typed(&inbox_actor, &osis_schema::core_types::KEYS).unwrap().unwrap().deposit_seed.unwrap();
    let key = osis_crypto::deposit_key(&osis_crypto::Secret32::from_bytes(seed), &inbox.label);
    net.set_online(a, false);
    net.run();
    let mut p = dial_as(&mut net, a, b, CHALLENGE);
    send(&mut net, b, &mut p, Message::NoRecord { id: 1 << 31 });
    let blob = osis_proto::examples::Fixture::blob(7);
    let wrap = [5; osis_crypto::WRAP_LEN];
    let id = osis_label::blob_id(&blob);
    let item = |label: LabelId, sig| OfferItem::Deposit { label, blob: blob.clone(), wrap, sig };
    let elsewhere = LabelId([7; 16]);
    let good = osis_label::sign_deposit(&key, &inbox.label, &id, &wrap);
    let other = osis_label::sign_deposit(&key, &elsewhere, &id, &wrap);
    let bad = osis_label::sign_deposit(&osis_crypto::SigningSecret::from_seed(&osis_crypto::Secret32::from_bytes([9; 32])), &inbox.label, &id, &wrap);
    let ans = offer(&mut net, b, &mut p, vec![item(elsewhere, other), item(inbox.label, bad), item(inbox.label, good)]);
    assert_eq!(ans, vec![(Code::NOT_ADMITTED, None), (Code::NOT_ADMITTED, None), (Code::OK, None)]);
    assert!(net.sync(b).entries(&inbox.label).iter().any(|(x, _)| *x == id), "taken into the inbox");
}

// spec/sync.md §10 Shared set (Deposit items refused for now): a deposit past the receiver's
// peer budget is answered 5, kept pending and offered again after the back-off; it lands once the
// budget frees (the first deposit, opened at the receiver, no longer counts)
#[test]
fn a_deposit_refused_for_now_is_offered_again_and_lands_spec_sync_10() {
    let mut net = Net::new();
    let cfg = SyncConfig { peer_bytes: 6_000, ..SyncConfig::default() };
    let (a, b) = known_pair(&mut net, cfg);
    let tb = net.tid(b);
    let (_, one) = granted(&mut net, a, tb, 2);
    let (_, two) = granted(&mut net, a, tb, 3);
    net.run();
    assert_eq!((net.sync(a).pass_stats().deposits_sent, net.sync(a).deliveries_pending()), (2, 1), "the second refused for now, kept");
    for _ in 0..4 {
        net.advance(60_000);
        net.run();
    }
    assert_eq!(net.sync(a).pass_stats().deposits_sent, 3, "offered again once");
    assert_eq!(net.sync(a).deliveries_pending(), 0, "both taken");
    assert_eq!(net.read(b, one), Some(s("granted")));
    assert_eq!(net.read(b, two), Some(s("granted")));
}
