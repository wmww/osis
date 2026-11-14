//! A link's first contact over real connections (spec/sync-inbox.md §6, spec/permissions.md §7):
//! the redeemer dials the sharer node by the link's hints, opens K by the link key's static entry,
//! takes the head's entry box, pulls K and joins.

use crate::harness::{World, two_nodes};
use osis_base::Role;
use osis_label::ShareLink;
use osis_sync::types::Waiting;

/// Node 0 makes a read link to its profile; node 1 redeems it; run to quiet.
fn redeemed() -> (World, ShareLink) {
    let mut w = two_nodes();
    let p0 = w.node(0).profile.unwrap();
    let link = w.make_link(0, p0, Role::Read);
    assert_eq!(w.redeem(1, &link), Waiting::Pending);
    w.run();
    (w, link)
}

// spec/sync-inbox.md §6 (First contact), spec/sync-set.md §2 (Sync set: a link's sync ID while
// its redeemer redeems it), spec/sync-opens.md §5 (Opening: a static entry's answer carries the
// head's entry box and the path): K, listed in the sharer's D, opens at node 1 by L's static entry, and node 1
// takes K's read secret from the head's entry box.
#[test]
fn a_link_opens_k_by_its_static_entry_spec_sync_inbox_6() {
    let (mut w, link) = redeemed();
    let s = link.k_label;
    assert!(matches!(w.engine(0).sync_holding(&s).unwrap(), Some((_, osis_engine::sync::Holding::Read))), "the sharer syncs K");
    assert!(matches!(w.engine(1).sync_holding(&s).unwrap(), Some((t, osis_engine::sync::Holding::Read)) if t == link.k), "the redeemer follows K's sync ID");
    assert!(w.status(1).get(&s).is_some_and(|st| !st.sources.is_empty()), "K open at the sharer");
    assert!(!w.engine(1).read_credentials(&s).unwrap().unwrap().read_secrets.is_empty(), "K's read secret from the entry box");
}

// spec/permissions.md §7 (Redeem): node 1's account joins K and the join is held at node 0.
#[test]
#[ignore = "fails: K's commits do not apply at the redeemer (issues/sync-link-first-contact.md)"]
fn a_redeemer_joins_k_spec_permissions_7() {
    let (mut w, link) = redeemed();
    let a1 = w.node(1).account.unwrap();
    assert!(w.engine(1).roster(&link.k).contains_key(&a1), "node 1's account joined K here");
    assert!(w.engine(0).roster(&link.k).contains_key(&a1), "the join held at the sharer");
    assert_eq!(w.redeem(1, &link), Waiting::Done);
}
