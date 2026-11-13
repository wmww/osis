#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Re-seals reach the holder they box (spec/permissions.md §3 Re-seal).

use crate::net;
use net::*;
use osis_base::{Ak, Role};
use osis_node::flows::Demotion;

// spec/permissions.md §3 (Re-seal, delivered as an inbox blob): a grantee left out of a rotation
// whose rotator had not yet learned its grant reads what is written after, once that rotator
// re-seals it. F (f0 admin, f1 admin, x reader) administers T; f0 grants t1 read on T while f1 is
// away; f1, offline, demotes x from F, then comes back with f0 gone: its first pass of T's label
// rotates T (F's box is stale) before it opens the grant, then it re-seals t1 at the new epoch,
// in a commit under T's label t1 cannot open; the inbox copy reaches t1 (its account's inbox is
// at the host: an inbox listing no host, `hosted_nodes`' default, takes grants and re-seals only
// over a direct connection to a node of it, spec/sync.md §5 Sending).
#[test]
fn reseal_reaches_grantee_left_out_spec_permissions_3() {
    let mut net = Net::new();
    net.home_at_hosts = true;
    let host = net.add_host();
    let [f0, f1, t1, x] = std::array::from_fn(|i| net.node(i as u64 + 1, &[host]));
    net.run();
    let f = net.group(f0, &[(f1, Role::Admin), (x, Role::Read)], &[host]);
    let t = net.item(f0, f, f, "first");
    net.run();
    net.set_online(f1, false);
    net.pair(t1, f0);
    let t1t = net.tid(t1);
    net.grant(f0, t, t1t, Role::Read);
    net.advance(15_000);
    assert_eq!(net.read(t1, t), Some(s("first")), "t1 reads T");
    let xt = net.tid(x);
    let done = net.engine(f1).demote(&f, &Demotion { holder: xt, new: None, retain: None }).unwrap();
    let acts = net.sync(f1).carry_out(done).unwrap();
    net.actions(f1, acts);
    net.set_online(f0, false);
    net.set_online(f1, true);
    for _ in 0..3 {
        net.advance(15_000);
    }
    // the case: f1 rotated T, then wrote a re-seal (secrets, no keyset) of T
    let f1t = net.tid(f1);
    let (keys, secrets) = (Ak::new("keys.0").unwrap(), Ak::new("secrets.0").unwrap());
    let mut rotated = false;
    let mut resealed = false;
    for id in net.engine(f1).commit_ids() {
        let h = net.engine(f1).header(&id).unwrap();
        let on = |ak: &Ak| h.aspects.iter().any(|a| a.tid == t && a.ak == *ak);
        if h.author == f1t {
            rotated |= on(&keys);
            resealed |= on(&secrets) && !on(&keys);
        }
    }
    assert!(rotated && resealed, "f1 rotated T and re-sealed it");
    net.write(f1, t, "after");
    for _ in 0..3 {
        net.advance(15_000);
    }
    assert_eq!(net.read(t1, t), Some(s("after")), "t1 reads what f1 wrote after re-sealing it");
    // f0 back (its own pass of T may re-key beside f1's): t1 reads what f0 writes
    net.set_online(f0, true);
    for _ in 0..3 {
        net.advance(15_000);
    }
    net.write(f0, t, "later");
    for _ in 0..3 {
        net.advance(15_000);
    }
    assert_eq!(net.read(f1, t), Some(s("later")));
    assert_eq!(net.read(t1, t), Some(s("later")), "t1 reads what f0 wrote after the fork");
}

