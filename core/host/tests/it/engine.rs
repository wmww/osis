//! The engine's blobs in the hub's store (`osis_store::CipherHost`, issues/net-one-peer.md step
//! 4): a blob the node reads and serves is stored once, and each holder's drop leaves it to the
//! other.

use crate::common::*;
use osis_crypto::SeededRng;
use osis_host::HostPolicy;
use osis_label::Prefix;
use osis_proto::msg::DeleteItem;
use osis_proto::*;
use osis_store::CipherHost;

fn blob(n: u8) -> Vec<u8> {
    let p = Prefix::new([n; 16], None, vec![]).unwrap();
    osis_label::frame(&p, &[n; 300], &mut SeededRng::from_seed([n; 32])).unwrap().1
}

// spec: none (notes/serving.md, HostStore): one blob area for the engine and the hub
#[test]
fn a_blob_read_and_served_is_stored_once() {
    let mut w = World::new();
    let h = w.add_hub(HostPolicy::default());
    let a = w.connect(h);
    let l = Label::new(3);
    w.setup(a, &l);
    w.open(a, &l);
    let blobs = |w: &World| w.backends[h].held_split().2;
    let (x, y) = (blob(1), blob(2));
    let (xi, yi) = (osis_label::blob_id(&x), osis_label::blob_id(&y));
    // served first, then held by the engine: one copy; the hub's delete leaves the engine's
    w.run(a, Command::Upload { label: l.id, entries: vec![l.entry(x.clone())] });
    assert_eq!(blobs(&w), 1);
    {
        let mut s = w.hubs[h].store();
        assert!(!s.held(&xi).unwrap());
        assert!(s.hold(&xi, x.clone(), false).unwrap());
        s.commit().unwrap();
    }
    assert_eq!(blobs(&w), 1, "stored once");
    let item = DeleteItem::sign(&l.head_keys().delete, &l.id, xi).unwrap();
    w.run(a, Command::Delete { label: l.id, items: vec![item] });
    assert_eq!(blobs(&w), 1, "the engine still holds it");
    {
        let mut s = w.hubs[h].store();
        s.release(&xi, false).unwrap();
        s.commit().unwrap();
    }
    assert_eq!(blobs(&w), 0, "neither holds it");
    // held by the engine first, then served: the engine's release leaves the hub's
    {
        let mut s = w.hubs[h].store();
        assert!(s.hold(&yi, y.clone(), false).unwrap());
        s.commit().unwrap();
    }
    w.run(a, Command::Upload { label: l.id, entries: vec![l.entry(y.clone())] });
    assert_eq!(blobs(&w), 1, "stored once");
    {
        let mut s = w.hubs[h].store();
        s.release(&yi, false).unwrap();
        s.commit().unwrap();
        assert_eq!(s.blob(&yi).unwrap(), Some(y), "the hub still serves it");
    }
    let item = DeleteItem::sign(&l.head_keys().delete, &l.id, yi).unwrap();
    w.run(a, Command::Delete { label: l.id, items: vec![item] });
    assert_eq!(blobs(&w), 0);
}

// spec: none: an engine transaction dropped uncommitted leaves nothing in the hub's store
#[test]
fn an_aborted_engine_transaction_leaves_nothing() {
    let mut w = World::new();
    let h = w.add_hub(HostPolicy::default());
    let x = blob(4);
    let xi = osis_label::blob_id(&x);
    {
        let mut s = w.hubs[h].store();
        assert!(s.hold(&xi, x, false).unwrap());
        s.abort();
        assert!(!s.held(&xi).unwrap());
    }
    assert_eq!(w.backends[h].held_split().2, 0);
}
