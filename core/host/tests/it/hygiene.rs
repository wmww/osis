//! What a host learns (spec/requirements.md Data a node cannot read; notes/unreadable-data.md): a scripted run whose blobs carry tids, AKs and author keys in their plaintext,
//! then every byte the node ever wrote, and every host-store row an attacker holding the device
//! decrypts from it, is searched for them.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use crate::common;

use common::*;
use osis_base::{BlobId, WallMs};
use osis_crypto::SeededRng;
use osis_label::Prefix;
use osis_proto::msg::DeleteItem;
use osis_proto::*;
use osis_host::HostPolicy;
use osis_store::Backend;

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

// spec/sync.md §4, spec/requirements.md Data a node cannot read: no tid, AK or author key reaches the host's storage
#[test]
fn stored_bytes_hold_no_plaintext_identifiers() {
    let mut w = World::new();
    let h = w.add_hub(HostPolicy::default());
    w.backends[h].record_history();
    let a = w.connect(h);
    let l = Label::new(3);
    w.setup(a, &l);
    w.open(a, &l);
    let tid = [0xa7u8; 15];
    let ak = b"profile:display_name.0".to_vec();
    let author = [0xa9u8; 32];
    let plaintext = [&tid[..], &ak, &author].concat();
    let mut rng = SeededRng::from_seed([0; 32]);
    let blobs: Vec<Vec<u8>> = (0..4u8)
        .map(|n| {
            let p = Prefix::new([n; 16], (n == 3).then_some(WallMs(w.now() + 1_000)), vec![]).unwrap();
            osis_label::frame(&p, &plaintext, &mut rng).unwrap().1
        })
        .collect();
    w.run(a, Command::Upload { label: l.id, entries: blobs[..2].iter().map(|b| l.entry(b.clone())).collect() });
    w.run(a, l.deposit(blobs[2].clone(), &l.head_keys().deposit.clone()));
    w.run(a, Command::Upload { label: l.id, entries: vec![l.entry(blobs[3].clone())] });
    let item = DeleteItem::sign(&l.head_keys().delete, &l.id, osis_label::blob_id(&blobs[0])).unwrap();
    w.run(a, Command::Delete { label: l.id, items: vec![item] });
    let env = osis_label::frame(&Prefix::new([9; 16], None, vec![]).unwrap().with_class(osis_label::Class::Relay), &plaintext, &mut rng).unwrap().1;
    w.run(a, Command::Upload { label: l.id, entries: vec![l.entry(env)] });
    w.advance(1_000);
    let mut history = w.backends[h].history();
    assert!(!history.is_empty());
    let keys = w.hubs[h].store().store_mut().unwrap().forensic_keys().unwrap();
    let plain = osis_store::attack(&osis_store::Evidence { store_keys: keys, rows: history.clone(), ..Default::default() }, None).into_iter().map(|r| r.plain).collect::<Vec<_>>();
    // control: what the host may know (the label ID) is found by the same search
    assert!(plain.iter().any(|p| contains(p, &l.id.0)));
    history.extend(plain.into_iter().map(|p| (Vec::new(), p)));
    let ids: Vec<BlobId> = blobs.iter().map(|b| osis_label::blob_id(b)).collect();
    let stored: Vec<Vec<u8>> = ids.iter().filter_map(|id| w.backends[h].get_blob(id).unwrap()).collect();
    assert_eq!(stored.len(), 2, "the deleted and the expired blob are gone");
    for needle in [&tid[..], &ak[..], &author[..]] {
        for (k, v) in &history {
            assert!(!contains(k, needle) && !contains(v, needle));
        }
        for b in &stored {
            assert!(!contains(b, needle));
        }
    }
}

// spec/requirements.md Deletion (forward secure), spec/sync.md §4: a node hosting a label it can
// also read holds the read secret, so a wrap it kept would open the blob: after a delete, an
// expiry, a replaced-then-deleted wrap and the label dropped (hosting stopped), an attacker holding the device (every key the
// current root yields) and every row the host store ever wrote finds none of those wraps
#[test]
fn deleted_wraps_unrecoverable() {
    use osis_base::{LabelId, ManualClock};
    use osis_crypto::Signature;
    use osis_store::{MemoryBackend, MemoryRoot, Store, StoreConfig};
    use std::sync::Arc;
    let (backend, root) = (MemoryBackend::new(), MemoryRoot::new());
    backend.record_history();
    // a small key tree and pages: few units share a node, so a shred elsewhere does not rotate a
    // leaked copy away by accident
    let cfg = StoreConfig { arity: 4, depth: 8, page_max: 512, ..StoreConfig::default() };
    let store = Store::create(Box::new(backend.clone()), Box::new(root), cfg, &mut SeededRng::from_seed([0; 32])).unwrap();
    let clock = Arc::new(ManualClock::new(WallMs(T0)));
    let mut s = osis_host::HostStore::open(store, clock.clone(), HostPolicy::unlimited(), Box::new(SeededRng::from_seed([1; 32]))).unwrap();
    let f = osis_proto::examples::Fixture::new(0x10);
    let l: LabelId = f.label;
    s.push_step(&l, f.genesis.clone(), Some(f.genesis_claims.clone())).unwrap();
    let wrap = |m: u8| {
        let mut w = [0u8; osis_proto::msg::WRAP_LEN];
        w.iter_mut().enumerate().for_each(|(i, b)| *b = m ^ (i as u8).wrapping_mul(37));
        w
    };
    let blobs: Vec<Vec<u8>> = (0..24u64).map(osis_proto::examples::blob).collect();
    let put = |s: &mut osis_host::HostStore, i: usize, w: u8, expiry: Option<u64>| {
        let b = &blobs[i];
        // entry 3 starts as a deposit
        let stamp = (i != 3 || w != 103).then_some(Signature([w; 64]));
        let p = Put { blob_id: osis_label::blob_id(b), blob: b, wrap: wrap(w), stamp, expiry, ephemeral: false, replaces: &[], now: 0 };
        assert_eq!(s.put(&l, p).unwrap(), Code::OK);
    };
    for i in 0..24 {
        put(&mut s, i, 100 + i as u8, (i == 7).then_some(T0 + 1_000));
    }
    // entry 3's wrap replaced (a promotion under another wrap), then deleted; entry 5 deleted; entry 7 expires
    put(&mut s, 3, 250, None);
    let (dead, live) = ([wrap(103), wrap(250), wrap(105), wrap(107)], wrap(120));
    let found = |s: &mut osis_host::HostStore, w: &[u8]| {
        let keys = s.store_mut().unwrap().forensic_keys().unwrap();
        osis_store::attack(&osis_store::Evidence { store_keys: keys, rows: backend.history(), ..Default::default() }, None).into_iter().any(|r| contains(&r.plain, w))
    };
    assert!(dead.iter().all(|w| found(&mut s, w)), "the attack finds live wraps");
    s.delete(&l, &osis_label::blob_id(&blobs[3]), T0).unwrap();
    s.delete(&l, &osis_label::blob_id(&blobs[5]), T0).unwrap();
    s.sweep(T0 + 1_000, 1024).unwrap();
    assert_eq!(s.entry(&l, &osis_label::blob_id(&blobs[7])).unwrap(), None);
    for w in &dead {
        assert!(!found(&mut s, w), "a deleted wrap recovered");
    }
    assert!(found(&mut s, &live), "a live wrap is still found");
    // hosting stopped: the label kept for others goes, its live wraps with it
    assert_eq!(s.drop_labels(&|_| true).unwrap(), [l]);
    assert!(!found(&mut s, &live), "a dropped label's wrap recovered");
}
