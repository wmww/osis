//! What a blind node learns (spec/requirements.md, Untrusted nodes; notes/sync.md "What a blind
//! node learns"): a scripted run whose blobs carry tids, AKs and author keys in their plaintext,
//! then every byte the node ever wrote is searched for them.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use crate::common;

use common::*;
use osis_base::{BlobId, WallMs};
use osis_crypto::SeededRng;
use osis_label::Prefix;
use osis_proto::msg::DeleteItem;
use osis_proto::*;
use osis_server::Policy;
use osis_store::Backend;

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

// spec/sync.md §4, spec/requirements.md Untrusted nodes: no tid, AK or author key reaches the node's storage
#[test]
fn stored_bytes_hold_no_plaintext_identifiers() {
    let mut w = World::new();
    let h = w.add_hub(Policy::default());
    w.backends[h].record_history();
    let a = w.connect(h);
    let l = Label::new(3);
    w.setup(a, &l);
    w.open(a, &l);
    let tid = [0xa7u8; 15];
    let ak = b"/profile/display_name".to_vec();
    let author = [0xa9u8; 32];
    let plaintext = [&tid[..], &ak, &author].concat();
    let mut rng = SeededRng::from_seed([5; 32]);
    let blobs: Vec<Vec<u8>> = (0..4u8)
        .map(|n| {
            let p = Prefix::new([n; 16], (n == 3).then_some(WallMs(w.now() + 1_000)), vec![]).unwrap();
            osis_label::frame(&p, &plaintext, &mut rng).unwrap().1
        })
        .collect();
    w.run(a, Command::Upload { label: l.id, entries: blobs[..2].iter().map(|b| l.entry(b.clone())).collect() });
    w.run(a, l.deposit(blobs[2].clone(), &l.head_keys().deposit.clone()));
    w.run(a, Command::Upload { label: l.id, entries: vec![l.entry(blobs[3].clone())] });
    let item = DeleteItem::sign(&l.head_keys().delete, &l.id, osis_label::blob_id(&blobs[0]), None).unwrap();
    w.run(a, Command::Delete { label: l.id, items: vec![item] });
    let env = osis_label::frame(&Prefix::new([9; 16], None, vec![]).unwrap().with_class(osis_label::Class::Relay), &plaintext, &mut rng).unwrap().1;
    w.run(a, Command::Upload { label: l.id, entries: vec![l.entry(env)] });
    w.advance(1_000);
    let history = w.backends[h].history();
    assert!(!history.is_empty());
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
