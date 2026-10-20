#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Shredding: after a shredded drop, an attacker holding the device (every key the current root
//! yields) and every byte ever written (freed pages, old versions) recovers nothing
//! (spec/commits.md §5; spec/requirements.md, Deletion: forward secure).

mod common;

use common::*;
use osis_core::{BlobId, CommitId, LabelId};
use osis_crypto::SeededRng;
use osis_store::{AspectUnit, PendingKind, Shred, Store, forensic_node_keys, forensic_open};
use std::collections::HashSet;

/// Everything an attacker decrypts: start from the keys the current tree yields, open every
/// row ever written with every key, harvest keys from opened tree nodes, until nothing new.
fn attack(s: &mut Store, history: &[(Vec<u8>, Vec<u8>)]) -> Vec<Vec<u8>> {
    let mut keys: Vec<[u8; 32]> = s.forensic_keys().unwrap();
    let mut known: HashSet<[u8; 32]> = keys.iter().copied().collect();
    let mut opened = vec![None; history.len()];
    let mut tried = 0;
    while tried < keys.len() {
        let batch: Vec<[u8; 32]> = keys[tried..].to_vec();
        tried = keys.len();
        for (i, (row, value)) in history.iter().enumerate() {
            if opened[i].is_some() {
                continue;
            }
            for k in &batch {
                if let Some(plain) = forensic_open(row, value, k) {
                    for nk in forensic_node_keys(row, &plain) {
                        if known.insert(nk) {
                            keys.push(nk);
                        }
                    }
                    opened[i] = Some(plain);
                    break;
                }
            }
        }
    }
    opened.into_iter().flatten().collect()
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

fn recoverable(s: &mut Store, dev: &MemDevice, marker: &[u8]) -> bool {
    attack(s, &dev.backend.history()).iter().any(|p| contains(p, marker))
}

const LABEL: LabelId = LabelId([4; 16]);

/// Writes `marker` into every kind of unit, then rewrites some of them without shredding so old
/// versions pile up in the history.
fn plant(s: &mut Store, rng: &mut SeededRng, marker: &[u8]) {
    let (t1, a) = (tid(1), ak("/doc"));
    let mut t = s.transaction(rng).unwrap();
    let unit = AspectUnit { state: b"live".to_vec(), undo: [b"undo:", marker].concat(), snapshots: [b"snap:", marker].concat() };
    t.put_aspect(&t1, &a, &unit, Shred::No).unwrap();
    t.put_wrap(&LABEL, &BlobId([1; 32]), &[marker, b"wrap"].concat()).unwrap();
    t.put_wrap(&LABEL, &BlobId([2; 32]), b"other wrap").unwrap();
    t.put_secrets(&tid(9), &[b"secrets:", marker].concat(), Shred::No).unwrap();
    let big = t.create_table(&t1, &ak("/big"), 0).unwrap();
    for i in 0..300u32 {
        t.table_put(big, &i.to_be_bytes(), format!("element {i}").into_bytes(), Shred::No).unwrap();
    }
    t.table_put(big, &150u32.to_be_bytes(), [b"elem:", marker].concat(), Shred::No).unwrap();
    t.put_pending(&CommitId([3; 32]), PendingKind::Parked, &[b"commit:", marker, &[0; 400]].concat()).unwrap();
    t.commit().unwrap();
    // Unrelated edits: same unit keys, new versions.
    for round in 0..3u8 {
        let mut t = s.transaction(rng).unwrap();
        let mut u = t.get_aspect(&t1, &a).unwrap().unwrap();
        u.state = vec![round; 5];
        t.put_aspect(&t1, &a, &u, Shred::No).unwrap();
        t.table_put(big, &151u32.to_be_bytes(), vec![round; 8], Shred::No).unwrap();
        t.commit().unwrap();
    }
}

/// The shredded drops of every unit kind holding the marker.
fn shred_all(s: &mut Store, rng: &mut SeededRng) {
    let (t1, a) = (tid(1), ak("/doc"));
    let mut t = s.transaction(rng).unwrap();
    let mut u = t.get_aspect(&t1, &a).unwrap().unwrap();
    u.undo.clear();
    u.snapshots.clear();
    t.put_aspect(&t1, &a, &u, Shred::Yes).unwrap();
    assert!(t.drop_wrap(&LABEL, &BlobId([1; 32])).unwrap());
    assert!(t.drop_actor_secrets(&tid(9)).unwrap());
    let big = t.table(&t1, &ak("/big"), 0).unwrap().unwrap();
    t.table_put(big, &150u32.to_be_bytes(), b"element 150".to_vec(), Shred::Yes).unwrap();
    assert!(t.remove_pending(&CommitId([3; 32]), Shred::Yes).unwrap());
    t.commit().unwrap();
}

// spec/commits.md §5: dropping a body destroys every local copy (undo buffers and pre-reset
// snapshots included) so that later compromise recovers nothing; wraps, secrets, pages likewise.
#[test]
fn shredded_content_is_unrecoverable() {
    let dev = MemDevice::new();
    dev.backend.record_history();
    let mut rng = SeededRng::from_u64(1);
    let mut s = create(&dev, &mut rng);
    let marker = b"MARKER-7f3a9c";
    plant(&mut s, &mut rng, marker);
    assert!(recoverable(&mut s, &dev, marker), "the attack finds live content");
    shred_all(&mut s, &mut rng);
    assert!(!recoverable(&mut s, &dev, marker), "shredded content recovered");
    // Live content is still readable, and still found by the attack.
    let mut t = s.transaction(&mut rng).unwrap();
    assert_eq!(t.get_wrap(&LABEL, &BlobId([2; 32])).unwrap(), Some(b"other wrap".to_vec()));
    drop(t);
    assert!(recoverable(&mut s, &dev, b"other wrap"));
    // Backends hold ciphertext only.
    assert!(dev.backend.history().iter().all(|(k, v)| !contains(k, marker) && !contains(v, marker)));
}

// spec/commits.md §5: a whole-aspect purge drops the units: nothing of the aspect survives.
#[test]
fn dropped_aspect_is_unrecoverable() {
    let dev = MemDevice::new();
    dev.backend.record_history();
    let mut rng = SeededRng::from_u64(2);
    let mut s = create(&dev, &mut rng);
    plant(&mut s, &mut rng, b"MARKER-big");
    let mut t = s.transaction(&mut rng).unwrap();
    t.drop_aspect(&tid(1), &ak("/big")).unwrap();
    t.drop_aspect(&tid(1), &ak("/doc")).unwrap();
    t.commit().unwrap();
    let plains = attack(&mut s, &dev.backend.history());
    assert!(!plains.iter().any(|p| contains(p, b"element 77") || contains(p, b"undo:")));
}

// spec/commits.md §5: a record written before page splits moved it to other slots is still
// unrecoverable after its shredded removal (pages losing entries are rewritten shredded).
#[test]
fn shred_after_splits_and_merges() {
    let dev = MemDevice::new();
    dev.backend.record_history();
    let mut rng = SeededRng::from_u64(6);
    let mut s = create(&dev, &mut rng);
    let mut t = s.transaction(&mut rng).unwrap();
    for i in 0..200u32 {
        t.put_local(format!("a{i:04}").as_bytes(), &[1; 40], Shred::No).unwrap();
    }
    t.commit().unwrap();
    let mut t = s.transaction(&mut rng).unwrap();
    t.put_local(b"m-victim", b"SECRET-MARK", Shred::No).unwrap();
    t.commit().unwrap();
    // Inserts around the victim split its page (each transaction commits a page version);
    // removals merge pages.
    for i in 0..12u32 {
        let mut t = s.transaction(&mut rng).unwrap();
        for j in 0..5 {
            t.put_local(format!("l{i:02}{j}").as_bytes(), &[1; 40], Shred::No).unwrap();
            t.put_local(format!("b{i:02}{j}").as_bytes(), &[1; 40], Shred::No).unwrap();
        }
        t.commit().unwrap();
    }
    for i in 0..10u32 {
        let mut t = s.transaction(&mut rng).unwrap();
        for j in 0..20 {
            t.remove_local(format!("a{:04}", i * 20 + j).as_bytes(), Shred::No).unwrap();
        }
        t.commit().unwrap();
    }
    assert!(recoverable(&mut s, &dev, b"SECRET-MARK"));
    let mut t = s.transaction(&mut rng).unwrap();
    assert!(t.remove_local(b"m-victim", Shred::Yes).unwrap());
    t.commit().unwrap();
    assert!(!recoverable(&mut s, &dev, b"SECRET-MARK"), "recovered from a page version before a split or merge");
}

// notes/local-store.md, Key tree: without `Shred::Yes` an overwrite may stay recoverable from
// freed storage; any later shred along the same key path makes it unrecoverable too.
#[test]
fn unshredded_overwrite_is_recoverable_until_a_later_shred() {
    let dev = MemDevice::new();
    dev.backend.record_history();
    let mut rng = SeededRng::from_u64(3);
    let mut s = create(&dev, &mut rng);
    let mut t = s.transaction(&mut rng).unwrap();
    t.put_local(b"k", b"old-MARK", Shred::No).unwrap();
    t.commit().unwrap();
    let mut t = s.transaction(&mut rng).unwrap();
    t.put_local(b"k", b"new", Shred::No).unwrap();
    t.commit().unwrap();
    assert!(recoverable(&mut s, &dev, b"old-MARK"));
    let mut t = s.transaction(&mut rng).unwrap();
    t.put_local(b"k", b"newer", Shred::Yes).unwrap();
    t.commit().unwrap();
    assert!(!recoverable(&mut s, &dev, b"old-MARK"));
}

// notes/local-store.md, Key tree: the same contract for a value above a quarter page (its own
// unit): a later shred of the key reaches every earlier unshredded version, though each lived
// in a unit of its own (spec/commits.md §5: dropping destroys every local copy).
#[test]
fn unshredded_large_overwrite_is_unrecoverable_after_a_later_shred() {
    let dev = MemDevice::new();
    dev.backend.record_history();
    let mut rng = SeededRng::from_u64(5);
    let mut s = create(&dev, &mut rng);
    let big = |m: &[u8]| [m, &[7u8; 300][..]].concat();
    // Other units around the old value, so its leaf of the key tree holds only units the later
    // writes leave alone.
    let fill = |s: &mut Store, rng: &mut SeededRng, tag: &str| {
        let mut t = s.transaction(rng).unwrap();
        for i in 0..64u32 {
            t.put_local(format!("{tag}{i:03}").as_bytes(), &big(b"filler"), Shred::No).unwrap();
        }
        t.commit().unwrap();
    };
    fill(&mut s, &mut rng, "a");
    let mut t = s.transaction(&mut rng).unwrap();
    t.put_local(b"k", &big(b"old-BIG-MARK"), Shred::No).unwrap();
    t.commit().unwrap();
    fill(&mut s, &mut rng, "z");
    let mut t = s.transaction(&mut rng).unwrap();
    t.put_local(b"k", &big(b"new"), Shred::No).unwrap();
    t.commit().unwrap();
    assert!(recoverable(&mut s, &dev, b"old-BIG-MARK"));
    let mut t = s.transaction(&mut rng).unwrap();
    t.put_local(b"k", &big(b"newer"), Shred::Yes).unwrap();
    t.commit().unwrap();
    assert!(!recoverable(&mut s, &dev, b"old-BIG-MARK"), "an earlier version of a large value survived the shred");
}

// spec/requirements.md, Deletion: the file backend holds ciphertext only.
#[cfg(feature = "file-backend")]
#[test]
fn file_backend_holds_no_plaintext() {
    let dev = FileDevice::new("shred");
    let mut rng = SeededRng::from_u64(4);
    let mut s = create(&dev, &mut rng);
    plant(&mut s, &mut rng, b"MARKER-file");
    shred_all(&mut s, &mut rng);
    drop(s);
    let raw = std::fs::read(dev.dir.join("db")).unwrap();
    // Store files are readable by their owner only.
    #[cfg(unix)]
    assert_eq!(std::os::unix::fs::PermissionsExt::mode(&std::fs::metadata(dev.dir.join("db")).unwrap().permissions()) & 0o077, 0);
    assert!(!contains(&raw, b"MARKER-file"));
    assert!(!contains(&raw, b"element 1"));
    let mut s = reopen(&dev);
    let mut t = s.transaction(&mut rng).unwrap();
    assert_eq!(t.get_wrap(&LABEL, &BlobId([1; 32])).unwrap(), None);
    assert_eq!(t.get_wrap(&LABEL, &BlobId([2; 32])).unwrap(), Some(b"other wrap".to_vec()));
}
