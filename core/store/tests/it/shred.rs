#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Shredding: after a shredded drop, an attacker holding the device (every key the current root
//! yields) and every byte ever written (freed pages, old versions) recovers nothing
//! (spec/commits.md §5; spec/requirements.md, Deletion: forward secure).

use crate::common;

use common::*;
use osis_base::{BlobId, CommitId, LabelId};
use osis_crypto::SeededRng;
use osis_store::{AspectUnit, Evidence, PendingKind, Shred, Store};

/// Everything an attacker recovers (`osis_store::attack`): from the keys the current tree
/// yields and every row and blob ever written.
fn attack(s: &mut Store, dev: &MemDevice) -> Vec<Vec<u8>> {
    osis_store::attack(&Evidence::of(s.forensic_keys().unwrap(), &dev.backend), None).into_iter().map(|r| r.plain).collect()
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

fn recoverable(s: &mut Store, dev: &MemDevice, marker: &[u8]) -> bool {
    attack(s, dev).iter().any(|p| contains(p, marker))
}

const LABEL: LabelId = LabelId([4; 16]);

/// Writes `marker` into every kind of unit, then rewrites some of them without shredding so old
/// versions pile up in the history.
fn plant(s: &mut Store, rng: &mut SeededRng, marker: &[u8]) {
    let (t1, a) = (tid(1), ak("doc.0"));
    let mut t = s.transaction(rng).unwrap();
    let unit = AspectUnit { state: b"live".to_vec(), undo: [b"undo:", marker].concat(), snapshots: [b"snap:", marker].concat() };
    t.put_aspect(&t1, &a, &unit, Shred::No).unwrap();
    t.put_wrap(&LABEL, &BlobId([1; 32]), &[marker, b"wrap"].concat()).unwrap();
    t.put_wrap(&LABEL, &BlobId([2; 32]), b"other wrap").unwrap();
    t.put_secrets(&tid(9), &[b"secrets:", marker].concat(), Shred::No).unwrap();
    let big = t.create_table(&t1, &ak("big.0"), 0).unwrap();
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
    let (t1, a) = (tid(1), ak("doc.0"));
    let mut t = s.transaction(rng).unwrap();
    let mut u = t.get_aspect(&t1, &a).unwrap().unwrap();
    u.undo.clear();
    u.snapshots.clear();
    t.put_aspect(&t1, &a, &u, Shred::Yes).unwrap();
    assert!(t.drop_wrap(&LABEL, &BlobId([1; 32])).unwrap());
    assert!(t.drop_actor_secrets(&tid(9)).unwrap());
    let big = t.table(&t1, &ak("big.0"), 0).unwrap().unwrap();
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
    t.drop_aspect(&tid(1), &ak("big.0")).unwrap();
    t.drop_aspect(&tid(1), &ak("doc.0")).unwrap();
    t.commit().unwrap();
    let plains = attack(&mut s, &dev);
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

/// Blobs as osis-label frames them, without a prefix: enough for the attack's blob paths.
const CIPHERS: osis_store::Ciphers = osis_store::Ciphers {
    open: |blob, key| osis_crypto::decrypt_blob(blob, 0, &osis_crypto::Secret32::from_bytes(*key)).ok(),
    unwrap: |secret, blob, wrap| osis_crypto::unwrap(&osis_crypto::Secret32::from_bytes(*secret), blob, wrap).ok().map(|k| *k.expose()),
    wrap_len: osis_crypto::WRAP_LEN,
};

// spec/requirements.md, Deletion (forward secure): a blob's ciphertext outlives its deletion in
// freed storage, so its key must not: the attack opens a blob through a recorded key or a wrap
// under a read secret the device still yields, and through neither once both are dropped
// shredded (the read secret still held)
#[test]
fn blob_keys_and_wraps_dropped_leave_the_blob_unopenable() {
    let dev = MemDevice::new();
    dev.backend.record_history();
    let mut rng = SeededRng::from_u64(7);
    let mut s = create(&dev, &mut rng);
    let secret = osis_crypto::Secret32::from_bytes([9; 32]);
    let blob = |m: &[u8], rng: &mut SeededRng| {
        let (key, b) = osis_crypto::encrypt_blob(&[], m, rng).unwrap();
        (osis_crypto::blob_id(&b), key, b)
    };
    let (wrapped, wkey, wb) = blob(b"WRAPPED-BLOB-MARK", &mut rng);
    // the keyed blob holds the key of an inner one (as a large value's tree node holds chunk keys)
    let (inner, ikey, ib) = blob(b"INNER-BLOB-MARK", &mut rng);
    let (keyed, kkey, kb) = blob(&[b"KEYED-BLOB-MARK".as_slice(), ikey.expose()].concat(), &mut rng);
    let mut t = s.transaction(&mut rng).unwrap();
    t.put_blob(&inner, ib).unwrap();
    t.put_blob(&wrapped, wb).unwrap();
    t.put_wrap(&LABEL, &wrapped, &osis_crypto::wrap(&secret, &wrapped, &wkey, 1).unwrap()).unwrap();
    t.put_blob(&keyed, kb).unwrap();
    t.put_local(&[b"blobkey/".as_slice(), &keyed.0].concat(), kkey.expose(), Shred::No).unwrap();
    t.commit().unwrap();
    let found = |s: &mut Store, m: &[u8]| {
        let ev = Evidence { secrets: vec![*secret.expose()], ..Evidence::of(s.forensic_keys().unwrap(), &dev.backend) };
        osis_store::attack(&ev, Some(&CIPHERS)).into_iter().filter(|r| contains(&r.plain, m)).map(|r| r.from).collect::<Vec<_>>()
    };
    assert_eq!(found(&mut s, b"WRAPPED-BLOB-MARK"), vec![osis_store::Source::Blob { id: wrapped, wrapped: true }]);
    assert_eq!(found(&mut s, b"KEYED-BLOB-MARK"), vec![osis_store::Source::Blob { id: keyed, wrapped: false }]);
    assert_eq!(found(&mut s, b"INNER-BLOB-MARK"), vec![osis_store::Source::Blob { id: inner, wrapped: false }]);
    let mut t = s.transaction(&mut rng).unwrap();
    assert!(t.drop_wrap(&LABEL, &wrapped).unwrap());
    assert!(t.remove_local(&[b"blobkey/".as_slice(), &keyed.0].concat(), Shred::Yes).unwrap());
    t.delete_blob(&wrapped);
    t.delete_blob(&keyed);
    t.delete_blob(&inner);
    t.commit().unwrap();
    assert_eq!(found(&mut s, b"WRAPPED-BLOB-MARK"), vec![], "a dropped wrap opened its blob");
    assert_eq!(found(&mut s, b"KEYED-BLOB-MARK"), vec![], "a dropped key opened its blob");
    assert_eq!(found(&mut s, b"INNER-BLOB-MARK"), vec![], "a key inside a dropped blob opened its blob");
    // the freed ciphertexts are still in the attacker's hands
    assert_eq!(dev.backend.blob_history().iter().filter(|(_, b)| b.is_some()).count(), 3);
}

// spec/requirements.md, Deletion: the attack reads what the store keeps in clear (pointer and
// journal rows) and blobs as stored
#[test]
fn attack_reads_clear_rows_and_raw_blobs() {
    let dev = MemDevice::new();
    dev.backend.record_history();
    let mut rng = SeededRng::from_u64(8);
    let mut s = create(&dev, &mut rng);
    let mut t = s.transaction(&mut rng).unwrap();
    t.put_blob(&BlobId([5; 32]), b"CLEAR-BLOB-MARK".to_vec()).unwrap();
    t.commit().unwrap();
    let all = osis_store::attack(&Evidence::of(s.forensic_keys().unwrap(), &dev.backend), None);
    assert!(all.iter().any(|r| r.from == osis_store::Source::RawBlob(BlobId([5; 32])) && contains(&r.plain, b"CLEAR-BLOB-MARK")));
    assert!(all.iter().any(|r| r.from == osis_store::Source::Row(b"r".to_vec())), "the clear pointer row");
}

// spec/requirements.md, Deletion (no confirmation of a guess): around a shredded drop of a small
// entry, every slot's rewritten unit keeps its padded length or moves one Padmé class step
// (notes/local-store.md, Row padding), so freed versions do not show the entry's length
#[test]
fn shredded_small_drop_keeps_unit_lengths_within_a_class_step() {
    let dev = MemDevice::new();
    dev.backend.record_history();
    let mut rng = SeededRng::from_u64(9);
    let mut s = create(&dev, &mut rng);
    let mut t = s.transaction(&mut rng).unwrap();
    for i in 0..100u32 {
        t.put_local(format!("a{i:04}").as_bytes(), &[1; 40], Shred::No).unwrap();
    }
    t.put_local(b"m-victim", b"SMALL-SECRET", Shred::No).unwrap();
    t.commit().unwrap();
    let before = dev.backend.history().len();
    let mut t = s.transaction(&mut rng).unwrap();
    assert!(t.remove_local(b"m-victim", Shred::Yes).unwrap());
    t.commit().unwrap();
    // unit rows `u slot ver`: the last version of each slot before the drop and the drop's
    let units = |rows: &[(Vec<u8>, Vec<u8>)]| -> std::collections::BTreeMap<Vec<u8>, usize> {
        let ct = |v: &Vec<u8>| v.len() - 24 - 16;
        rows.iter().filter(|(k, _)| k.len() == 17 && k[0] == b'u').map(|(k, v)| (k[..9].to_vec(), ct(v))).collect()
    };
    let h = dev.backend.history();
    let (old, new) = (units(&h[..before]), units(&h[before..]));
    let mut compared = 0;
    for (slot, n) in &new {
        let Some(o) = old.get(slot) else { continue };
        let (lo, hi) = ((*o).min(*n), (*o).max(*n));
        assert!(lo == hi || osis_crypto::padme(lo + 1) == hi, "slot {slot:?}: {o} B then {n} B");
        compared += 1;
    }
    assert!(compared > 0, "the drop rewrote a unit");
    assert!(!recoverable(&mut s, &dev, b"SMALL-SECRET"));
}
