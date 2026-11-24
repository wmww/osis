//! Stated paths in the header and sections (spec/wire.md §4 fields 1, 2, 17; `Path`, `Paths`,
//! `Split`, `PathKey`, `Contents`; spec/crypto.md §5 Path entry).

use crate::tests::build::{content, key, rng};
use crate::tests::verify::TestSecrets;
use crate::tests::{sample_header, t};
use crate::*;
use osis_base::format::MAX_PATH_THINGS;
use osis_base::Tid;
use osis_crypto::Secret32;
use std::collections::BTreeMap;

fn built(b: CommitBuilder) -> CommitBlob {
    b.build(&key(), &TestSecrets { admin: true }, &mut MemoryBlobs::default(), &mut rng()).unwrap().commit
}

fn one(path: Path) -> Header {
    Header { path: Paths::One(path), ..sample_header() }
}

/// The read roles secret the tests seal thing `t`'s entry under.
fn roles(t: &Tid) -> Secret32 {
    Secret32::from_bytes([t.as_bytes()[0] ^ 0x5a; 32])
}

/// `content(n)` stating the split form: its first thing along `[t(2)]`, the others along
/// `[t(9), t(2)]`, purge author `t(2)`.
fn split(n: usize) -> CommitBuilder {
    let mut b = content(n);
    let things = b.aspects.iter().map(|a| a.tid).collect::<Vec<_>>();
    let each = things.iter().enumerate().map(|(i, x)| (*x, ((if i == 0 { vec![t(2)] } else { vec![t(9), t(2)] }, 0), roles(x)))).collect();
    b.split = Some(SplitWrite { author: Some(t(2)), things: each });
    b
}

fn path_len(h: &Header) -> usize {
    let mut out = Vec::new();
    h.path.put(&mut out);
    out.len()
}

// spec/wire.md §4 field 2: a path in the clear round-trips with the empty path, one listed thing
// and MAX_PATH_THINGS of them; the decoder rejects a path past MAX_PATH_THINGS, an index past
// its things, a thing twice, the signer listed, a key commitment in a path in the clear; a split
// path of one entry, an entry of no padded length (one without its commitment), two entries
// committing to one key, or naming its signer as purge author.
#[test]
fn paths_decode_by_their_rules() {
    let many: Vec<_> = (0..MAX_PATH_THINGS).map(|i| osis_base::Tid::from_bytes([i as u8 + 20; 15])).collect();
    for p in [Path::default(), Path::through(t(2)), Path { purge: 3, things: many.clone(), direct: 0 }] {
        let h = one(p);
        assert_eq!(Header::decode(&h.encode()).unwrap(), h);
    }
    let mut longer = many.clone();
    longer.push(t(200));
    for (p, why) in [
        (Path { purge: 0, things: longer, direct: 0 }, "longer than MAX_PATH_THINGS"),
        (Path { purge: 2, things: vec![t(2)], direct: 0 }, "index out of range"),
        (Path { purge: 0, things: vec![t(2), t(2)], direct: 0 }, "thing twice"),
        (Path { purge: 0, things: vec![t(1)], direct: 0 }, "the signer"),
    ] {
        assert!(matches!(Header::decode(&one(p).encode()), Err(Error::Malformed(_))), "{why}");
    }
    // a `Path` has no place for a commitment: `[0, commitment]` reads it as a listed tid
    let mut clear = Vec::new();
    osis_base::cbor::put_array(&mut clear, 2);
    osis_base::cbor::put_uint(&mut clear, 0);
    osis_base::cbor::put_bytes(&mut clear, &key_commitment(&[7; 32]));
    assert!(matches!(Path::read(osis_base::cbor::Item::parse(&clear, &crate::header::LIMITS).unwrap(), &t(1)), Err(Error::Malformed(_))), "a commitment in a path in the clear");
    // entry `n` of class `k`: its commitment (first byte) distinct per `n`
    let e = |k: usize, n: u8| [vec![n], vec![7u8; entry_len(k).unwrap() - 1]].concat();
    let sp = |author, entries| Header { path: Paths::Split(Split { author, entries }), ..sample_header() };
    for h in [sp(None, vec![e(0, 0), e(5, 1)]), sp(Some(t(2)), vec![e(64, 0), e(1, 1), e(16, 2)])] {
        assert_eq!(Header::decode(&h.encode()).unwrap(), h);
    }
    let bare = |k: usize| vec![7u8; entry_len(k).unwrap() - COMMITMENT_LEN];
    for (h, why) in [
        (sp(None, vec![e(0, 0)]), "one entry"),
        (sp(None, vec![e(0, 0), vec![7; 50]]), "no padded length"),
        (sp(None, vec![e(0, 0), bare(0)]), "an entry without its commitment"),
        (sp(None, vec![e(0, 0), [vec![9], bare(0)].concat()]), "a commitment of 1 byte"),
        (sp(None, vec![e(0, 0), e(0, 0)]), "two entries committing to one key"),
        (sp(None, vec![e(0, 3), e(16, 3)]), "one commitment on entries of two classes"),
        (sp(Some(t(1)), vec![e(0, 0), e(0, 1)]), "the signer as author"),
    ] {
        assert!(matches!(Header::decode(&h.encode()), Err(Error::Malformed(_))), "{why}");
    }
}

// For Tess 3 (notes/path-form.md): an entry's size shows only its class: up to 4 listed things,
// up to 16, up to MAX_PATH_THINGS (each with its 32-byte key commitment), room for every hop
// marked direct (`marks`) in each, so a mark shows nothing either.
#[test]
fn entries_pad_to_their_class() {
    assert_eq!([0, 1, 4].map(|k| entry_len(k).unwrap()), [115; 3]);
    assert_eq!([5, 16].map(|k| entry_len(k).unwrap()), [309; 2]);
    assert_eq!([17, MAX_PATH_THINGS].map(|k| entry_len(k).unwrap()), [1084; 2]);
    assert_eq!(entry_len(MAX_PATH_THINGS + 1), None);
}

// spec/wire.md §4 field 2: one path in the clear stands for any number of things written; the
// split form has an entry per thing written, never on a role commit.
#[test]
fn path_forms_by_the_things_written() {
    let mut h = sample_header();
    h.validate().unwrap();
    let e = vec![7u8; entry_len(0).unwrap()];
    h.path = Paths::Split(Split { author: None, entries: vec![e.clone(), e.clone()] });
    assert!(matches!(h.validate(), Err(Error::Malformed(_))), "split on one thing");
    let mut b = h.aspects[0].clone();
    b.tid = t(4);
    h.aspects.push(b);
    h.validate().unwrap();
    h.path = Paths::Split(Split { author: None, entries: vec![e.clone(), e.clone(), e.clone()] });
    assert!(matches!(h.validate(), Err(Error::Malformed(_))), "three entries for two things");
    h.path = Paths::One(Path::through(t(2)));
    h.validate().unwrap();
    let mut r = crate::tests::validate::role_header("roles.0");
    let mut b = r.aspects[0].clone();
    b.tid = t(4);
    r.aspects.push(b);
    r.validate().unwrap();
    r.path = Paths::Split(Split { author: None, entries: vec![e.clone(), e] });
    assert!(r.validate().unwrap_err().to_string().contains("split"), "a role commit states one path");
}

// spec/wire.md §4 field 2: the one path off which each thing's own
// path is read: its end one of the things, the others one hop past it; none where a thing's own
// path is not read off it, or the purge author is on no path.
#[test]
fn one_path_reads_each_things_own() {
    let (s, d, x, y) = (t(1), t(2), t(3), t(4));
    let p = |things: Vec<Tid>| Path { purge: 0, things, direct: 0 };
    // a creation with a granted mint admin: D along [D], the new thing along [D] one hop past
    let each = [(d, p(vec![d])), (x, p(vec![d]))];
    let q = Path::one_of(each.iter().map(|(a, b)| (a, b)), s, s).unwrap();
    assert_eq!(q, p(vec![d]));
    assert!(each.iter().all(|(a, b)| q.to(a) == b.to(a)));
    // the end's own path stated without it: [] for D, [D] for x
    let each = [(d, p(vec![])), (x, p(vec![d]))];
    assert_eq!(Path::one_of(each.iter().map(|(a, b)| (a, b)), s, d), Some(Path { purge: 1, things: vec![d], direct: 0 }));
    // own things: the empty path
    let each = [(x, p(vec![])), (y, p(vec![]))];
    assert_eq!(Path::one_of(each.iter().map(|(a, b)| (a, b)), s, s), Some(Path::default()));
    // an own thing and a thing minted with admin D: two paths
    let each = [(x, p(vec![])), (y, p(vec![d]))];
    assert_eq!(Path::one_of(each.iter().map(|(a, b)| (a, b)), s, s), None);
    // a purge author on no path
    let each = [(x, p(vec![d])), (y, p(vec![d]))];
    assert_eq!(Path::one_of(each.iter().map(|(a, b)| (a, b)), s, t(9)), None);
}

// spec/wire.md §4: the commit ID, and so the signature, covers `signer`, `path` (a split form's
// author and entries included).
#[test]
fn signer_and_path_are_signed() {
    for b in [content(1), split(2)] {
        let c = built(b);
        let k = key().verifying_key();
        verify_signature(&c.id(), &c.sigs, &k).unwrap();
        let flips: [&dyn Fn(&mut Header); 5] = [
            &|h| h.signer = t(77),
            &|h| h.path = Paths::One(Path::default()),
            &|h| h.path = Paths::One(Path { purge: 0, things: vec![t(2)], direct: 0 }),
            &|h| if let Paths::Split(s) = &mut h.path { s.author = None } else { h.signer = t(78) },
            &|h| if let Paths::Split(s) = &mut h.path { s.entries.swap(0, 1) } else { h.signer = t(79) },
        ];
        for flip in flips {
            let mut h = c.header.clone();
            flip(&mut h);
            assert_ne!(h.id(), c.id());
            assert!(verify_signature(&h.id(), &c.sigs, &k).is_err());
        }
    }
}

// spec/wire.md §4 `Split`, `PathKey`, `Contents`; spec/crypto.md §5 Path entry: each thing's entry
// opens under `kdf("path", roles secret, blind ‖ tid)` to its own path, its purge author in the
// clear; every section carries the path keys of the things whose parts it holds, so a reader of
// any one section (a re-encryption, a copy) opens that thing's path and no other; the stored form
// keeps the keys. A copy of a commit stating one path holds one section with no keys.
#[test]
fn split_paths_open_from_the_roles_secret_and_from_every_encryption() {
    let c = built(split(3));
    let things = c.header.things();
    assert_eq!(c.header.purge_author(), t(2));
    let Paths::Split(sp) = &c.header.path else { panic!("split") };
    assert_eq!((sp.entries.len(), path_len(&c.header)), (3, 1 + 17 + 1 + 3 * (2 + 115)));
    let want = |i: usize| if i == 0 { Path::through(t(2)) } else { Path { purge: 2, things: vec![t(9), t(2)], direct: 0 } };
    for (i, x) in things.iter().enumerate() {
        let k = path_key(&roles(x), &c.header.blind, x);
        assert_eq!(c.keys.get(&i), Some(&k));
        assert_eq!(c.header.open_path(i, &k), Some(ThingPath::Known(want(i))));
        assert_eq!(c.path(x), Some(ThingPath::Known(want(i))));
        assert_eq!(c.header.open_path((i + 1) % 3, &k), None, "a key opens its own entry only");
    }
    assert_eq!(CommitBlob::decode(&c.encode()).unwrap(), c);
    assert_eq!(CommitBlob::decode_stored(&c.encode()).unwrap(), c);
    // sealed per thing; each section opened alone gives its thing's parts and path key
    let secret = |r: &Tid| Secret32::from_bytes([r.as_bytes()[0]; 32]);
    let env = seal_commit(&c, &c.header, |ai| c.header.aspects[ai].tid, |r, _| Some((secret(r), vec![])), &[], &mut rng()).unwrap();
    assert_eq!(env.sections.len(), 3);
    for (i, x) in things.iter().enumerate() {
        let o = env.open(|s| if c.header.aspects[s.ais[0]].tid == *x { vec![secret(x)] } else { vec![] }).unwrap();
        assert_eq!(o.commit.keys, BTreeMap::from([(i, c.keys[&i])]));
        assert_eq!(o.commit.path(x), Some(ThingPath::Known(want(i))));
        assert!(things.iter().filter(|y| *y != x).all(|y| o.commit.path(y).is_none()), "no other thing's path");
        // re-encrypted from what it opened, the sealed ones copied: the same commit again
        let again = seal_commit(&o.commit, &c.header, |ai| c.header.aspects[ai].tid, |r, _| Some((secret(r), vec![])), &o.sealed, &mut rng()).unwrap();
        assert_eq!(again.open(|s| vec![secret(&c.header.aspects[s.ais[0]].tid)]).unwrap().commit, c);
    }
    // a copy: one section under the blob key carrying every key
    let blob = Secret32::from_bytes([3; 32]);
    let copy = seal_commit(&c, &c.header, |_| (), |_, _| Some((blob.clone(), vec![])), &[], &mut rng()).unwrap();
    assert_eq!(copy.sections.len(), 1);
    assert_eq!(copy.open(|_| vec![blob.clone()]).unwrap().commit, c);
    // a copy of one thing's parts (the record keeps every key) carries that thing's key alone
    let first = things[0];
    let one = rewrite(&c, |ai| c.header.aspects[ai].tid != first);
    assert_eq!(one.keys, c.keys);
    let e = seal_commit(&one, &c.header, |_| (), |_, _| Some((blob.clone(), vec![])), &[], &mut rng()).unwrap();
    assert_eq!(e.open(|_| vec![blob.clone()]).unwrap().commit.keys, BTreeMap::from([(0, c.keys[&0])]));
    let plain = built(content(3));
    let e = seal_commit(&plain, &plain.header, |_| (), |_, _| Some((blob.clone(), vec![])), &[], &mut rng()).unwrap();
    assert_eq!(e.sections.len(), 1);
    assert_eq!(e.open(|_| vec![blob.clone()]).unwrap().commit, plain);
}

// spec/wire.md §4, spec/commits.md §5 Destruction: a header-only copy of a split commit destroying
// a thing carries one section of no part holding that thing's path key, so the destroyed thing's
// judges open its path; a header-only copy of anything else has no section; a section of no part
// is bad input where the path is in the clear.
#[test]
fn a_header_only_copy_carries_the_destroyed_things_path_key() {
    let mut b = split(2);
    let gone = b.aspects[1].tid;
    b.purge = vec![PurgeItem::Aspect { tid: gone, ak: osis_base::Ak::new(retention::CREATED).unwrap() }];
    let c = built(b);
    let blob = Secret32::from_bytes([3; 32]);
    let bare = rewrite(&c, |_| true);
    assert_eq!(bare.keys, c.keys, "the purge rewrite keeps every path key: header data");
    let e = seal_header_only(&bare, &c.header, &blob, &mut rng()).unwrap();
    assert_eq!(e.sections.len(), 1);
    assert!(e.sections[0].ais.is_empty());
    let back = Envelope::decode(&e.encode()).unwrap();
    let o = back.open(|_| vec![blob.clone()]).unwrap().commit;
    assert!(o.parts.is_empty());
    assert_eq!(o.keys, BTreeMap::from([(1, c.keys[&1])]), "the copy carries the destroyed thing's key alone");
    assert_eq!(o.path(&gone), Some(ThingPath::Known(Path { purge: 2, things: vec![t(9), t(2)], direct: 0 })));
    let plain = built(content(1));
    assert!(seal_header_only(&plain, &plain.header, &blob, &mut rng()).unwrap().sections.is_empty());
    let forged = Envelope { header: plain.header.clone(), sigs: plain.sigs.clone(), sections: e.sections.clone() };
    assert!(Envelope::decode(&forged.encode()).is_err(), "a section of no part beside a path in the clear");
}

// spec/wire.md §4 `Split`: a forged entry harms only its own thing, alike at every reader of it:
// an encryption carrying a key its entry does not commit to (a key for another entry, an entry
// sealed under another key, entries swapped) holds nothing; an entry opening to a list breaking `Path`'s rules
// or leaving out the purge author leaves its thing's parts holding nothing, whichever encryption
// carried them; the other things' parts and paths stand.
#[test]
fn a_forged_entry_harms_only_its_own_thing() {
    let c = built(split(3));
    let things = c.header.things();
    let first = things[0];
    let blob = Secret32::from_bytes([3; 32]);
    let secret = |r: &Tid| Secret32::from_bytes([r.as_bytes()[0]; 32]);
    let theirs = |c: &CommitBlob, x: &Tid| c.parts.iter().filter(|p| c.header.aspects[p.ai].tid == *x).count();
    // the same commit with the first entry replaced under its own key, re-signed (a writer
    // refuses to build it)
    let with_entry = |listed: &[Tid]| -> CommitBlob {
        let mut f = c.clone();
        if let Paths::Split(s) = &mut f.header.path {
            s.entries[0] = Split::seal(&c.keys[&0], listed, 0).unwrap();
        }
        f.sigs = Sigs::signed(&f.id(), &key(), None, vec![], vec![]);
        f
    };
    let mut b = split(3);
    b.split.as_mut().unwrap().things.get_mut(&first).unwrap().0 = (vec![t(9), t(9)], 0);
    assert!(b.build(&key(), &TestSecrets { admin: true }, &mut MemoryBlobs::default(), &mut rng()).is_err());
    for (forged, why) in [(with_entry(&[t(9), t(9)]), "a thing twice"), (with_entry(&[t(1)]), "the signer"), (with_entry(&[t(8)]), "author left out"), (with_entry(&[first, t(2)]), "the thing not last")] {
        assert_eq!(forged.path(&first), Some(ThingPath::Bad), "{why}");
        for (sel, name) in [(true, "own section"), (false, "copy")] {
            let env = if sel {
                seal_commit(&forged, &forged.header, |ai| forged.header.aspects[ai].tid, |r, _| Some((secret(r), vec![])), &[], &mut rng()).unwrap()
            } else {
                seal_commit(&forged, &forged.header, |_| (), |_, _| Some((blob.clone(), vec![])), &[], &mut rng()).unwrap()
            };
            let o = env.open(|s| vec![secret(&forged.header.aspects[s.ais[0]].tid), blob.clone()]).unwrap().commit;
            assert_eq!(theirs(&o, &first), 0, "{why}, {name}");
            assert!(things[1..].iter().all(|x| theirs(&o, x) == 1 && matches!(o.path(x), Some(ThingPath::Known(_)))), "{why}, {name}");
        }
    }
    // keys their entries do not commit to: the section carrying them holds nothing (a swap
    // leaves both things' keys committed nowhere)
    let mut swapped = c.clone();
    if let Paths::Split(s) = &mut swapped.header.path {
        s.entries.swap(0, 1);
    }
    swapped.sigs = Sigs::signed(&swapped.id(), &key(), None, vec![], vec![]);
    let mut wrong = c.clone();
    wrong.keys.insert(0, [1; 32]);
    for (e, why) in [(seal_commit_unchecked(&swapped, &secret), "entries swapped"), (seal_commit_unchecked(&wrong, &secret), "a key that opens nothing")] {
        let o = e.open(|s| vec![secret(&e.header.aspects[s.ais[0]].tid)]).unwrap().commit;
        assert_eq!(theirs(&o, &first), 0, "{why}");
        assert_eq!(theirs(&o, &things[2]), 1, "{why}");
        assert!(matches!(o.path(&things[2]), Some(ThingPath::Known(_))), "{why}");
    }
    // one encoding: a section carrying a key beyond its parts' things (its entry commits to it) holds
    // nothing; a section of no part carrying the key of a thing the commit does not destroy too
    let id = c.id();
    let mut sections: Vec<Section> = things
        .iter()
        .enumerate()
        .map(|(i, x)| {
            let ps: Vec<&Part> = c.parts.iter().filter(|p| c.header.aspects[p.ai].tid == *x).collect();
            let keys = if i == 0 { c.keys.clone() } else { BTreeMap::from([(i, c.keys[&i])]) };
            Section::seal(&id, &ps, Some(&keys), vec![], &secret(x), &mut rng()).unwrap()
        })
        .collect();
    sections.push(Section::seal(&id, &[] as &[Part], Some(&BTreeMap::from([(1, c.keys[&1])])), vec![], &blob, &mut rng()).unwrap());
    sections.sort_by_key(|s| s.ais.first().copied());
    let extra = Envelope { header: c.header.clone(), sigs: c.sigs.clone(), sections };
    let o = extra.open(|s| s.ais.first().map_or(vec![blob.clone()], |ai| vec![secret(&c.header.aspects[*ai].tid)])).unwrap().commit;
    assert_eq!(theirs(&o, &first), 0, "extra keys");
    assert!(things[1..].iter().all(|x| theirs(&o, x) == 1), "extra keys harm only their section");
    assert_eq!(o.keys.keys().copied().collect::<Vec<_>>(), vec![1, 2], "no key from a refused section");
    // a key from another commit's entry: opens nothing here
    let mut o = split(3);
    o.blind = Some([9; 16]);
    let other = built(o);
    assert_eq!(c.header.open_path(0, &other.keys[&0]), None);
    // the stored form refuses a key its entry does not commit to
    assert!(CommitBlob::decode(&wrong.encode()).is_err());
}

// spec/wire.md §4 `Split`, `PathKey`; spec/crypto.md §5 Path entry (an entry commits to its path
// key; a reader accepts no other): the destroyed thing's entry commits to its true key `k1`, its
// ciphertext sealed under `k2` (what a ciphertext opening under two keys gives a writer:
// XChaCha20-Poly1305 commits to no key; the engine's `validity::entry_under_two_keys` builds one). Whatever
// route `k2` comes by it is no key of the entry, so two readers can never read two paths: the
// header (`open_path`, as a roles secret's key is tried), the thing's own section, a copy's
// section, a header-only copy and the stored form each hold nothing of it under `k2`; under `k1`
// the entry reads bad (its own key opens nothing), alike in every encryption, the thing's parts
// holding nothing; the other thing stands throughout.
#[test]
fn an_entry_accepts_only_the_key_it_commits_to() {
    let mut b = split(2);
    let gone = b.aspects[1].tid;
    b.purge = vec![PurgeItem::Aspect { tid: gone, ak: osis_base::Ak::new(retention::CREATED).unwrap() }];
    let c = built(b);
    let i = c.header.things().iter().position(|x| *x == gone).unwrap();
    let other = c.header.things()[1 - i];
    let (k1, k2) = (c.keys[&i], [0x77; 32]);
    let mut f = c.clone();
    if let Paths::Split(s) = &mut f.header.path {
        s.entries[i] = [key_commitment(&k1).to_vec(), Split::seal(&k2, &[t(9), t(2)], 0).unwrap()[COMMITMENT_LEN..].to_vec()].concat();
    }
    f.sigs = Sigs::signed(&f.id(), &key(), None, vec![], vec![]);
    assert_eq!(f.header.open_path(i, &k2), None, "k2 is no key of the entry");
    assert_eq!(f.header.open_path(i, &k1), Some(ThingPath::Bad), "its committed key opens nothing");
    let id = f.id();
    let blob = Secret32::from_bytes([3; 32]);
    let secret = |r: &Tid| Secret32::from_bytes([r.as_bytes()[0]; 32]);
    let theirs = |c: &CommitBlob, x: &Tid| c.parts.iter().filter(|p| c.header.aspects[p.ai].tid == *x).count();
    for (k, name) in [(k2, "k2"), (k1, "k1")] {
        let mut fk = f.clone();
        fk.keys.insert(i, k);
        assert!(CommitBlob::decode(&fk.encode()).is_err(), "{name}: the stored form");
        // the thing's own section, and a copy's section under the blob key, carrying k
        let own = seal_commit_unchecked(&fk, &secret);
        let ps: Vec<&Part> = fk.parts.iter().filter(|p| fk.header.aspects[p.ai].tid == gone).collect();
        let mut copy = own.clone();
        copy.sections.retain(|s| fk.header.aspects[s.ais[0]].tid != gone);
        copy.sections.push(Section::seal(&id, &ps, Some(&BTreeMap::from([(i, k)])), vec![], &blob, &mut rng()).unwrap());
        copy.sections.sort_by_key(|s| s.ais.first().copied());
        for (e, route) in [(own, "own section"), (copy, "copy")] {
            let o = e.open(|s| vec![secret(&fk.header.aspects[s.ais[0]].tid), blob.clone()]).unwrap().commit;
            assert_eq!(theirs(&o, &gone), 0, "{name}, {route}");
            assert_eq!(o.keys.contains_key(&i), k == k1, "{name}, {route}: the key taken only where committed");
            assert_eq!(o.path(&gone), (k == k1).then_some(ThingPath::Bad), "{name}, {route}");
            assert_eq!((theirs(&o, &other), o.path(&other).is_some_and(|p| matches!(p, ThingPath::Known(_)))), (1, true), "{name}, {route}: the other thing stands");
        }
        // a header-only copy of the destroying request carrying k
        let bare = rewrite(&fk, |_| true);
        let h = seal_header_only(&bare, &fk.header, &blob, &mut rng()).unwrap();
        let o = h.open(|_| vec![blob.clone()]).unwrap().commit;
        assert_eq!(o.path(&gone), (k == k1).then_some(ThingPath::Bad), "{name}, header-only copy");
    }
}

/// `c` sealed per thing with whatever keys it holds, unchecked: a forger's encryption.
fn seal_commit_unchecked(c: &CommitBlob, secret: &dyn Fn(&Tid) -> Secret32) -> Envelope {
    let id = c.id();
    let things = c.header.things();
    let mut sections: Vec<Section> = things
        .iter()
        .enumerate()
        .map(|(i, x)| {
            let ps: Vec<&Part> = c.parts.iter().filter(|p| c.header.aspects[p.ai].tid == *x).collect();
            Section::seal(&id, &ps, Some(&BTreeMap::from([(i, c.keys[&i])])), vec![], &secret(x), &mut rng()).unwrap()
        })
        .collect();
    sections.sort_by_key(|s| s.ais.first().copied());
    Envelope { header: c.header.clone(), sigs: c.sigs.clone(), sections }
}

// spec/wire.md §4 field 11 (at level 2 at most one, the commit's purge author's), spec/crypto.md §7
// (Levels): a split commit writing three things, each along its own path, of a purge-by
// calling for level 2 lists one level-2 key, which every such aspect names; its other levels are
// per thing.
#[test]
fn a_split_commit_lists_one_level_2_key() {
    for by in [osis_schema::PurgeBy::AuthorOrAdmin, osis_schema::PurgeBy::Writer] {
        let mut b = split(3);
        b.aspects.iter_mut().for_each(|a| a.purge_by = by);
        let h = built(b).header;
        assert!(h.is_split());
        let level_2: Vec<usize> = (0..h.keys.len()).filter(|i| h.keys[*i].level == 2).collect();
        assert_eq!(level_2.len(), 1, "{by:?}: one level-2 key");
        assert!(h.aspects.iter().all(|a| a.keys.contains(&level_2[0])), "{by:?}: every aspect names it");
        h.validate().unwrap();
    }
}

// Interim (notes/a1-spec/README.md step 3): the walk reads every thing a commit writes as acting
// for its one purge author, in the clear in either form, the signer for index 0. A role commit
// whose index names a listed thing is invalid.
#[test]
fn interim_acting_is_the_one_purge_author() {
    let deep = Path { purge: 1, things: vec![t(2), t(4)], direct: 0 };
    for (path, author) in [(Path::default(), t(1)), (Path::through(t(2)), t(2)), (deep.clone(), t(2))] {
        for n in [1, 3] {
            let mut b = content(n);
            b.path = path.clone();
            assert_eq!(built(b).header.purge_author(), author, "{n} things");
        }
    }
    let mut b = split(2);
    b.split.as_mut().unwrap().author = None;
    b.split.as_mut().unwrap().things.values_mut().for_each(|p| p.0 = (vec![], 0));
    assert_eq!(built(b).header.purge_author(), t(1));
    one(Path { purge: 0, things: vec![t(2)], direct: 0 }).validate().unwrap();
    let mut r = crate::tests::validate::role_header("roles.0");
    r.path = Paths::One(Path::through(t(9)));
    assert!(r.validate().unwrap_err().to_string().contains("a path this commit may not state"), "a role commit's index names its signer");
    r.path = Paths::One(Path { purge: 0, things: vec![t(9)], direct: 0 });
    r.validate().unwrap();
}

// notes/path-form.md Bytes: a commit writing one thing along the empty path spends 18 bytes on
// `signer` and `path` (16 + 2); one listed thing adds 16;
// several things along one path cost what one does; the split form 3 bytes, an author's 16, and
// an entry per thing (117 B up to four listed things), each section 38 B for its thing's key.
#[test]
fn header_bytes_of_signer_and_path() {
    let mut h = sample_header();
    h.path = Paths::default();
    let base = h.encode().len();
    let signer = osis_base::cbor::Item::parse(&h.encode(), &osis_base::Limits::new(512, 1 << 20)).unwrap().as_list().unwrap().iter().nth(1).unwrap().bytes().len();
    assert_eq!((signer, Path::default().encode().len()), (16, 2));
    h.path = Paths::One(Path::through(t(2)));
    assert_eq!(h.encode().len(), base + 16);
    assert_eq!(path_len(&built(content(3)).header), path_len(&built(content(1)).header));
    let mut b = split(2);
    b.split.as_mut().unwrap().author = None;
    assert_eq!(path_len(&built(b).header), 3 + 2 * 117);
    // a section's path key: `[[Part*], [[i, key]]]` against `[Part*]`
    let c = built(split(2));
    let ps: Vec<&Part> = c.parts.iter().take(1).collect();
    let s = Secret32::from_bytes([1; 32]);
    let keyed = Section::seal(&c.id(), &ps, Some(&BTreeMap::from([(0, [0; 32])])), vec![], &s, &mut rng()).unwrap();
    let bare = Section::seal(&c.id(), &ps, None, vec![], &s, &mut rng()).unwrap();
    assert_eq!(keyed.encoded_len() - bare.encoded_len(), 1 + 1 + 1 + 1 + 34);
}

// spec/wire.md §4 `marks`: a path marking hops direct round-trips in the clear and in a split
// entry, costing nothing where no hop is marked and 2 bytes where hops below 8 are; the decoder
// rejects marks that are empty, end in a zero byte, set a bit past the hop past the last listed
// thing, or run past 9 bytes; a split entry likewise reads as bad.
#[test]
fn marks_decode_by_their_rules() {
    let many: Vec<_> = (0..MAX_PATH_THINGS).map(|i| osis_base::Tid::from_bytes([i as u8 + 20; 15])).collect();
    let all_hops: crate::Marks = (1 << (MAX_PATH_THINGS + 1)) - 1;
    for p in [Path { purge: 0, things: vec![], direct: 1 }, Path { purge: 1, things: vec![t(2)], direct: 0b10 }, Path { purge: 0, things: vec![t(2), t(4)], direct: 0b101 }, Path { purge: 3, things: many.clone(), direct: all_hops }, Path { purge: 0, things: many.clone(), direct: 1 << MAX_PATH_THINGS }] {
        let h = one(p.clone());
        assert_eq!(Header::decode(&h.encode()).unwrap(), h, "{p:?}");
    }
    assert_eq!(Path { purge: 0, things: vec![t(2)], direct: 0b10 }.encode().len(), Path::through(t(2)).encode().len() + 2);
    assert_eq!(crate::marks_bytes(1 << MAX_PATH_THINGS).len(), 9);
    // hand-built tails: [0, t(2), marks]
    let raw = |marks: &[u8]| {
        let mut b = Vec::new();
        osis_base::cbor::put_array(&mut b, 3);
        osis_base::cbor::put_uint(&mut b, 0);
        osis_base::cbor::put_bytes(&mut b, t(2).as_bytes());
        osis_base::cbor::put_bytes(&mut b, marks);
        Path::read(osis_base::cbor::Item::parse(&b, &crate::header::LIMITS).unwrap(), &t(1))
    };
    assert_eq!(raw(&[0b11]).unwrap(), Path { purge: 0, things: vec![t(2)], direct: 0b11 });
    for (m, why) in [(&[][..], "empty"), (&[1, 0][..], "a trailing zero byte"), (&[0b100][..], "a bit past the hop past the end"), (&[0; 10][..], "past 9 bytes")] {
        assert!(matches!(raw(m), Err(Error::Malformed(_))), "{why}");
    }
    // a list past 127 things with marks: malformed, not a shift past the marks' width
    let mut b = Vec::new();
    osis_base::cbor::put_array(&mut b, 202);
    osis_base::cbor::put_uint(&mut b, 0);
    (0..200u32).for_each(|i| osis_base::cbor::put_bytes(&mut b, osis_base::Tid::from_bytes([(i % 250) as u8, (i / 250) as u8, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7]).as_bytes()));
    osis_base::cbor::put_bytes(&mut b, &[1]);
    assert!(matches!(Path::read(osis_base::cbor::Item::parse(&b, &crate::header::LIMITS).unwrap(), &t(1)), Err(Error::Malformed(_))));
    assert!(Split::seal(&[3; 32], &[t(2)], 0b100).is_err(), "a writer seals no mark past its hops");
    for (listed, direct) in [(vec![], 1), (vec![t(2), t(4), t(5), t(6)], 0b11111), (many[..16].to_vec(), 1 << 16), (many.clone(), all_hops)] {
        let e = Split::seal(&[3; 32], &listed, direct).unwrap();
        assert_eq!(Some(e.len()), entry_len(listed.len()), "a mark keeps the entry's class");
        assert_eq!(Split::open(&[3; 32], &e), Some(Some((listed, direct))));
    }
}

// spec/wire.md §4 field 2: one path serves several things only where each thing's own marks are
// its: a mark on the hop past the end (bit 1 of `[D]`) marks each thing one hop past D, and the
// end D has no such hop, so D beside a marked thing past it is no one path.
#[test]
fn one_path_carries_its_marks() {
    let (s, d) = (t(1), t(2));
    let mk = |things: Vec<Tid>, direct| Path { purge: 0, things, direct };
    let marked = mk(vec![d], 0b10);
    let each = [(t(5), marked.clone()), (t(6), marked.clone())];
    assert_eq!(Path::one_of(each.iter().map(|(a, b)| (a, b)), s, s), Some(marked.clone()));
    let mixed = [(t(5), marked.clone()), (t(6), mk(vec![d], 0))];
    assert_eq!(Path::one_of(mixed.iter().map(|(a, b)| (a, b)), s, s), None);
    let with_end = [(d, mk(vec![], 0)), (t(5), marked.clone())];
    assert_eq!(Path::one_of(with_end.iter().map(|(a, b)| (a, b)), s, s), None);
    let first_hop = [(d, mk(vec![], 1)), (t(5), mk(vec![d], 1))];
    assert_eq!(Path::one_of(first_hop.iter().map(|(a, b)| (a, b)), s, s), Some(mk(vec![d], 1)));
}
