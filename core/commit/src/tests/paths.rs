//! Stated paths in the header and sections (spec/wire.md §4 fields 1, 2, 17; `Path`, `Paths`,
//! `Salted`, `Contents`).

use crate::tests::build::{content, key, rng};
use crate::tests::verify::TestSecrets;
use crate::tests::{sample_header, t};
use crate::*;
use osis_base::format::MAX_PATH_THINGS;
use osis_crypto::Secret32;

fn built(b: CommitBuilder) -> CommitBlob {
    b.build(&key(), &TestSecrets { admin: true }, &mut MemoryBlobs::default(), &mut rng()).unwrap().commit
}

fn one(path: Path) -> Header {
    Header { path: Paths::One(path), ..sample_header() }
}

// spec/wire.md §4 field 2: a path in the clear round-trips with the empty path, one listed thing
// and MAX_PATH_THINGS of them; the decoder rejects a path past MAX_PATH_THINGS, an index past
// its things, a thing twice, the signer listed, and a hashed path of fewer than two hashes.
#[test]
fn path_in_the_clear_decodes_by_its_rules() {
    let many: Vec<_> = (0..MAX_PATH_THINGS).map(|i| osis_base::Tid::from_bytes([i as u8 + 20; 15])).collect();
    for p in [Path::default(), Path::through(t(2)), Path { purge: 3, things: many.clone() }] {
        let h = one(p);
        assert_eq!(Header::decode(&h.encode()).unwrap(), h);
    }
    let mut longer = many.clone();
    longer.push(t(200));
    for (p, why) in [
        (Path { purge: 0, things: longer }, "longer than MAX_PATH_THINGS"),
        (Path { purge: 2, things: vec![t(2)] }, "index out of range"),
        (Path { purge: 0, things: vec![t(2), t(2)] }, "thing twice"),
        (Path { purge: 0, things: vec![t(1)] }, "the signer"),
    ] {
        assert!(matches!(Header::decode(&one(p).encode()), Err(Error::Malformed(_))), "{why}");
    }
    let h = Header { path: Paths::Hashed(vec![[1; 32]]), ..sample_header() };
    assert!(Header::decode(&h.encode()).is_err(), "one hash");
    let h = Header { path: Paths::Hashed(vec![[1; 32], [2; 32]]), ..sample_header() };
    assert_eq!(Header::decode(&h.encode()).unwrap(), h);
}

// spec/wire.md §4 field 2: one path in the clear stands for any number of things written; a
// hashed form on a commit writing one thing, or a hash count other than the things written, is
// bad input.
#[test]
fn path_forms_by_the_things_written() {
    let mut h = sample_header();
    h.validate().unwrap();
    h.path = Paths::Hashed(vec![[1; 32], [2; 32]]);
    assert!(matches!(h.validate(), Err(Error::Malformed(_))), "hashed on one thing");
    let mut b = h.aspects[0].clone();
    b.tid = t(4);
    h.aspects.push(b);
    h.validate().unwrap();
    h.path = Paths::Hashed(vec![[1; 32], [2; 32], [3; 32]]);
    assert!(matches!(h.validate(), Err(Error::Malformed(_))), "three hashes for two things");
    h.path = Paths::One(Path::through(t(2)));
    h.validate().unwrap();
}

/// `content(n)` whose things after the first state `[2, t(9), t(2)]`: a path other than the
/// first thing's, acting on the same thing (`t(2)`, the Interim's one acting thing).
fn differing(n: usize) -> CommitBuilder {
    let mut b = content(n);
    let other = Path { purge: 2, things: vec![t(9), t(2)] };
    b.thing_paths = b.aspects.iter().skip(1).map(|a| (a.tid, other.clone())).collect();
    b
}

// spec/wire.md §4 (one path): every thing's path equal, the header states it once
// in the clear, so a commit writing several things spends on its path what one writing one thing
// does; paths that differ go hashed, one per thing.
#[test]
fn equal_paths_are_stated_once() {
    let one = built(content(1));
    let three = built(content(3));
    assert_eq!(three.header.path, Paths::One(Path::through(t(2))));
    assert!(three.salted.is_empty());
    let path_len = |h: &Header| {
        let mut out = Vec::new();
        h.path.put(&mut out);
        out.len()
    };
    assert_eq!(path_len(&three.header), path_len(&one.header));
    for t in three.header.things() {
        assert_eq!(three.path(&t), Some(&Path::through(crate::tests::t(2))));
    }
    let mut same = content(3);
    same.thing_paths = same.aspects.iter().map(|a| (a.tid, Path::through(t(2)))).collect();
    assert_eq!(built(same).header.path, three.header.path, "stated per thing, all equal");
    let d = built(differing(3));
    assert!(matches!(&d.header.path, Paths::Hashed(hs) if hs.len() == 3));
    assert_eq!(path_len(&d.header), 1 + 3 * 34);
}

// spec/wire.md §4: the commit ID, and so the signature, covers `signer`, `path` and `remains`:
// a relay changing any of them changes the ID and the signature no longer verifies.
#[test]
fn signer_path_and_remains_are_signed() {
    let c = built(content(1));
    let k = key().verifying_key();
    verify_signature(&c.id(), &c.sigs, &k).unwrap();
    let flips: [&dyn Fn(&mut Header); 4] = [
        &|h| h.signer = t(77),
        &|h| h.path = Paths::One(Path::default()),
        &|h| h.path = Paths::One(Path { purge: 0, things: vec![t(2)] }),
        &|h| h.remains = Some(t(5)),
    ];
    for flip in flips {
        let mut h = c.header.clone();
        flip(&mut h);
        assert_ne!(h.id(), c.id());
        assert!(verify_signature(&h.id(), &c.sigs, &k).is_err());
    }
}

// spec/wire.md §4 `Salted`, `Contents`: a commit whose things' paths differ carries a salted hash
// per thing, each section (a copy's too: one per thing) its thing's Salted; every reader gets the
// path back, and a section whose Salted is missing or does not hash to its entry holds no part
// (its parts dropped). A copy of a commit stating one path holds one section.
#[test]
fn hashed_paths_ride_in_their_sections() {
    let c = built(differing(3));
    let Paths::Hashed(hs) = &c.header.path else { panic!("hashed") };
    assert_eq!(hs.len(), 3);
    assert_eq!(c.salted.len(), 3);
    for (i, t) in c.header.things().into_iter().enumerate() {
        let want = if i == 0 { Path::through(crate::tests::t(2)) } else { Path { purge: 2, things: vec![crate::tests::t(9), crate::tests::t(2)] } };
        assert_eq!(c.path(&t), Some(&want));
        assert_eq!(c.header.path_hash(&t), Some(c.salted_of(&t).unwrap().hash()));
    }
    let secret = Secret32::from_bytes([3; 32]);
    let env = seal_commit(&c, &c.header, |_| (), |_, _| Some((secret.clone(), vec![])), &[], &mut rng()).unwrap();
    assert_eq!(env.sections.len(), 3, "a copy holds a section per thing");
    let opened = env.open(|_| vec![secret.clone()]).unwrap().commit;
    assert_eq!(opened, c);
    assert_eq!(CommitBlob::decode(&opened.encode()).unwrap(), c);
    let plain = built(content(3));
    let e = seal_commit(&plain, &plain.header, |_| (), |_, _| Some((secret.clone(), vec![])), &[], &mut rng()).unwrap();
    assert_eq!(e.sections.len(), 1, "one path stated: a copy holds one section");
    assert_eq!(e.open(|_| vec![secret.clone()]).unwrap().commit, plain);

    // a Salted that does not hash: its section opens to nothing
    let first = c.header.things()[0];
    let mut forged = c.clone();
    forged.salted.get_mut(&0).unwrap().salt[0] ^= 1;
    assert!(CommitBlob::decode(&forged.encode()).is_err(), "the stored form checks it");
    forged.check_paths().unwrap_err();
    let parts: Vec<&Part> = forged.parts.iter().filter(|p| forged.header.aspects[p.ai].tid == first).collect();
    let bad = Section::seal(&c.id(), forged.salted_of(&first), &parts, vec![], &secret, &mut rng()).unwrap();
    let missing = Section::seal(&c.id(), None, &parts, vec![], &secret, &mut rng()).unwrap();
    for s in [bad, missing] {
        let mut e = env.clone();
        let i = e.sections.iter().position(|x| x.ais == s.ais).unwrap();
        e.sections[i] = s;
        let o = e.open(|_| vec![secret.clone()]).unwrap().commit;
        assert!(o.path(&first).is_none());
        assert!(o.parts.iter().all(|p| o.header.aspects[p.ai].tid != first), "its parts dropped");
        assert_eq!(o.parts.len(), c.parts.len() - parts.len());
    }
    // a Salted in a section of a commit stating its path in the clear holds no part either
    let one = built(content(1));
    let parts: Vec<&Part> = one.parts.iter().collect();
    let s = Section::seal(&one.id(), c.salted_of(&first), &parts, vec![], &secret, &mut rng()).unwrap();
    let e = Envelope { header: one.header.clone(), sigs: one.sigs.clone(), sections: vec![s] };
    assert!(e.open(|_| vec![secret.clone()]).unwrap().commit.parts.is_empty());
}

// Interim (notes/a1-spec/README.md step 3): the walk reads the path's last listed thing as the
// commit acting on it, its signer for the empty path, alike in both forms (a hashed one known
// once a section opens); a path whose index does not name that thing, a role commit's path listing
// a thing, or hashed paths acting on different things, are invalid.
#[test]
fn interim_acting_is_the_last_listed_thing() {
    for (path, acting) in [(Path::default(), t(1)), (Path::through(t(2)), t(2))] {
        for n in [1, 3] {
            let mut b = content(n);
            b.path = path.clone();
            let c = built(b);
            assert_eq!(c.acting(), Some(acting), "{n} things");
            assert_eq!(c.header.acting(), Some(acting));
        }
    }
    let c = built(differing(3));
    assert_eq!((c.acting(), c.header.acting()), (Some(t(2)), None));
    let h = one(Path { purge: 0, things: vec![t(2)] });
    assert!(matches!(h.validate(), Err(Error::Invalid(_))), "index naming the signer");
    let mut b = content(1);
    b.path = Path { purge: 1, things: vec![t(2), t(4)] };
    assert!(b.build(&key(), &TestSecrets { admin: true }, &mut MemoryBlobs::default(), &mut rng()).is_err());
    let mut b = differing(3);
    let last = b.aspects[2].tid;
    b.thing_paths.insert(last, Path::through(t(4)));
    assert!(b.build(&key(), &TestSecrets { admin: true }, &mut MemoryBlobs::default(), &mut rng()).is_err(), "two acting things");
}

// spec/wire.md §4 field 17: `remains` sits only on a role commit writing `roles.0`, without the
// adminless mark.
#[test]
fn remains_only_beside_edge_writes() {
    let mut r = crate::tests::validate::role_header("roles.0");
    r.remains = Some(t(9));
    assert_eq!(Header::decode(&r.encode()).unwrap(), r);
    r.validate().unwrap();
    let mut x = r.clone();
    x.adminless = true;
    assert!(x.validate().is_err(), "beside the adminless mark");
    let x = Header { remains: Some(t(9)), ..crate::tests::validate::role_header("keys.0") };
    assert!(x.validate().is_err(), "no edge write");
    let x = Header { remains: Some(t(9)), ..sample_header() };
    assert!(x.validate().is_err(), "content commit");
}

// notes/a1-spec/README.md Bytes per commit: a commit writing one thing along the empty path
// spends 19 bytes on `signer`, `path` and `remains` (16 + 2 + 1), against the 32 of the two tids
// it replaces; one listed thing adds 16, a remaining admin 16.
#[test]
fn header_bytes_of_signer_path_and_remains() {
    let mut h = sample_header();
    h.path = Paths::default();
    let base = h.encode().len();
    let signer = osis_base::cbor::Item::parse(&h.encode(), &osis_base::Limits::new(512, 1 << 20)).unwrap().as_list().unwrap().iter().nth(1).unwrap().bytes().len();
    assert_eq!((signer, Path::default().encode().len(), 1), (16, 2, 1));
    h.path = Paths::One(Path::through(t(2)));
    assert_eq!(h.encode().len(), base + 16);
    h.path = Paths::default();
    h.remains = Some(t(9));
    assert_eq!(h.encode().len(), base + 16);
}
