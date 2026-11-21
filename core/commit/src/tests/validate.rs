//! Header validation and retention (spec/wire.md §4, spec/commits.md §2, §5, §6).

use crate::tests::{dkey, sample_header, t, ts};
use crate::retention::purge_keep_until;
use crate::*;
use crate::header::aspect_order;
use osis_base::{Ak, CommitId, Tid, Value};
use osis_schema::{PurgeBy, Retention};

fn invalid(h: &Header) -> Error {
    h.validate().unwrap_err()
}

// spec/wire.md §4: the sample header is valid; sort orders and indices are checked.
#[test]
fn validate_layout() {
    let h = sample_header();
    h.validate().unwrap();
    let mut x = h.clone();
    x.keys.swap(0, 1);
    assert!(matches!(invalid(&x), Error::Malformed(_)));
    let mut x = h.clone();
    x.keys.push(dkey(3, 3));
    assert!(matches!(invalid(&x), Error::Malformed(_)), "unused delete key");
    let mut x = h.clone();
    let mut a2 = x.aspects[0].clone();
    a2.tid = t(0);
    x.aspects.push(a2);
    assert!(matches!(invalid(&x), Error::Malformed(_)), "aspects unsorted");
    x.aspects.reverse();
    x.validate().unwrap();
    let mut x = h.clone();
    x.aspects[0].lo = 2;
    assert!(invalid(&x).to_string().contains("counter range"));
}

// spec/commits.md §2: kinds and aspect classes; snapshots have empty ranges.
#[test]
fn validate_kinds() {
    let h = sample_header();
    let mut x = h.clone();
    x.kind = Kind::Role;
    assert!(matches!(invalid(&x), Error::Invalid(_)), "content aspect in a role commit");
    let mut x = h.clone();
    x.kind = Kind::ContentSnapshot;
    x.form = Form::Commit;
    assert!(invalid(&x).to_string().contains("counter range"));
    x.aspects[0].lo = 0;
    x.aspects[0].hi = 0;
    assert!(invalid(&x).to_string().contains("writer"));
    x.aspects[0].retention.by = PurgeBy::Writer;
    x.keys.push(dkey(3, 3));
    x.aspects[0].keys = vec![0, 1, 2];
    x.validate().unwrap();
}

// spec/wire.md §4 (header flags): field 18, a trailing uint, present only when nonzero; bit 0 the
// own cover, on a durable content snapshot only (a header without flags keeps its bytes); a
// flags of 0 or a reserved bit is bad.
#[test]
fn own_cover_flag_spec_wire_4() {
    let mut x = sample_header();
    x.own_cover = true;
    assert!(invalid(&x).to_string().contains("own cover"), "on a content commit");
    x.kind = Kind::ContentSnapshot;
    x.form = Form::Commit;
    x.aspects[0].lo = 0;
    x.aspects[0].hi = 0;
    x.aspects[0].retention.by = PurgeBy::Writer;
    x.keys.push(dkey(3, 3));
    x.aspects[0].keys = vec![0, 1, 2];
    x.validate().unwrap();
    let marked = x.encode();
    assert_eq!(Header::decode(&marked).unwrap(), x);
    x.own_cover = false;
    assert_eq!(x.encode().len() + 1, marked.len(), "one byte, on the own cover alone");
    assert_eq!(Header::decode(&x.encode()).unwrap(), x);
    // a trailing 0 or a reserved bit is no canonical header
    for f in [0x00, 0x04] {
        let mut bad = x.encode();
        bad[0] += 1;
        bad.push(f);
        assert!(Header::decode(&bad).is_err(), "flags {f}");
    }
    x.own_cover = true;
    x.ephemeral = Some(EphClass::Plain);
    assert!(invalid(&x).to_string().contains("own cover"), "an ephemeral own cover");
}

// spec/wire.md §4 (header flags): field 18 bit 1, the adminless mark, on a role commit only, one byte.
#[test]
fn adminless_flag_spec_wire_4() {
    let mut x = role_header("roles.0");
    x.validate().unwrap();
    let plain = x.encode();
    x.adminless = true;
    x.validate().unwrap();
    let marked = x.encode();
    assert_eq!(plain.len() + 1, marked.len());
    assert_eq!(Header::decode(&marked).unwrap(), x);
    let mut c = sample_header();
    c.adminless = true;
    assert!(invalid(&c).to_string().contains("adminless"), "on a content commit");
}

pub(crate) fn role_header(ak: &str) -> Header {
    let mut h = sample_header();
    h.kind = Kind::Role;
    h.form = crate::header::Form::Commit;
    h.path = Paths::default();
    let a = &mut h.aspects[0];
    a.ak = Ak::new(ak).unwrap();
    a.retention = retention::ROLE_RETENTION;
    a.keys = vec![0];
    a.hash = [1; 32];
    h.expires = None;
    h.keys.truncate(1);
    h
}

// spec/commits.md §2, §5: role commits carry no expires, keep fixed retention, may touch secrets.0 and keys.0 of several things; a frontier only on role
// commits; roles.0 is never compaction-snapshotted.
// spec/commits.md §2 (role commit no expires); spec/commits.md §3 (commit form kinds): a role
// commit in session form is bad input.
#[test]
fn validate_role_commit() {
    let h = role_header("roles.0");
    h.validate().unwrap();
    // spec/commits.md §3 (commit form kinds), §4: a session-form role commit is bad input
    let mut x = h.clone();
    x.form = crate::tests::SESSION;
    assert!(invalid(&x).to_string().contains("session form outside a content commit"));
    // Interim (notes/a1-spec/README.md step 3): a role commit's index names its signer
    let mut x = h.clone();
    x.path = Paths::One(Path::through(t(9)));
    assert!(invalid(&x).to_string().contains("a path this commit may not state"));
    let mut x = h.clone();
    x.expires = Some(9_999_999_999);
    assert!(invalid(&x).to_string().contains("expires"));
    let mut x = h.clone();
    x.aspects[0].retention.by = PurgeBy::Writer;
    assert!(matches!(invalid(&x), Error::Malformed(_) | Error::Invalid(_)));
    let mut x = h.clone();
    x.frontier = Some(std::sync::Arc::from([]));
    x.validate().unwrap();
    let mut c = sample_header();
    c.frontier = x.frontier.clone();
    assert!(invalid(&c).to_string().contains("frontier"));
    let mut x = h.clone();
    for (n, ak) in [(4, "secrets.0"), (5, "keys.0"), (6, "secrets.0")] {
        let mut a = x.aspects[0].clone();
        a.tid = t(n);
        a.ak = Ak::new(ak).unwrap();
        x.aspects.push(a);
    }
    x.validate().unwrap();
    let mut x = h.clone();
    x.kind = Kind::RoleSnapshot;
    x.aspects[0].lo = 0;
    x.aspects[0].hi = 0;
    assert!(invalid(&x).to_string().contains("roles.0"));
    // the control: a snapshot of keys.0 is fine
    let mut y = x.clone();
    y.aspects[0].ak = Ak::new("keys.0").unwrap();
    assert!(y.validate().is_ok());
}

// spec/commits.md §6 (one per commit): an expiring commit carries no fixed-retention aspect;
// `retention^.0` has ordinary retention, so one may expire.
#[test]
fn validate_commit_expiry() {
    let sort = |x: &mut Header| x.aspects.sort_by(|a, b| crate::header::aspect_order(&a.tid, a.ak.as_str()).cmp(&crate::header::aspect_order(&b.tid, b.ak.as_str())));
    let mut h = sample_header();
    h.expires = None;
    for (ak, fixed) in [("purge.0", true), ("retention^.0", false)] {
        let mut b = h.aspects[0].clone();
        b.ak = Ak::new(ak).unwrap();
        b.tid = t(2);
        let mut x = h.clone();
        x.aspects.insert(0, b);
        sort(&mut x);
            x.validate().unwrap();
        x.expires = Some(h.ts.wall_ms().0 + 1);
        if fixed {
            assert!(invalid(&x).to_string().contains("fixed-retention"), "{ak}");
        } else {
            x.validate().unwrap();
        }
    }
    // a minting is purgeable by admins alone (spec/commits.md §5 Destruction)
    for by in [PurgeBy::AuthorOrAdmin, PurgeBy::Writer] {
        let mut y = h.clone();
        y.aspects[0].ak = Ak::new("created.0").unwrap();
        y.aspects[0].retention = Retention { by };
        assert!(invalid(&y).to_string().contains("created.0 not purgeable by admin"), "{by:?}: {}", invalid(&y));
    }
}

// spec/commits.md §5, §6: expires after ts; purge never names role-class deltas; a purge request
// beside an expiry is valid, its floor ending there.
// spec/commits.md §5 (purge not role-class)
#[test]
fn validate_expiry_purge_retention() {
    let h = sample_header();
    let mut x = h.clone();
    x.expires = Some(h.ts.wall_ms().0);
    assert!(invalid(&x).to_string().contains("expires"));
    let mut x = h.clone();
    x.purge.push(PurgeItem::Aspect { tid: t(3), ak: Ak::new("app:title.0").unwrap() });
    x.validate().unwrap();
    assert_eq!(purge_keep_until(&x), x.expires, "the floor ends at the commit's expiry");
    x.expires = None;
    x.validate().unwrap();
    assert_eq!(purge_keep_until(&x), Some(x.ts.wall_ms().0 + osis_base::format::ROLE_KEEP_MS));
    x.purge.push(PurgeItem::Aspect { tid: t(3), ak: Ak::new("roles.0").unwrap() });
    x.purge.sort_by_key(crate::header::purge_bytes);
    assert!(invalid(&x).to_string().contains("role-class"));
}

// spec/wire.md §4 (a purge item on `created.0` by commit or by author), spec/commits.md §5
// (Destruction: an item on `created.0` names every minting): only the whole-aspect item is valid
// there; by commit or by author is bad input.
#[test]
fn validate_purge_created_whole_only_spec_wire_4() {
    let created = Ak::new(crate::retention::CREATED).unwrap();
    let with = |item: PurgeItem| {
        let mut x = sample_header();
        x.purge.push(item);
        x
    };
    with(PurgeItem::Aspect { tid: t(3), ak: created.clone() }).validate().unwrap();
    let by_commit = with(PurgeItem::Commit { tid: t(3), ak: created.clone(), ts: ts(1), src: osis_crdt::Source::commit(CommitId([7; 32])) });
    assert!(invalid(&by_commit).to_string().contains("created.0"));
    let by_author = with(PurgeItem::Author { tid: t(3), ak: created, author: t(4) });
    assert!(invalid(&by_author).to_string().contains("created.0"));
    with(PurgeItem::Author { tid: t(3), ak: Ak::new("app:title.0").unwrap(), author: t(4) }).validate().unwrap();
}

// spec/wire.md §4: a part's retention is `by` alone: every class round-trips; an unknown class, or
// one as a list, is malformed.
#[test]
fn retention_encoding_spec_wire_4() {
    let h = sample_header();
    for by in PurgeBy::ALL {
        let mut x = h.clone();
        x.aspects[0].retention = Retention { by };
        assert_eq!(Header::decode(&x.encode()).unwrap(), x);
    }
    for bad in [Value::Int(0), Value::Int(4), Value::List(vec![Value::Int(2), Value::Int(0)])] {
        let mut v = crate::tests::header_value(&h);
        if let Value::List(items) = &mut v
            && let Some(Value::List(aspects)) = items.get_mut(7)
            && let Some(Value::List(a)) = aspects.first_mut()
        {
            a[4] = bad.clone();
        }
        assert!(Header::decode(&osis_base::encode(&v)).is_err(), "{bad:?}");
    }
}

// spec/commits.md §5: fixed tables, write defaults (untyped: admin, no expiry), `nobody`
// refused, snapshot retention.
#[test]
fn retention_rules() {
    use osis_schema::AspectDefaults;
    use retention::*;
    assert_eq!(fixed_retention("secrets.0"), Some(ROLE_RETENTION));
    assert_eq!(fixed_retention("created.0"), None);
    assert_eq!(fixed_retention("retention^.0"), None);
    assert_eq!(fixed_retention("app:x.0"), None);
    assert_eq!(write_retention("app:x.0", None, None).unwrap(), Retention::default());
    assert_eq!(Retention::default().by, PurgeBy::Admin);
    assert_eq!(write_expires("app:x.0", ts(10), None, None).unwrap(), None);
    let d = AspectDefaults { retention: Retention { by: PurgeBy::Writer }, expires: Some(100) };
    assert_eq!(write_retention("app:x.0", Some(&d), None).unwrap(), d.retention);
    assert_eq!(write_expires("app:x.0", ts(10), Some(&d), None).unwrap(), Some(110));
    assert_eq!(write_expires("app:x.0", ts(10), Some(&d), Some(50)).unwrap(), Some(50));
    assert_eq!(write_expires("roles.0", ts(10), Some(&d), Some(50)).unwrap(), None);
    assert!(write_retention("roles.0", None, Some(Retention { by: PurgeBy::Writer })).is_err());
    assert_eq!(write_retention("retention^.0", None, None).unwrap(), Retention::default());
    // a snapshot is `writer`, its history the thing's setting; fixed retention keeps its own
    assert_eq!(snapshot_retention("app:x.0"), Retention { by: PurgeBy::Writer });
    assert_eq!(snapshot_retention("keys.0"), ROLE_RETENTION);
}

// spec/commits.md §2, spec/wire.md §4: an ephemeral commit's retention is `writer`, in session
// form and as a commit-form snapshot alike; it may undo a commit. A relay-only commit is a content
// snapshot and undoes nothing.
#[test]
fn ephemeral_retention_writer_spec_commits_2() {
    let mut session = sample_header();
    session.undoes = None;
    session.ephemeral = Some(EphClass::Plain);
    session.keys.push(dkey(3, 3));
    session.aspects[0].keys = vec![0, 1, 2];
    session.aspects[0].retention = crate::retention::EPHEMERAL_RETENTION;
    let mut snapshot = session.clone();
    snapshot.form = Form::Commit;
    snapshot.kind = Kind::ContentSnapshot;
    (snapshot.aspects[0].lo, snapshot.aspects[0].hi) = (0, 0);
    let mut undo = session.clone();
    undo.undoes = Some(CommitId([4; 32]));
    let mut relay = snapshot.clone();
    relay.ephemeral = Some(EphClass::Relay);
    relay.expires = None;
    for h in [session, snapshot, undo] {
        h.validate().unwrap();
        let mut x = h.clone();
        x.aspects[0].retention.by = PurgeBy::AuthorOrAdmin;
        x.aspects[0].keys = vec![0, 1];
        x.keys.truncate(2);
        assert!(invalid(&x).to_string().contains("writer"), "{}", invalid(&x));
    }
    relay.validate().unwrap();
    let mut x = relay.clone();
    x.undoes = Some(CommitId([4; 32]));
    assert!(invalid(&x).to_string().contains("relay-only"), "{}", invalid(&x));
    let mut x = relay.clone();
    x.kind = Kind::Content;
    (x.aspects[0].lo, x.aspects[0].hi) = (1, 2);
    assert!(invalid(&x).to_string().contains("relay-only"), "{}", invalid(&x));
}

// spec/commits.md §3 (session form), spec/wire.md §4: session form `[1, nonce]` round-trips; the
// form rule is one for durable and ephemeral commits: an ephemeral content commit may be in
// commit form (a shared key actor's) and a snapshot in session form is bad input either way.
#[test]
fn session_form_spec_commits_3() {
    let mut h = sample_header();
    h.undoes = None;
    h.form = Form::Session([6; 16]);
    assert_eq!(Header::decode(&h.encode()).unwrap(), h);
    assert_ne!(h.id(), Header { form: Form::Session([7; 16]), ..h.clone() }.id());
    // a durable content commit in session form, and an ephemeral one
    h.validate().unwrap();
    h.ephemeral = Some(EphClass::Plain);
    assert!(invalid(&h).to_string().contains("retention"), "the durable commit's retention");
    h.aspects[0].retention = crate::retention::EPHEMERAL_RETENTION;
    h.keys.push(dkey(3, 3));
    h.aspects[0].keys = vec![0, 1, 2];
    h.validate().unwrap();
    let mut x = h.clone();
    x.form = Form::Commit;
    x.validate().unwrap();
    let mut x = h.clone();
    x.kind = Kind::ContentSnapshot;
    (x.aspects[0].lo, x.aspects[0].hi) = (0, 0);
    assert!(x.validate().is_err(), "a session-form snapshot");
    x.ephemeral = None;
    assert!(x.validate().is_err(), "a session-form snapshot");
    // the session's dots are its own: `(Session(signer, nonce), ctr)`
    let own = h.form.own_source(h.signer, h.id());
    assert_eq!(own.as_session(), Some(osis_crdt::Session { node: h.signer, nonce: [6; 16] }));
    // another form value is malformed
    let mut v = crate::tests::header_value(&h);
    if let Value::List(items) = &mut v {
        items[5] = Value::List(vec![Value::Int(2), Value::bytes(&[6; 16])]);
    }
    assert!(Header::decode(&osis_base::encode(&v)).is_err());
}

// spec/wire.md §4: the sort keys order as canonical bytes do: aspects by `[tid, ak]` (the text
// head's width steps at 24, 256 and 65536 bytes), delete keys by `[level, key]` (any u8 level)
#[test]
fn sort_orders_match_canonical_bytes() {
    use osis_base::cbor::{put_array, put_bytes, put_text, put_uint};
    let mut aks = Vec::new();
    for len in [0, 1, 2, 22, 23, 24, 25, 254, 255, 256, 257, 65535, 65536, 65537] {
        for fill in *b"az" {
            let mut s = vec![fill; len];
            if let Some(last) = s.last_mut() {
                *last = b'm';
            }
            aks.push(String::from_utf8(s).unwrap());
        }
    }
    let items: Vec<(Tid, String, Vec<u8>)> = [t(0), t(1), t(0xff)]
        .into_iter()
        .flat_map(|tid| aks.iter().map(move |ak| (tid, ak.clone())))
        .map(|(tid, ak)| {
            let mut b = Vec::new();
            put_array(&mut b, 2);
            put_bytes(&mut b, tid.as_bytes());
            put_text(&mut b, &ak);
            (tid, ak, b)
        })
        .collect();
    for (ta, aa, ba) in &items {
        for (tb, ab, bb) in &items {
            assert_eq!(aspect_order(ta, aa).cmp(&aspect_order(tb, ab)), ba.cmp(bb), "{} {}", aa.len(), ab.len());
        }
    }
    let keys: Vec<(DeleteKey, Vec<u8>)> = (0..=255u8)
        .flat_map(|level| [[0u8; 32], [1; 32], [0xff; 32]].map(|key| DeleteKey { level, key }))
        .map(|k| {
            let mut b = Vec::new();
            put_array(&mut b, 2);
            put_uint(&mut b, u64::from(k.level));
            put_bytes(&mut b, &k.key);
            (k, b)
        })
        .collect();
    for (ka, ba) in &keys {
        for (kb, bb) in &keys {
            assert_eq!(ka.cmp(kb), ba.cmp(bb));
        }
    }
}
