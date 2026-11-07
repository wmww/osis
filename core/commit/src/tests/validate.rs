//! Header validation and retention (spec/wire.md §4, spec/commits.md §2, §5, §6).

use crate::tests::{dkey, sample_header, t, ts};
use crate::*;
use osis_base::{Ak, Value};
use osis_schema::{Bound, PurgeBy, Retention};

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

pub(crate) fn role_header(ak: &str) -> Header {
    let mut h = sample_header();
    h.kind = Kind::Role;
    h.form = crate::header::Form::Commit;
    h.actor = h.author;
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
    // spec/wire.md §4: a role commit's actor is its author
    let mut x = h.clone();
    x.actor = t(9);
    assert!(invalid(&x).to_string().contains("acting for another actor"));
    let mut x = h.clone();
    x.expires = Some(9_999_999_999);
    assert!(invalid(&x).to_string().contains("expires"));
    let mut x = h.clone();
    x.aspects[0].retention.by = PurgeBy::Writer;
    assert!(matches!(invalid(&x), Error::Malformed(_) | Error::Invalid(_)));
    let mut x = h.clone();
    x.frontier = Some(Value::Map(Default::default()));
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
}

// spec/commits.md §5 (nobody shares a commit only with nobody), §6 (one expiry per commit): a
// `nobody` delta beside another class is bad input, a record or `required.0^` beside either is
// not; an expiring commit carries no fixed-retention aspect.
#[test]
fn validate_nobody_and_commit_expiry() {
    let sort = |x: &mut Header| x.aspects.sort_by_key(|a| crate::header::aspect_key(&a.tid, &a.ak));
    let mut h = sample_header();
    h.expires = None;
    let mut b = h.aspects[0].clone();
    b.ak = Ak::new("app:z.0").unwrap();
    b.retention = Retention { by: PurgeBy::Nobody, ..b.retention };
    b.keys.clear();
    let mut x = h.clone();
    x.aspects.push(b.clone());
    sort(&mut x);
    assert!(invalid(&x).to_string().contains("nobody"), "{}", invalid(&x));
    let mut rec = b.clone();
    rec.ak = Ak::new("created.0").unwrap();
    rec.retention = retention::CREATED_RETENTION;
    rec.tid = t(2);
    let mut x = h.clone();
    x.aspects.insert(0, rec.clone());
    sort(&mut x);
    x.validate().unwrap();
    let mut x = h.clone();
    x.aspects[0] = b.clone();
    x.aspects.insert(0, rec.clone());
    sort(&mut x);
    x.keys.clear();
    x.validate().unwrap();
    x.expires = Some(h.ts.wall_ms().0 + 1);
    assert!(invalid(&x).to_string().contains("fixed-retention"));
}

// spec/commits.md §5, §6: expires after ts; no expires with a purge request; purge never names
// role-class deltas; a relative keep at most only 0 after replaced, only under writer.
// spec/commits.md §5 (purge not role-class), §5 (purge no expires)
#[test]
fn validate_expiry_purge_retention() {
    let h = sample_header();
    let mut x = h.clone();
    x.expires = Some(h.ts.wall_ms().0);
    assert!(invalid(&x).to_string().contains("expires"));
    let mut x = h.clone();
    x.purge.push(PurgeItem::Aspect { tid: t(3), ak: Ak::new("app:title.0").unwrap() });
    assert!(invalid(&x).to_string().contains("purge request"));
    x.expires = None;
    x.validate().unwrap();
    x.purge.push(PurgeItem::Aspect { tid: t(3), ak: Ak::new("roles.0").unwrap() });
    x.purge.sort_by_key(|p| osis_base::encode(&crate::header::purge_value(p)));
    assert!(invalid(&x).to_string().contains("role-class"));
    let mut x = h.clone();
    x.aspects[0].retention.at_most.rel = Some(0);
    assert!(invalid(&x).to_string().contains("writer"));
    // checked before the delete levels the class calls for
    x.aspects[0].retention.by = PurgeBy::Writer;
    assert!(invalid(&x).to_string().contains("delete levels"));
    x.aspects[0].retention.at_most.rel = Some(1);
    assert!(invalid(&x).to_string().contains("other than 0"));
}

// spec/commits.md §5: fixed tables, write defaults (untyped: author, no bounds, no expiry),
// snapshot retention from schema defaults, keep bounds, the purge floor.
#[test]
fn retention_rules() {
    use osis_base::format::ROLE_KEEP_MS;
    use osis_schema::AspectDefaults;
    use retention::*;
    assert_eq!(fixed_retention("secrets.0"), Some(ROLE_RETENTION));
    assert_eq!(fixed_retention("created.0").unwrap().by, PurgeBy::Nobody);
    assert_eq!(fixed_retention("app:x.0"), None);
    assert_eq!(write_retention("app:x.0", None, None).unwrap(), Retention::default());
    assert_eq!(Retention::default().by, PurgeBy::AuthorOrAdmin);
    assert_eq!(write_expires("app:x.0", ts(10), None, None).unwrap(), None);
    let d = AspectDefaults {
        retention: Retention { by: PurgeBy::AuthorOrAdmin, at_least: Bound { abs: Some(7), rel: None }, at_most: Bound::default() },
        expires: Some(100),
    };
    assert_eq!(write_retention("app:x.0", Some(&d), None).unwrap(), d.retention);
    assert_eq!(write_expires("app:x.0", ts(10), Some(&d), None).unwrap(), Some(110));
    assert_eq!(write_expires("app:x.0", ts(10), Some(&d), Some(50)).unwrap(), Some(50));
    assert_eq!(write_expires("roles.0", ts(10), Some(&d), Some(50)).unwrap(), None);
    assert!(write_retention("roles.0", None, Some(Retention::default())).is_err());
    let bad = Retention { by: PurgeBy::AuthorOrAdmin, at_least: Bound::default(), at_most: Bound { abs: None, rel: Some(0) } };
    assert!(write_retention("app:x.0", None, Some(bad)).is_err());
    let bad = Retention { by: PurgeBy::Writer, at_least: Bound::default(), at_most: Bound { abs: None, rel: Some(1) } };
    assert!(write_retention("app:x.0", None, Some(bad)).is_err());
    assert!(write_retention("app:x.0", None, Some(Retention { at_most: Bound { abs: None, rel: Some(0) }, ..bad })).is_ok());
    // the own deltas' longest relative keep at least (no absolute one) and strictest keep at
    // most (a passed absolute bound counts as 0 after replaced)
    let own = |least: Bound, abs: Option<u64>, rel: Option<u64>| Retention { by: PurgeBy::AuthorOrAdmin, at_least: least, at_most: Bound { abs, rel } };
    let none = Bound::default();
    let s = snapshot_retention("app:x.0", [own(Bound { abs: Some(900), rel: Some(5) }, Some(500), None), own(none, Some(300), None), own(Bound { abs: None, rel: Some(7) }, None, None)], 100);
    assert_eq!(s, Retention { by: PurgeBy::Writer, at_least: Bound { abs: None, rel: Some(7) }, at_most: Bound { abs: Some(300), rel: None } });
    let s = snapshot_retention("app:x.0", [own(none, Some(500), None), own(none, None, Some(0))], 100);
    assert_eq!(s.at_most, Bound { abs: Some(500), rel: Some(0) });
    assert_eq!(snapshot_retention("app:x.0", [], 100), Retention { by: PurgeBy::Writer, ..Default::default() });
    let s = snapshot_retention("app:x.0", [own(none, Some(100), None), own(none, Some(400), None)], 100);
    assert_eq!(s.at_most, Bound { abs: Some(400), rel: Some(0) });
    assert_eq!(snapshot_retention("keys.0", [own(none, None, Some(0))], 0), ROLE_RETENTION);
    let r = Retention { by: PurgeBy::Writer, at_least: Bound { abs: Some(100), rel: Some(50) }, at_most: Bound { abs: Some(400), rel: Some(0) } };
    assert_eq!(keep_at_least(&r, None), 100);
    assert_eq!(keep_at_least(&r, Some(80)), 130);
    assert_eq!(keep_at_most(&r, None), Some(400));
    assert_eq!(keep_at_most(&r, Some(20)), Some(20));
    let h = sample_header();
    assert_eq!(body_keep(&h, &r, Some(20), Some(80)), Keep { at_least: 20, at_most: Some(20) });
    let mut p = h.clone();
    p.purge.push(PurgeItem::Aspect { tid: t(3), ak: Ak::new("app:title.0").unwrap() });
    let floor = h.ts.wall_ms().0 + ROLE_KEEP_MS;
    assert_eq!(purge_keep_until(&p), Some(floor));
    assert_eq!(body_keep(&p, &r, Some(20), Some(80)), Keep { at_least: floor, at_most: Some(floor) });
}

// spec/commits.md §5 (keep at most): under 0 after replaced a body's bound is its first death,
// whatever its kind; an absolute bound stands alone, the earlier of the two counts.
#[test]
fn at_most_zero_is_the_first_death_spec_commits_5() {
    use crate::retention::body_keep;
    let r = Retention { by: PurgeBy::Writer, at_least: Bound::default(), at_most: Bound { abs: None, rel: Some(0) } };
    let h = sample_header();
    let mut s = h.clone();
    s.kind = Kind::ContentSnapshot;
    for x in [&h, &s] {
        assert_eq!(body_keep(x, &r, Some(20), Some(80)).at_most, Some(20));
        assert_eq!(body_keep(x, &r, None, None).at_most, None);
        let t = Retention { at_most: Bound { abs: Some(30), rel: None }, ..r };
        assert_eq!(body_keep(x, &t, Some(20), Some(80)).at_most, Some(30));
        let both = Retention { at_most: Bound { abs: Some(30), rel: Some(0) }, ..r };
        assert_eq!(body_keep(x, &both, Some(20), Some(80)).at_most, Some(20));
        assert_eq!(body_keep(x, &both, Some(40), Some(80)).at_most, Some(30));
    }
}

// spec/commits.md §2, spec/wire.md §4: an ephemeral commit's retention is `writer` with no bounds,
// in session form and as a commit-form snapshot alike.
#[test]
fn ephemeral_retention_writer_no_bounds_spec_commits_2() {
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
    for h in [session, snapshot] {
        h.validate().unwrap();
        for f in [|r: &mut Retention| r.at_least.rel = Some(5), |r: &mut Retention| r.at_least.abs = Some(5), |r: &mut Retention| r.at_most.rel = Some(0), |r: &mut Retention| r.at_most.abs = Some(5)] {
            let mut x = h.clone();
            f(&mut x.aspects[0].retention);
            assert!(invalid(&x).to_string().contains("retention"), "{:?}", x.aspects[0].retention);
        }
    }
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
    // the session's dots are its own: `(Session(author, nonce), ctr)`
    let own = h.form.own_source(h.author, h.id());
    assert_eq!(own.as_session(), Some(osis_crdt::Session { node: h.author, nonce: [6; 16] }));
    // another form value is malformed
    let mut v = h.to_value();
    if let Value::List(items) = &mut v {
        items[5] = Value::List(vec![Value::Int(2), Value::bytes(&[6; 16])]);
    }
    assert!(Header::from_value(&v).is_err());
}
