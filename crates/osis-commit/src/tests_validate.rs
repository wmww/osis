//! Header validation and retention (spec/wire.md §4, spec/commits.md §2, §5, §6).

use crate::tests::{sample_header, t, ts};
use crate::*;
use osis_core::{Ak, CommitId, Value};
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
    x.tokens.swap(0, 1);
    assert!(matches!(invalid(&x), Error::Malformed(_)));
    let mut x = h.clone();
    x.aspects[0].schema = Some(1);
    assert!(matches!(invalid(&x), Error::Malformed(_)));
    let mut x = h.clone();
    x.tokens.push(Token { level: 3, hash: [3; 16] });
    assert!(matches!(invalid(&x), Error::Malformed(_)), "unused token");
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

// spec/commits.md §2: kinds and aspect classes; snapshots and imports have empty ranges;
// one delta per aspect except membership and roster snapshots.
#[test]
fn validate_kinds() {
    let h = sample_header();
    let mut x = h.clone();
    x.kind = Kind::Membership;
    assert!(matches!(invalid(&x), Error::Invalid(_)), "content aspect in a membership commit");
    let mut x = h.clone();
    x.aspects[0].hashes.push([10; 32]);
    assert!(matches!(invalid(&x), Error::Invalid(_)));
    let mut x = h.clone();
    x.kind = Kind::ContentSnapshot;
    assert!(invalid(&x).to_string().contains("counter range"));
    x.aspects[0].lo = 0;
    x.aspects[0].hi = 0;
    assert!(invalid(&x).to_string().contains("writer"));
    x.aspects[0].retention.by = PurgeBy::Writer;
    x.tokens.push(Token { level: 3, hash: [3; 16] });
    x.aspects[0].tokens = vec![0, 1, 2];
    x.validate().unwrap();
    let mut x = h.clone();
    x.kind = Kind::Import;
    x.aspects[0].lo = 0;
    x.aspects[0].hi = 0;
    assert!(invalid(&x).to_string().contains("token levels"), "imports carry no level-2 token");
    x.tokens.remove(1);
    x.aspects[0].tokens = vec![0];
    assert!(invalid(&x).to_string().contains("origins"));
    x.origins.push(Origin { commit: CommitId([1; 32]), author: t(1), actor: t(2), ts: ts(5) });
    x.validate().unwrap();
}

pub(crate) fn membership_header(ak: &str) -> Header {
    let mut h = sample_header();
    h.kind = Kind::Membership;
    h.form = crate::header::Form::Commit;
    h.schemas.clear();
    let a = &mut h.aspects[0];
    a.ak = Ak::new(ak).unwrap();
    a.retention = retention::MEMBERSHIP_RETENTION;
    a.expires = None;
    a.schema = None;
    a.tokens = vec![0];
    a.hashes = vec![[1; 32], [2; 32]];
    h.tokens.truncate(1);
    h
}

// spec/commits.md §2, §5: membership commits carry no expires, keep fixed retention, may carry
// several sorted delta hashes per aspect, may touch /secrets and /keys of several things; a
// frontier only on membership commits; roster snapshots only /members and /tenures of one thing.
// spec/commits.md §2 (membership no expires)
#[test]
fn validate_membership() {
    let h = membership_header("/members");
    h.validate().unwrap();
    // spec/commits.md §3, §4: a node-form membership commit is bad input
    for k in [Kind::Membership, Kind::RosterSnapshot] {
        let mut x = h.clone();
        x.kind = k;
        x.form = crate::header::Form::Node;
        assert!(invalid(&x).to_string().contains("node-form membership"));
    }
    let mut x = h.clone();
    x.aspects[0].expires = Some(9_999_999_999);
    assert!(invalid(&x).to_string().contains("expires"));
    let mut x = h.clone();
    x.aspects[0].retention.by = PurgeBy::Writer;
    assert!(matches!(invalid(&x), Error::Malformed(_) | Error::Invalid(_)));
    let mut x = h.clone();
    x.aspects[0].hashes.reverse();
    assert!(matches!(invalid(&x), Error::Malformed(_)));
    let mut x = h.clone();
    x.frontier = Some(Value::Map(Default::default()));
    x.validate().unwrap();
    let mut c = sample_header();
    c.frontier = x.frontier.clone();
    assert!(invalid(&c).to_string().contains("frontier"));
    let mut x = h.clone();
    for (n, ak) in [(4, "/secrets"), (5, "/keys"), (6, "/secrets")] {
        let mut a = x.aspects[0].clone();
        a.tid = t(n);
        a.ak = Ak::new(ak).unwrap();
        x.aspects.push(a);
    }
    x.validate().unwrap();
    let mut x = h.clone();
    x.kind = Kind::RosterSnapshot;
    x.validate().unwrap();
    let mut a = x.aspects[0].clone();
    a.ak = Ak::new("/secrets").unwrap();
    x.aspects.push(a);
    assert!(invalid(&x).to_string().contains("roster"));
    let mut x = h.clone();
    x.kind = Kind::MembershipSnapshot;
    x.aspects[0].lo = 0;
    x.aspects[0].hi = 0;
    x.aspects[0].hashes.truncate(1);
    assert!(invalid(&x).to_string().contains("/members"));
}

// spec/commits.md §5, §6: expires after ts; no expires with a purge request; purge never names
// membership deltas; relative keep at most only under writer.
// spec/commits.md §5 (purge not membership), §5 (purge no expires)
#[test]
fn validate_expiry_purge_retention() {
    let h = sample_header();
    let mut x = h.clone();
    x.aspects[0].expires = Some(h.ts.wall_ms().0);
    assert!(invalid(&x).to_string().contains("expires"));
    let mut x = h.clone();
    x.purge.push(PurgeItem::Aspect { tid: t(3), ak: Ak::new("/app/title").unwrap() });
    assert!(invalid(&x).to_string().contains("purge request"));
    x.aspects[0].expires = None;
    x.validate().unwrap();
    x.purge.push(PurgeItem::Aspect { tid: t(3), ak: Ak::new("/members").unwrap() });
    x.purge.sort_by_key(|p| osis_core::encode(&crate::header::purge_value(p)));
    assert!(invalid(&x).to_string().contains("membership"));
    let mut x = h.clone();
    x.aspects[0].retention.at_most.rel = Some(0);
    assert!(invalid(&x).to_string().contains("writer"));
}

// spec/commits.md §5: fixed tables, write defaults (untyped: author, no bounds, no expiry),
// snapshot retention from schema defaults, keep bounds, the purge floor.
#[test]
fn retention_rules() {
    use osis_core::format::MEMBERSHIP_KEEP_MS;
    use osis_schema::AspectDefaults;
    use retention::*;
    assert_eq!(fixed_retention("/secrets"), Some(MEMBERSHIP_RETENTION));
    assert_eq!(fixed_retention("/created").unwrap().by, PurgeBy::Nobody);
    assert_eq!(fixed_retention("/app/x"), None);
    assert_eq!(write_retention("/app/x", None, None).unwrap(), Retention::default());
    assert_eq!(Retention::default().by, PurgeBy::Author);
    assert_eq!(write_expires("/app/x", ts(10), None, None).unwrap(), None);
    let d = AspectDefaults {
        retention: Retention { by: PurgeBy::Author, at_least: Bound { abs: Some(7), rel: None }, at_most: Bound::default() },
        expires: Some(100),
    };
    assert_eq!(write_retention("/app/x", Some(&d), None).unwrap(), d.retention);
    assert_eq!(write_expires("/app/x", ts(10), Some(&d), None).unwrap(), Some(110));
    assert_eq!(write_expires("/app/x", ts(10), Some(&d), Some(50)).unwrap(), Some(50));
    assert_eq!(write_expires("/members", ts(10), Some(&d), Some(50)).unwrap(), None);
    assert!(write_retention("/members", None, Some(Retention::default())).is_err());
    let bad = Retention { by: PurgeBy::Author, at_least: Bound::default(), at_most: Bound { abs: None, rel: Some(1) } };
    assert!(write_retention("/app/x", None, Some(bad)).is_err());
    let s = snapshot_retention("/app/x", Some(&d));
    assert_eq!((s.by, s.at_least), (PurgeBy::Writer, d.retention.at_least));
    assert_eq!(snapshot_retention("/keys", Some(&d)), MEMBERSHIP_RETENTION);
    let r = Retention { by: PurgeBy::Writer, at_least: Bound { abs: Some(100), rel: Some(50) }, at_most: Bound { abs: Some(400), rel: Some(10) } };
    assert_eq!(keep_at_least(&r, None), 100);
    assert_eq!(keep_at_least(&r, Some(80)), 130);
    assert_eq!(keep_at_most(&r, None), Some(400));
    assert_eq!(keep_at_most(&r, Some(20)), Some(30));
    let h = sample_header();
    assert_eq!(body_keep(&h, &r, Some(20), Some(80), false), Keep { at_least: 30, at_most: Some(30) });
    let mut p = h.clone();
    p.purge.push(PurgeItem::Aspect { tid: t(3), ak: Ak::new("/app/title").unwrap() });
    let floor = h.ts.wall_ms().0 + MEMBERSHIP_KEEP_MS;
    assert_eq!(purge_keep_until(&p), Some(floor));
    assert_eq!(body_keep(&p, &r, Some(20), Some(80), false), Keep { at_least: floor, at_most: Some(floor) });
}

// spec/commits.md §5 (keep at most): under at most D after replaced, a body's bound is its
// first death plus D, plus `AT_MOST_GRACE` while it has a live write, whatever its kind.
#[test]
fn at_most_grace_spec_commits_5() {
    use crate::retention::body_keep;
    use osis_core::format::AT_MOST_GRACE_MS as G;
    let r = Retention { by: PurgeBy::Writer, at_least: Bound::default(), at_most: Bound { abs: None, rel: Some(0) } };
    let h = sample_header();
    let mut s = h.clone();
    s.kind = Kind::ContentSnapshot;
    for x in [&h, &s] {
        assert_eq!(body_keep(x, &r, Some(20), Some(80), false).at_most, Some(20));
        assert_eq!(body_keep(x, &r, Some(20), Some(80), true).at_most, Some(20 + G));
        assert_eq!(body_keep(x, &r, None, None, true).at_most, None);
        let d = Retention { at_most: Bound { abs: None, rel: Some(5) }, ..r };
        assert_eq!(body_keep(x, &d, Some(20), Some(80), false).at_most, Some(25));
        assert_eq!(body_keep(x, &d, Some(20), Some(80), true).at_most, Some(25 + G));
        // an absolute bound is not extended
        let t = Retention { at_most: Bound { abs: Some(30), rel: None }, ..r };
        assert_eq!(body_keep(x, &t, Some(20), Some(80), true).at_most, Some(30));
    }
}
