//! The client port's values (spec/wire.md §11.2 (client port), notes/client-port.md §2, `port::codec`): every type the method table
//! carries reads from its layout and writes back the same value, with optional positions present
//! and absent; a value of the wrong shape is refused. The literals are the layout.

use osis::internals::Port;
use osis::internals::node::{Diagnostic, DiagnosticKind};
use osis::{Ak, Backlink, BacklinkPage, BacklinkQuery, Body, Commit, CommitFrom, CommitKind, CommitPage, CommitQuery, DerivedFrom, GrantOpts, Grants, GroupsOf, Holder, HolderKind, LinkInfo, Member, Origin, Path, PurgeBy, Role, Scope, SetRoleOpts, Stamp, Status, Step, SyncScope, SyncState, ThingStamp, Tid, Time, Value};
use osis_crdt::PathSeg;

fn u(n: u64) -> Value {
    Value::uint(n)
}

fn l(v: Vec<Value>) -> Value {
    Value::List(v)
}

fn t(n: u8) -> Value {
    Value::Tid(Tid::from_bytes([n; 15]))
}

fn id(n: u8) -> Value {
    Value::bytes(&[n; 32])
}

fn ak() -> Value {
    Value::Str("note.0".into())
}

/// A valid ts: wall 7, logical 3.
fn ts() -> Value {
    u((7 << 16) | 3)
}

fn stamp() -> Value {
    l(vec![id(1), t(2), ts(), u(9)])
}

/// `v` reads as a `T` that writes back as `v`.
fn same<T: Port>(v: Value) -> T {
    let x = T::from_port(v.clone()).unwrap_or_else(|e| panic!("{v:?}: {e}"));
    assert_eq!(x.to_port(), v);
    x
}

fn refused<T: Port>(v: Value) {
    assert!(T::from_port(v.clone()).is_err(), "{v:?} read");
}

/// A list with one more position than its layout.
fn longer(v: &Value) -> Value {
    let Value::List(mut x) = v.clone() else { panic!("not a list") };
    x.push(u(0));
    l(x)
}

/// A unit-only enum as a bare index: each of `n` cases in order, then the first past them refused.
fn index<T: Port + PartialEq + std::fmt::Debug>(cases: &[T]) {
    for (i, c) in cases.iter().enumerate() {
        assert_eq!(&same::<T>(u(i as u64)), c);
    }
    refused::<T>(u(cases.len() as u64));
    refused::<T>(l(vec![]));
}

#[test]
fn index_enums_read_by_position() {
    index(&[Role::Read, Role::Write, Role::Admin, Role::Sync]);
    index(&[HolderKind::Actor, HolderKind::Link, HolderKind::Key]);
    index(&[CommitKind::Content, CommitKind::Revert, CommitKind::Role, CommitKind::Snapshot]);
    index(&[SyncState::Synced, SyncState::Syncing, SyncState::NotConnected, SyncState::Refused, SyncState::Stranded]);
    index(&[DerivedFrom::ValidityChanged, DerivedFrom::Expired, DerivedFrom::Purged, DerivedFrom::Arrived, DerivedFrom::LostAccess, DerivedFrom::Recovered]);
    use DiagnosticKind::*;
    index(&[
        BadInput, CollidingRecord, Parked, Pending, OverlappingCounters, Removed, Callback, NotSynced, Stranded, Uncommitted, EphemeralRefused, Mismatch, Storage, Repair, OwnWriteInvalid,
        Unreadable, SyncStopped, DisputesUnexamined, OwnWriteFailed, ClockSkew, InputCapped,
    ]);
}

#[test]
fn tagged_enums_read_as_case_and_payload() {
    let p = same::<Path>(l(vec![l(vec![u(0), u(1)]), l(vec![u(1), u(2)]), l(vec![u(2), Value::Str("k".into())]), l(vec![u(3), u(4)]), l(vec![u(4), u(5)])]));
    assert_eq!(p.0, vec![Step::Field(1), Step::Case(2), Step::Key(Value::Str("k".into())), Step::Index(4), Step::Elem(u(5))]);
    same::<Path>(l(vec![]));
    refused::<Path>(l(vec![l(vec![u(5), u(0)])]));
    refused::<Path>(l(vec![l(vec![u(0), u(1), u(2)])]));

    let s = same::<Vec<PathSeg>>(l(vec![l(vec![u(0), u(1)]), l(vec![u(1), u(2)]), l(vec![u(2), u(3)]), l(vec![u(3), u(4)])]));
    assert_eq!(s, vec![PathSeg::Field(1), PathSeg::Case(2), PathSeg::Key(u(3)), PathSeg::Index(4)]);
    refused::<PathSeg>(l(vec![u(4), u(0)]));

    assert_eq!(same::<Origin>(l(vec![u(0)])), Origin::Initial);
    assert!(matches!(same::<Origin>(l(vec![u(1), stamp()])), Origin::Local(_)));
    assert!(matches!(same::<Origin>(l(vec![u(2), stamp()])), Origin::Remote(_)));
    assert_eq!(same::<Origin>(l(vec![u(3), u(4)])), Origin::Derived(DerivedFrom::LostAccess));
    refused::<Origin>(l(vec![u(0), u(0)]));
    refused::<Origin>(l(vec![u(4)]));

    let scopes = [l(vec![u(0), t(1)]), l(vec![u(1), l(vec![l(vec![t(1), ak()])])]), l(vec![u(2), t(1)])];
    for s in &scopes {
        same::<Scope>(s.clone());
        refused::<Scope>(longer(s));
    }
    assert!(matches!(same::<Scope>(scopes[0].clone()), Scope::Thing(_)));
    assert!(matches!(same::<Scope>(scopes[2].clone()), Scope::Group(_)));

    let addresses = [l(vec![u(0), l(vec![u(2), t(1)])]), l(vec![u(1), t(1), ak()]), l(vec![u(2), t(1), ak(), id(3)])];
    for a in &addresses {
        assert_eq!(osis::internals::port_commit_address(a.clone()).unwrap(), *a);
        assert!(osis::internals::port_commit_address(longer(a)).is_err());
    }
    assert!(osis::internals::port_commit_address(l(vec![u(3)])).is_err());

    let bodies = [l(vec![u(0), l(vec![])]), l(vec![u(0), l(vec![u(8)])]), l(vec![u(1), u(5)]), l(vec![u(2), id(4), l(vec![])]), l(vec![u(2), id(4), l(vec![t(5)])]), l(vec![u(3)])];
    for b in &bodies {
        same::<Body<Value>>(b.clone());
        refused::<Body<Value>>(longer(b));
    }
    assert_eq!(same::<Body<Value>>(l(vec![u(1), u(5)])), Body::TooLarge { limit: 5 });

    assert_eq!(same::<Member>(l(vec![u(0), t(1)])), Member::Item(Tid::from_bytes([1; 15])));
    assert_eq!(same::<Member>(l(vec![u(1), t(1)])), Member::Subgroup(Tid::from_bytes([1; 15])));
    refused::<Member>(l(vec![u(2), t(1)]));

    assert_eq!(same::<CommitFrom>(l(vec![u(0)])), CommitFrom::Newest);
    assert_eq!(same::<CommitFrom>(l(vec![u(1)])), CommitFrom::Oldest);
    assert!(matches!(same::<CommitFrom>(l(vec![u(2), ts(), id(1)])), CommitFrom::Before(_)));
    assert!(matches!(same::<CommitFrom>(l(vec![u(3), ts(), id(1)])), CommitFrom::After(_)));
    refused::<CommitFrom>(l(vec![u(2), ts()]));

    assert_eq!(same::<SyncScope>(l(vec![])), SyncScope::All);
    assert_eq!(same::<SyncScope>(l(vec![t(1)])), SyncScope::Thing(Tid::from_bytes([1; 15])));
    assert_eq!(same::<SyncScope>(l(vec![Value::Bool(true)])), SyncScope::Deliveries);
    refused::<SyncScope>(l(vec![t(1), t(2)]));
}

#[test]
fn structs_read_as_their_positions() {
    let s = same::<Stamp>(stamp());
    assert_eq!((s.received, s.written), (Time(9), Time(7)));
    let ts2 = same::<ThingStamp>(stamp());
    assert_eq!((ts2.received, ts2.written), (Time(9), Time(7)));
    refused::<Stamp>(longer(&stamp()));
    refused::<Stamp>(l(vec![id(1), t(2), Value::Str("7".into()), u(9)]));

    let g = same::<GroupsOf>(l(vec![l(vec![t(1)]), l(vec![]), l(vec![t(1), t(2)])]));
    assert_eq!((g.item_of.len(), g.subgroup_of.len(), g.within.len()), (1, 0, 2));

    for d in [l(vec![u(3), l(vec![t(1)]), l(vec![id(2)]), l(vec![t(3)]), Value::Str("d".into())]), l(vec![u(0), l(vec![]), l(vec![]), l(vec![]), Value::Str(String::new())])] {
        same::<Diagnostic>(d.clone());
        refused::<Diagnostic>(longer(&d));
    }

    let full = l(vec![l(vec![u(2), ts(), id(1)]), l(vec![u(4)]), l(vec![t(1)]), l(vec![u(1), u(3)]), l(vec![id(2)]), l(vec![id(3)]), l(vec![Value::Bool(false)])]);
    let q = same::<CommitQuery>(full.clone());
    assert_eq!((q.limit, q.kinds, q.in_effect), (Some(4), vec![CommitKind::Revert, CommitKind::Snapshot], Some(false)));
    assert_eq!((q.reverts.map(|c| c.to_port()), q.reverted_by.map(|c| c.to_port())), (Some(id(2)), Some(id(3))));
    refused::<CommitQuery>(longer(&full));
    let empty = l(vec![l(vec![u(0)]), l(vec![]), l(vec![]), l(vec![]), l(vec![]), l(vec![]), l(vec![])]);
    assert_eq!(same::<CommitQuery>(empty), CommitQuery::default());

    let part = |edited: Value| l(vec![t(1), ak(), Value::Bool(true), l(vec![u(0), l(vec![u(8)])]), edited]);
    let commit = l(vec![stamp(), u(1), l(vec![id(5)]), l(vec![id(6), id(7)]), Value::Bool(true), l(vec![part(l(vec![])), part(l(vec![l(vec![ts(), id(8)])]))])]);
    let c = same::<Commit>(commit.clone());
    assert_eq!((c.kind, c.parts().count()), (CommitKind::Revert, 2));
    let bare = l(vec![stamp(), u(0), l(vec![]), l(vec![]), Value::Bool(false), l(vec![])]);
    same::<Commit>(bare.clone());
    refused::<Commit>(longer(&commit));
    refused::<Commit>(l(vec![stamp(), u(0), l(vec![]), l(vec![]), Value::Bool(false), l(vec![longer(&part(l(vec![])))])]));
    let page = same::<CommitPage>(l(vec![l(vec![commit, bare]), Value::Bool(true), Value::Bool(false)]));
    assert_eq!((page.commits.len(), page.more, page.complete), (2, true, false));

    let w = |n: u64| l(vec![u(n)]);
    let o = same::<GrantOpts>(l(vec![w(5), w(1)]));
    assert_eq!((o.until, o.may_grant), (Some(Time(5)), Some(Role::Write)));
    assert_eq!(same::<GrantOpts>(l(vec![l(vec![]), l(vec![])])), GrantOpts::default());
    assert_eq!(same::<SetRoleOpts>(l(vec![l(vec![Value::Bool(true)])])).retain_copy, Some(true));
    assert_eq!(same::<SetRoleOpts>(l(vec![l(vec![])])).retain_copy, None);
    refused::<SetRoleOpts>(l(vec![]));

    let h = same::<Vec<Holder>>(l(vec![l(vec![t(1), u(1), u(2), w(5), l(vec![t(2)])]), l(vec![t(1), u(0), u(0), l(vec![]), l(vec![])])]));
    assert_eq!((h[0].kind, h[0].role, h[0].until, h[1].until), (HolderKind::Link, Role::Admin, Some(Time(5)), None));
    let links = same::<Vec<LinkInfo>>(l(vec![l(vec![t(1), t(2), u(0), w(5), Value::Bool(true)]), l(vec![t(1), t(2), u(1), l(vec![]), Value::Bool(false)])]));
    assert_eq!((links[0].target, links[0].single_use, links[1].until), (Tid::from_bytes([2; 15]), true, None));

    let b = l(vec![t(1), ak()]);
    assert_eq!(same::<Backlink>(b.clone()).ak, Ak::new("note.0").unwrap());
    assert_eq!(same::<BacklinkQuery>(l(vec![l(vec![b.clone()]), l(vec![u(3)])])).limit, Some(3));
    assert_eq!(same::<BacklinkQuery>(l(vec![l(vec![]), l(vec![])])), BacklinkQuery::default());
    assert!(same::<BacklinkPage>(l(vec![l(vec![b.clone(), b]), Value::Bool(true)])).more);
}

#[test]
fn maps_and_settings_read_as_their_rows() {
    let rows = l(vec![l(vec![t(1), u(2), l(vec![u(5)]), l(vec![u(0)]), Value::Bool(true)]), l(vec![t(2), u(0), l(vec![]), l(vec![]), Value::Bool(false)])]);
    let g = same::<Grants>(rows);
    assert_eq!(g[&Tid::from_bytes([1; 15])].may_grant, Some(Role::Read));
    refused::<Grants>(l(vec![l(vec![t(1), u(2), l(vec![]), l(vec![])])]));

    let addr = osis::Address::new(&"mem://elsewhere".parse().unwrap(), [7; 32]).to_string();
    let status = l(vec![
        u(2),
        l(vec![l(vec![t(1), u(3), l(vec![u(5)]), l(vec![Value::Str(addr)]), Value::Bool(true)]), l(vec![t(2), u(0), l(vec![]), l(vec![]), Value::Bool(false)])]),
        l(vec![t(3)]),
    ]);
    let s = same::<Status>(status.clone());
    assert_eq!((s.connected, s.groups[&Tid::from_bytes([1; 15])].state, s.two_sources.len()), (2, SyncState::Refused, 1));
    refused::<Status>(longer(&status));

    for by in PurgeBy::ALL {
        assert_eq!(same::<osis_schema::Retention>(u(by as u64)).by, by);
    }
    refused::<osis_schema::Retention>(u(4));
}
