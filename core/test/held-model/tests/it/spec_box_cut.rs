//! Boxes cut by holder (held_model::box_cut; spec/wire.md §4 Pieces, spec/permissions.md §4
//! Copies): a reader of a holder T's key part holding T's piece of each commit takes every secret
//! of X it takes from whole copies, and a holder of sync alone learns none of X's holders; each
//! clause is needed (a control without it reads otherwise). Findings: issues/account-evidence-per-unit.md.
use held_model::box_cut::*;

const SEEDS: u64 = 3000;

fn seen(w: &World, rule: Rule, whole: bool) -> Seen {
    judge(w, &if whole { w.whole() } else { w.cut(rule) }, rule)
}

#[test]
fn a_holder_takes_from_its_piece_what_it_takes_from_whole_copies_spec_permissions_4() {
    let (mut taken, mut carried_before, mut sync_worlds) = (0, 0, 0);
    for s in 0..SEEDS {
        let w = world(s);
        let (wh, cu) = (seen(&w, Rule::Spec, true), seen(&w, Rule::Spec, false));
        assert_eq!(wh.taken, cu.taken, "seed {s}");
        assert_eq!(cu.others_pieces, 0, "seed {s}");
        if w.t_sync_alone {
            sync_worlds += 1;
            assert!(cu.learned.is_empty(), "seed {s}: a holder of sync alone learns {:?}", cu.learned);
        }
        taken += !cu.taken.is_empty() as u64;
        carried_before += (judge(&w, &w.cut(Rule::WholePart), Rule::Spec).others_pieces > 0) as u64;
    }
    assert!(taken > 0 && carried_before > 0 && sync_worlds > 0, "taken {taken} carried {carried_before} sync {sync_worlds}");
}

fn rd(holder: Id, role: Role, epoch: u32) -> BoxAt {
    BoxAt { holder, role, epoch }
}

fn grant(id: Cid, s: Id, g: Id, role: Role, may_grant: bool, boxes: Vec<BoxAt>) -> Commit {
    Commit { id, signer: s, ts: id, roles: Some(vec![Edge { holder: g, role: Some(role), may_grant }]), boxes, step: None }
}

/// XA grants H read with the may-grant flag; H grants T read, with a junk box to O1 beside T's.
fn junk_beside() -> World {
    let commits = vec![
        Commit { id: 1, signer: XA, ts: 1, roles: None, boxes: vec![], step: Some((0, true)) },
        grant(2, XA, H, Role::Read, true, vec![rd(H, Role::Sync, 0), rd(H, Role::Read, 0)]),
        grant(3, H, T, Role::Read, false, vec![rd(T, Role::Sync, 0), rd(T, Role::Read, 0), rd(O1, Role::Read, 0)]),
    ];
    World { commits, t_sync_alone: false }
}

/// T holds sync alone; XA grants O1 read and H write; H rotates X boxing T and O1 and XA
/// records the step; H forges a box to T at an epoch no step bears.
fn sync_alone() -> World {
    let mut commits = vec![
        Commit { id: 1, signer: XA, ts: 1, roles: None, boxes: vec![], step: Some((0, true)) },
        grant(2, XA, T, Role::Sync, false, vec![rd(T, Role::Sync, 0)]),
        grant(3, XA, O1, Role::Read, false, vec![rd(O1, Role::Sync, 0), rd(O1, Role::Read, 0)]),
        grant(4, XA, H, Role::Write, false, vec![rd(H, Role::Sync, 0), rd(H, Role::Read, 0)]),
    ];
    commits.push(Commit { id: 5, signer: H, ts: 5, roles: None, boxes: vec![rd(T, Role::Sync, 1), rd(O1, Role::Sync, 1), rd(O1, Role::Read, 1), rd(XA, Role::Sync, 1), rd(XA, Role::Read, 1)], step: None });
    commits.push(Commit { id: 6, signer: XA, ts: 6, roles: None, boxes: vec![], step: Some((1, true)) });
    commits.push(Commit { id: 7, signer: H, ts: 7, roles: None, boxes: vec![rd(T, Role::Sync, 1001)], step: None });
    World { commits, t_sync_alone: true }
}

#[test]
fn the_hand_worlds_read_as_whole_copies_spec_permissions_4() {
    for w in [junk_beside(), sync_alone()] {
        assert_eq!(seen(&w, Rule::Spec, true).taken, seen(&w, Rule::Spec, false).taken);
    }
    // the grantee's box stands beside the junk one; the rotation's sync secret is taken, the forged one not
    assert!(seen(&junk_beside(), Rule::Spec, false).taken.contains(&(Role::Read, 0)));
    let s = seen(&sync_alone(), Rule::Spec, false);
    assert!(s.taken.contains(&(Role::Sync, 1)) && !s.taken.contains(&(Role::Sync, 1001)) && s.learned.is_empty(), "{s:?}");
}

/// A `secrets.0` write judged as one over the pieces held: whole copies void the grantee's box
/// for the junk beside it, T's piece alone does not, so the two read otherwise.
#[test]
fn a_write_judged_as_one_reads_otherwise_by_piece_spec_permissions_3() {
    let w = junk_beside();
    assert_ne!(seen(&w, Rule::AspectVerdict, true).taken, seen(&w, Rule::AspectVerdict, false).taken);
    assert!((0..SEEDS).any(|s| {
        let w = world(s);
        seen(&w, Rule::AspectVerdict, true).taken != seen(&w, Rule::AspectVerdict, false).taken
    }));
}

/// Today's copies: the whole `secrets.0` part shows a holder of sync alone the other holders'
/// box keys (spec/sync-ids.md §2 What a sync holder learns).
#[test]
fn a_whole_part_shows_the_roster_spec_sync_ids_2() {
    let s = judge(&sync_alone(), &sync_alone().cut(Rule::WholePart), Rule::Spec);
    assert!(s.learned.contains(&O1) && s.others_pieces > 0, "{s:?}");
}

/// A header beside a holder of sync alone's piece names the rotator.
#[test]
fn a_header_names_the_rotator_spec_sync_ids_2() {
    let s = seen(&sync_alone(), Rule::SyncHeader, false);
    assert!(s.learned.contains(&H), "{s:?}");
}

/// Without the step check a holder of sync alone takes a forged secret: a headerless piece
/// proves itself only by the step bearing its sync key (spec/crypto.md §4 Established).
#[test]
fn a_box_without_its_step_is_taken_forged_spec_crypto_4() {
    assert!(seen(&sync_alone(), Rule::NoStepCheck, false).taken.contains(&(Role::Sync, 1001)));
}
