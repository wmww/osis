//! Boxes cut by holder (held_model::box_cut; spec/wire.md §4 Pieces, spec/permissions.md §4
//! Copies): a reader of a holder T's unit holding, in X's stub, T's piece of each commit takes every secret
//! of X it takes from whole copies, and a holder of sync alone learns none of X's holders; each
//! clause is needed (a control without it reads otherwise). Findings: issues/account-evidence-per-unit.md.
use held_model::box_cut::*;

const SEEDS: u64 = 3000;

fn seen(w: &World, rule: Rule, whole: bool) -> Seen {
    judge(w, &if whole { w.whole() } else { w.cut(rule) }, rule)
}

#[test]
fn a_holder_takes_from_its_piece_what_it_takes_from_whole_copies_spec_permissions_4() {
    // and a holder of sync alone learns no holder of X, its removal included, and holds sync
    // exactly while X's newest step bears a secret its boxes give
    let (mut taken, mut carried_before, mut sync_worlds, mut history, mut told, mut shown, mut forged) = (0, 0, 0, 0, 0, 0, 0);
    for s in 0..SEEDS {
        let w = world(s);
        let (wh, cu) = (seen(&w, Rule::Spec, true), seen(&w, Rule::Spec, false));
        assert_eq!(wh.taken, cu.taken, "seed {s}");
        assert_eq!(cu.others_pieces, 0, "seed {s}");
        history += (cu.taken != seen(&w, Rule::NoRest, false).taken) as u64;
        if !w.reads(Rule::Spec) {
            sync_worlds += 1;
            // a forged edge write naming T read turns nothing R receives into a header
            forged += w.reads(Rule::AnyValidity) as u64;
            assert!(cu.learned.is_empty(), "seed {s}: a holder of sync alone learns {:?}", cu.learned);
            assert_eq!(cu.holds, w.t_holds(), "seed {s}: T's holding as its steps tell it");
            told += (!cu.holds && seen(&w, Rule::HolderKept, false).holds) as u64;
            shown += !seen(&w, Rule::RemovalHeader, false).learned.is_empty() as u64;
        }
        taken += !cu.taken.is_empty() as u64;
        carried_before += (judge(&w, &w.cut(Rule::WholePart), Rule::Spec).others_pieces > 0) as u64;
    }
    // the controls read otherwise somewhere: a removal told only by its step, a header naming its
    // remover, a forged write giving read
    assert!(
        taken > 0 && carried_before > 0 && sync_worlds > 0 && history > 0 && told > 0 && shown > 0 && forged > 0,
        "taken {taken} carried {carried_before} sync {sync_worlds} history {history} told {told} shown {shown} forged {forged}"
    );
    // X's admins' grant decides: where they grant T sync, T holds sync alone whatever is forged
    for s in 0..SEEDS {
        let w = world(s);
        assert!(!w.t_sync_alone || !w.reads(Rule::Spec), "seed {s}");
    }
}

fn rd(holder: Id, role: Role, epoch: u32) -> BoxAt {
    BoxAt { holder, role, epoch }
}

fn grant(id: Cid, s: Id, g: Id, role: Role, may_grant: bool, boxes: Vec<BoxAt>) -> Commit {
    Commit { id, signer: s, ts: id, roles: Some(vec![Edge { holder: g, role: Some(role), may_grant }]), boxes, step: None, history: None }
}

/// XA grants H read with the may-grant flag; H grants T read, with a junk box to O1 beside T's.
fn junk_beside() -> World {
    let commits = vec![
        Commit { id: 1, signer: XA, ts: 1, roles: None, boxes: vec![], step: Some((0, true)), history: None },
        grant(2, XA, H, Role::Read, true, vec![rd(H, Role::Sync, 0), rd(H, Role::Read, 0)]),
        grant(3, H, T, Role::Read, false, vec![rd(T, Role::Sync, 0), rd(T, Role::Read, 0), rd(O1, Role::Read, 0)]),
    ];
    World { commits, t_sync_alone: false }
}

/// T holds sync alone; XA grants O1 read and H write; H rotates X boxing T and O1 and XA
/// records the step; H forges a box to T at an epoch no step bears.
fn sync_alone() -> World {
    let mut commits = vec![
        Commit { id: 1, signer: XA, ts: 1, roles: None, boxes: vec![], step: Some((0, true)), history: None },
        grant(2, XA, T, Role::Sync, false, vec![rd(T, Role::Sync, 0)]),
        grant(3, XA, O1, Role::Read, false, vec![rd(O1, Role::Sync, 0), rd(O1, Role::Read, 0)]),
        grant(4, XA, H, Role::Write, false, vec![rd(H, Role::Sync, 0), rd(H, Role::Read, 0)]),
    ];
    commits.push(Commit { id: 5, signer: H, ts: 5, roles: None, boxes: vec![rd(T, Role::Sync, 1), rd(O1, Role::Sync, 1), rd(O1, Role::Read, 1), rd(XA, Role::Sync, 1), rd(XA, Role::Read, 1)], step: None, history: None });
    commits.push(Commit { id: 6, signer: XA, ts: 6, roles: None, boxes: vec![], step: Some((1, true)), history: None });
    commits.push(Commit { id: 7, signer: H, ts: 7, roles: None, boxes: vec![rd(T, Role::Sync, 1001)], step: None, history: None });
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

fn history(epoch: u32, roles: &[Role], names: &[Id]) -> Option<History> {
    Some(History { epoch, roles: roles.to_vec(), names: names.to_vec() })
}

/// XA grants O1 read at epoch 0, removes it and rotates X to epoch 1 (its history boxes carry
/// epoch 0 and name O1), then grants T at epoch 1 (`sync_alone`: sync, else read), writing the
/// history boxes of the roles it boxes again.
fn granted_after_a_removal(sync_alone: bool) -> World {
    let role = if sync_alone { Role::Sync } else { Role::Read };
    let roles: &[Role] = if sync_alone { &[Role::Sync] } else { &[Role::Sync, Role::Read] };
    let commits = vec![
        Commit { id: 1, signer: XA, ts: 1, roles: None, boxes: vec![], step: Some((0, true)), history: None },
        grant(2, XA, O1, Role::Read, false, vec![rd(O1, Role::Sync, 0), rd(O1, Role::Read, 0)]),
        Commit { id: 3, signer: XA, ts: 3, roles: Some(vec![Edge { holder: O1, role: None, may_grant: false }]), boxes: vec![], step: None, history: None },
        Commit { id: 4, signer: XA, ts: 4, roles: None, boxes: vec![rd(XA, Role::Sync, 1), rd(XA, Role::Read, 1)], step: None, history: history(1, &[Role::Sync, Role::Read], &[O1]) },
        Commit { id: 5, signer: XA, ts: 5, roles: None, boxes: vec![], step: Some((1, true)), history: None },
        Commit { history: history(1, roles, &[O1]), ..grant(6, XA, T, role, false, roles.iter().map(|r| rd(T, *r, 1)).collect()) },
    ];
    World { commits, t_sync_alone: sync_alone }
}

/// A grantee with history reads before its grant only by the rest piece beside its own: its box
/// gives epoch 1, the history box at 1 gives epoch 0 (spec/permissions.md §4 Copies).
#[test]
fn a_grantee_reads_its_history_by_the_rest_spec_permissions_4() {
    let w = granted_after_a_removal(false);
    let s = seen(&w, Rule::Spec, false);
    assert_eq!(s.taken, seen(&w, Rule::Spec, true).taken);
    assert!(s.taken.contains(&(Role::Read, 0)), "{s:?}");
    assert!(!seen(&w, Rule::NoRest, false).taken.contains(&(Role::Read, 0)), "control: no rest, no history");
}

/// A holder of sync alone carries no rest: the sync role's history box it would open names the
/// departed O1 (spec/sync-ids.md §2 What a sync holder learns).
#[test]
fn a_rest_beside_sync_alone_names_departed_holders_spec_sync_ids_2() {
    let w = granted_after_a_removal(true);
    assert!(seen(&w, Rule::Spec, false).learned.is_empty());
    assert!(seen(&w, Rule::RestToSync, false).learned.contains(&O1));
}

/// T holds sync alone (XA's grant at epoch 0); XA makes H an admin; H removes T, rotates X to
/// epoch 1 boxing those left, and XA records the step. X's stub in T's unit holds the removal and the
/// step, no header: R learns no remover and judges T removed by the step past its keys.
fn removed_by_another_admin() -> World {
    let commits = vec![
        Commit { id: 1, signer: XA, ts: 1, roles: None, boxes: vec![], step: Some((0, true)), history: None },
        grant(2, XA, T, Role::Sync, false, vec![rd(T, Role::Sync, 0)]),
        grant(3, XA, H, Role::Admin, false, vec![rd(H, Role::Sync, 0), rd(H, Role::Read, 0)]),
        Commit { id: 4, signer: H, ts: 4, roles: Some(vec![Edge { holder: T, role: None, may_grant: false }]), boxes: vec![], step: None, history: None },
        Commit { id: 5, signer: H, ts: 5, roles: None, boxes: vec![rd(XA, Role::Sync, 1), rd(XA, Role::Read, 1)], step: None, history: history(1, &[Role::Sync, Role::Read], &[T]) },
        Commit { id: 6, signer: XA, ts: 6, roles: None, boxes: vec![], step: Some((1, true)), history: None },
    ];
    World { commits, t_sync_alone: true }
}

/// A holder of sync alone learns its removal by the step past its keys, never by a header
/// (spec/sync-ids.md §2 What a sync holder learns, spec/sync-judgement.md §6 Stops).
#[test]
fn a_removal_of_sync_alone_is_told_by_its_step_spec_sync_ids_2() {
    let w = removed_by_another_admin();
    let s = seen(&w, Rule::Spec, false);
    assert!(s.learned.is_empty() && !s.holds && !w.t_holds(), "{s:?}");
    assert!(seen(&w, Rule::RemovalHeader, false).learned.contains(&H), "control: the removal's header names its remover");
    assert!(seen(&w, Rule::HolderKept, false).holds, "control: the box alone keeps T holding");
    // before XA's step T holds epoch 0's secret, which nothing has replaced
    let before = World { commits: w.commits[..5].to_vec(), ..w.clone() };
    assert!(seen(&before, Rule::Spec, false).holds && before.t_holds());
}

/// XA grants H read with the may-grant flag and O1 read; H grants T sync; O1, neither admin nor
/// may-grant, forges an edge write naming T read, and O2, holding no role, another (pending).
fn forged_read() -> World {
    let commits = vec![
        Commit { id: 1, signer: XA, ts: 1, roles: None, boxes: vec![], step: Some((0, true)), history: None },
        grant(2, XA, H, Role::Read, true, vec![rd(H, Role::Sync, 0), rd(H, Role::Read, 0)]),
        grant(3, XA, O1, Role::Read, false, vec![rd(O1, Role::Sync, 0), rd(O1, Role::Read, 0)]),
        grant(4, H, T, Role::Sync, false, vec![rd(T, Role::Sync, 0)]),
        grant(5, O1, T, Role::Read, false, vec![]),
        grant(6, O2, T, Role::Read, false, vec![]),
    ];
    World { commits, t_sync_alone: true }
}

/// An invalid or pending edge write giving T read changes nothing R receives: T reads X only by a
/// valid one, so R takes T's sync secret and learns no holder of X (spec/sync-ids.md §2 What a
/// sync holder learns; spec/permissions.md §4 Key part). Control: judged whatever their validity,
/// the forged writes send T's pieces with headers and evidence, naming its granter H.
#[test]
fn a_forged_edge_write_giving_read_changes_nothing_a_sync_holder_learns_spec_sync_ids_2() {
    let w = forged_read();
    assert!(!w.reads(Rule::Spec) && w.reads(Rule::AnyValidity));
    let s = seen(&w, Rule::Spec, false);
    assert!(s.learned.is_empty() && s.taken.contains(&(Role::Sync, 0)) && s.holds, "{s:?}");
    assert_eq!(s, seen(&World { commits: w.commits[..4].to_vec(), ..w.clone() }, Rule::Spec, false), "as without the forged writes");
    assert!(judge(&w, &w.cut(Rule::AnyValidity), Rule::Spec).learned.contains(&H), "control: the granter shown");
}
