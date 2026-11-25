//! Certificate copies cut per sync ID (held_model::copy_cut; spec/permissions.md §4 Copies): a
//! reader of S holding S's cut of each copy judges everything it reads or does exactly as with
//! whole copies; each clause of the cut is needed (a control without it judges otherwise).
//! Findings: issues/account-evidence-per-unit.md.
use held_model::copy_cut::*;

const SEEDS: u64 = 3000;

/// The first field two readings differ in.
fn differs(a: &Seen, b: &Seen) -> Option<&'static str> {
    if a.bodies != b.bodies {
        Some("bodies")
    } else if a.t_rotations != b.t_rotations {
        Some("t_rotations")
    } else if a.t_blocked != b.t_blocked {
        Some("t_blocked")
    } else if a.a_keysets != b.a_keysets {
        Some("a_keysets")
    } else if a.x_taken != b.x_taken {
        Some("x_taken")
    } else if a.x_steps != b.x_steps {
        Some("x_steps")
    } else {
        None
    }
}

/// The seeds where `rule`'s cut reads otherwise than whole copies, with the field.
fn failures(rule: Rule) -> Vec<(u64, &'static str)> {
    (0..SEEDS)
        .filter_map(|s| {
            let w = world(s);
            differs(&judge(&w, &w.whole()), &judge(&w, &w.cut(rule))).map(|f| (s, f))
        })
        .collect()
}

#[test]
fn a_cut_copy_judges_as_the_whole_copy_spec_permissions_4() {
    let fails = failures(Rule::Spec);
    assert!(fails.is_empty(), "{} of {SEEDS} worlds read otherwise, first {:?}", fails.len(), fails.first());
    // the cut leaves parts out, and what it keeps decides something
    let (mut dropped, mut blocked, mut taken, mut whole_secrets, mut cut_secrets) = (0, 0, 0, 0, 0);
    for s in 0..SEEDS {
        let w = world(s);
        let (wh, cu) = (w.whole(), w.cut(Rule::Spec));
        whole_secrets += parts(&wh, Ak::Secrets);
        cut_secrets += parts(&cu, Ak::Secrets);
        dropped += (parts(&wh, Ak::Secrets) > parts(&cu, Ak::Secrets)) as u64;
        let seen = judge(&w, &cu);
        blocked += !seen.t_blocked.is_empty() as u64;
        taken += !seen.x_taken.is_empty() as u64;
    }
    assert!(dropped > 0 && blocked > 0 && taken > 0, "dropped {dropped} blocked {blocked} taken {taken}");
    assert!(cut_secrets < whole_secrets, "secrets.0 parts: whole {whole_secrets}, cut {cut_secrets}");
}

/// A hand world: A minted with admin node 1, T with admin A; node 1 grants node 2 read with the
/// may-grant flag; node 2 grants node 3 read (a may-grant grant: its box and record at A's epoch 0
/// name node 3's keyset 0); node 3 rotates its keyset (R holds it); node 1 rotates T boxing A at
/// epoch 0. Node 2 and 3 write nothing on T, so their grants are in T's unit only as A's keys.
/// `admin_rotates`: an admin node 2 (granted admin) rotates A instead of node 1's T rotation
/// needing it, and nobody writing T needs node 2's grant.
fn hand(admin_rotates: bool) -> World {
    let rd = |holder, epoch, keyset| BoxAt { holder, role: Role::Read, epoch, keyset };
    let mut cs = Vec::new();
    let mut c = |id, signer, thing, hops: Vec<(Id, Id)>, parts| cs.push(Commit { id, signer, thing, hops, ts: id, parts });
    c(1, 1, A, vec![(1, A)], vec![Delta::Keys { keyset: Some(0), records: vec![rd(1, 0, 0)] }, Delta::Secrets(vec![rd(1, 0, 0)]), Delta::Sync]);
    if admin_rotates {
        let b = vec![rd(2, 0, 0)];
        c(2, 1, A, vec![(1, A)], vec![Delta::Roles(vec![Edge { holder: 2, role: Some(Role::Admin), may_grant: false }]), Delta::Secrets(b.clone()), Delta::Keys { keyset: None, records: b }]);
        let b = vec![rd(1, 1, 0), rd(2, 1, 0)];
        c(3, 2, A, vec![(2, A)], vec![Delta::Keys { keyset: Some(1), records: b.clone() }, Delta::Secrets(b)]);
        c(4, 1, T, vec![(1, A), (A, T)], vec![Delta::Secrets(vec![rd(A, 1, 1)])]);
    } else {
        let b = vec![rd(2, 0, 0)];
        c(2, 1, A, vec![(1, A)], vec![Delta::Roles(vec![Edge { holder: 2, role: Some(Role::Read), may_grant: true }]), Delta::Secrets(b.clone()), Delta::Keys { keyset: None, records: b }]);
        let b = vec![rd(3, 0, 0)];
        c(3, 2, A, vec![(2, A)], vec![Delta::Roles(vec![Edge { holder: 3, role: Some(Role::Read), may_grant: false }]), Delta::Secrets(b.clone()), Delta::Keys { keyset: None, records: b }]);
        c(4, 3, 3, vec![], vec![Delta::Keys { keyset: Some(1), records: vec![] }]);
        c(5, 1, T, vec![(1, A), (A, T)], vec![Delta::Secrets(vec![rd(A, 1, 0)])]);
    }
    let known = if admin_rotates { vec![] } else { vec![4] };
    World { commits: cs, records: [(A, 1), (T, A), (X, XA)].into(), known }
}

#[test]
fn the_hand_worlds_read_as_whole_copies_spec_permissions_4() {
    for w in [hand(false), hand(true)] {
        assert_eq!(judge(&w, &w.whole()), judge(&w, &w.cut(Rule::Spec)));
    }
    // node 3's box is stale at R: T's epoch boxing A there is blocked
    let w = hand(false);
    assert!(!judge(&w, &w.cut(Rule::Spec)).t_blocked.is_empty());
    // node 2's rotation of A is a keyset R seals T to A at
    let w = hand(true);
    assert!(judge(&w, &w.cut(Rule::Spec)).a_keysets.contains(&1));
}

/// A `secrets.0` or `keys.0` part without its commit's `roles.0` on the thing: a may-grant
/// grant's boxes and records count for nothing, so a stale box goes unseen.
#[test]
fn a_box_without_its_grant_reads_otherwise_spec_permissions_2() {
    let w = hand(false);
    assert_eq!(differs(&judge(&w, &w.whole()), &judge(&w, &w.cut(Rule::NoGrantRoles))), Some("t_blocked"));
}

/// Evidence closed over edge-class and `sync.0` parts only: a `keys.0` part whose author's grant
/// no other part needs is unjudgeable, so its keyset is not sealed to.
#[test]
fn a_keyset_without_its_evidence_reads_otherwise_spec_permissions_4() {
    let w = hand(true);
    assert_eq!(differs(&judge(&w, &w.whole()), &judge(&w, &w.cut(Rule::NoPartEvidence))), Some("a_keysets"));
    assert!(!failures(Rule::NoPartEvidence).is_empty(), "the control never reads otherwise at random");
}

/// Finding 1's lever (no grant's box records under T's sync ID): a reader holding a node's newer
/// keyset no longer finds A's epoch stale, and writes T under an epoch boxing A there.
#[test]
fn a_unit_without_grant_records_reads_otherwise_spec_crypto_4() {
    let w = hand(false);
    assert_eq!(differs(&judge(&w, &w.whole()), &judge(&w, &w.cut(Rule::NoRecords))), Some("t_blocked"));
    let fails = failures(Rule::NoRecords);
    assert!(!fails.is_empty(), "the control never reads otherwise at random");
    assert!(fails.iter().all(|(_, f)| *f == "t_blocked"), "{fails:?}");
}

