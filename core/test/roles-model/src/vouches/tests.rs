//! Hand worlds: the minimal world of each property, each asserting its control fails.
//! H is the remover (node 0), X the removed node (1).

use super::*;

const FULL: Option<Edge> = Some(Edge { role: Role::Admin, until: NEVER, invite: Role::Admin });
const WRITE: Option<Edge> = Some(Edge { role: Role::Write, until: NEVER, invite: Role::None });
const H: usize = 0;
const X: usize = 1;

struct B(World);

impl B {
    fn new(genesis: &[Option<Edge>]) -> B {
        B(World { h: EHist { genesis: genesis.to_vec(), writes: vec![], recv: vec![], extra: vec![] }, vouches: vec![] })
    }
    /// A one-op commit; `recv` lists (node, time), others never. Returns its op index.
    fn op(&mut self, author: usize, x: usize, e: Option<Edge>, t: u32, recv: &[(usize, u32)]) -> usize {
        let h = &mut self.0.h;
        let mut r = vec![LATE; h.n()];
        r[author] = t;
        for &(m, tm) in recv {
            r[m] = tm;
        }
        let id = h.writes.len() as u32;
        h.writes.push(EWrite { author, t, id, ops: vec![(x, e)], fin: false });
        h.recv.push(r);
        id as usize
    }
    /// The honest vouches, received by every node a tick after they are written.
    fn honest(mut self, rules: Rules) -> World {
        let n = self.0.h.n();
        self.0.derive(rules, |a, t| {
            let mut r = vec![t + 1; n];
            r[a] = t;
            r
        });
        self.0
    }
    fn vouch(&mut self, author: usize, t: u32, removal: usize, lists: &[usize], recv: &[(usize, u32)]) {
        let mut r = vec![LATE; self.0.h.n()];
        r[author] = t;
        for &(m, tm) in recv {
            r[m] = tm;
        }
        self.0.vouches.push(Vouch { author, t, removal: removal as u32, lists: lists.iter().map(|&c| c as u32).collect(), recv: r, forged: true });
    }
}

fn role(w: &World, rules: Rules, trust: u64, x: usize) -> Role {
    judge(w, rules, trust).res.0[x].0
}

/// X shares with K; only W received it; H removes X. W's vouch keeps the grant (finding 1 of
/// notes/path-model-findings.md on today's walk).
#[test]
fn a_grant_only_a_witness_received_stands() {
    let world = |rules| {
        let mut b = B::new(&[FULL, FULL, FULL, None]);
        b.op(X, 3, FULL, 1, &[(2, 1), (3, 1)]);
        b.op(H, X, None, 4, &[(2, 5), (3, 4)]);
        b.honest(rules)
    };
    assert_eq!(role(&world(FIXED), FIXED, 0, 3), Role::Admin);
    assert_eq!(kept(&world(FIXED), FIXED, 0), (1, 0));
    let off = Rules { vouches: false, ..FIXED };
    assert_eq!(role(&world(off), off, 0, 3), Role::None);
    assert_eq!(kept(&world(off), off, 0), (1, 1));
}

/// W writes only; H grants it admin after the removal: its vouch written then keeps X's grant.
#[test]
fn a_witness_granted_the_right_after_the_removal_vouches() {
    let world = |rules| {
        let mut b = B::new(&[FULL, FULL, WRITE, None]);
        b.op(X, 3, FULL, 1, &[(2, 1), (3, 1)]);
        b.op(H, X, None, 4, &[(2, 5), (3, 4)]);
        b.op(H, 2, FULL, 6, &[(2, 6), (3, 6)]);
        b.honest(rules)
    };
    assert_eq!(role(&world(FIXED), FIXED, 0, 3), Role::Admin);
    let once = Rules { rewrite: false, ..FIXED };
    assert_eq!(role(&world(once), once, 0, 3), Role::None);
    assert_eq!(kept(&world(once), once, 0).1, 1);
}

/// Written from its own held set, a vouch can miss: X demotes W to write (only H received it)
/// and grants K write (only W received it); H removes X, then grants W admin again. W never
/// received its demotion, so it reads itself an admin throughout: its vouch at receipt of the
/// removal does not count (W holds write there) and its view never shows it newly holding the
/// right, so it never writes again. The idealised writing (read off the canonical walk) writes
/// again after the re-grant and keeps K's grant; so does the state-based writing (`Rules::state`):
/// W receives its demotion by `SYNC`, sees its vouch not counting, and writes one that does.
#[test]
fn a_witness_unaware_of_its_own_demotion_never_vouches_again() {
    let world = |rules| {
        let mut b = B::new(&[FULL, FULL, FULL, None]);
        b.op(X, 3, WRITE, 3, &[(2, 3), (3, 3)]);
        b.op(X, 2, WRITE, 3, &[(H, 3)]);
        b.op(H, X, None, 4, &[(2, 5), (3, 4)]);
        b.op(H, 2, FULL, 6, &[(2, 6), (3, 6)]);
        b.honest(rules)
    };
    let held = Rules { held: true, ..FIXED };
    assert_eq!(role(&world(FIXED), FIXED, 0, 3), Role::Write);
    assert_eq!(kept(&world(FIXED), FIXED, 0), (1, 0));
    assert_eq!(role(&world(held), held, 0, 3), Role::None);
    assert_eq!(kept(&world(held), held, 0), (1, 1));
    let state = Rules { state: true, ..FIXED };
    assert_eq!(role(&world(state), state, 0, 3), Role::Write);
    assert_eq!(kept(&world(state), state, 0), (1, 0));
}

/// X demoted W before the theft; only W received it. W vouches for its own demotion (an edge
/// write lowering its own edge always applies): the demotion stays made, in two walks.
#[test]
fn a_demotion_only_its_victim_received_stays_made() {
    let mut b = B::new(&[FULL, FULL, FULL]);
    b.op(X, 2, WRITE, 1, &[(2, 1)]);
    b.op(H, X, None, 4, &[(2, 5)]);
    let w = b.honest(FIXED);
    assert_eq!(role(&w, FIXED, 0, 2), Role::Write);
    assert_eq!(stays_made(&w, FIXED, 0), (1, 0));
    let off = Rules { vouches: false, ..FIXED };
    assert_eq!(role(&w, off, 0, 2), Role::Admin);
    assert_eq!(stays_made(&w, off, 0), (1, 1));
}

/// The thief removes H; H receives it and removes X, listing it. Trusted, H's removal is void
/// on today's walk: listing keeps X's removal of H, and with an empty list it applies. Reading
/// such an entry as absent (the rest of what no list keeps) needs H's stated path (A1).
#[test]
fn a_removal_listing_the_thiefs_removal_of_its_author_is_void() {
    let mut b = B::new(&[FULL, FULL, FULL]);
    b.op(X, H, None, 1, &[(H, 2), (2, 2)]);
    let r = b.op(H, X, None, 4, &[(2, 5)]);
    let w = b.0;
    assert_eq!(judge(&w, FIXED, 1 << r).active, 0);
    assert_eq!(listing(&w, FIXED), Listing { checked: 2, fail: 0, lowered: 1, accomplice: 0, revived: 0 });
}

/// X grants Y admin; Y removes H; H received both and removes X, then Y. Trusted alone, H's
/// removal of X is void as written and applies with an empty list (an accomplice), and its
/// removal of Y likewise (Y lowered H). Both trusted, both stay void; a removal of Y omitting
/// Y's removal of H applies both (notes/disputes.md, Hole: an accomplice).
#[test]
fn an_accomplices_removal_is_answered_by_a_removal_omitting_it() {
    let world = |omit: bool| {
        let mut b = B::new(&[FULL, FULL, None]);
        b.op(X, 2, FULL, 1, &[(H, 1), (2, 1)]);
        b.op(2, H, None, 2, if omit { &[] } else { &[(H, 2)] });
        let rx = b.op(H, X, None, 4, &[(2, 4)]);
        let ry = b.op(H, 2, None, 5, &[(2, 5)]);
        (b.0, 1 << rx | 1 << ry)
    };
    let (w, both) = world(false);
    assert_eq!(listing(&w, FIXED), Listing { checked: 3, fail: 0, lowered: 1, accomplice: 1, revived: 0 });
    assert_eq!(judge(&w, FIXED, both).active, 0);
    let (w, both) = world(true);
    assert_eq!(judge(&w, FIXED, both).active, both);
}

/// A lying admin L vouches for X's grant nobody received; H removes L without having received
/// the vouch: the vouch falls with L. Received by H first, it stands (the accepted bargain).
#[test]
fn a_vouch_falls_with_its_author_unless_the_remover_received_it() {
    let world = |h_got: bool| {
        let mut b = B::new(&[FULL, FULL, FULL, None]);
        let g = b.op(X, 3, FULL, 1, &[(3, 1)]);
        let r = b.op(H, X, None, 4, &[(2, 4), (3, 4)]);
        b.vouch(2, 5, r, &[g], if h_got { &[(H, 5)] } else { &[] });
        b.op(H, 2, None, 6, &[(3, 6)]);
        b.0
    };
    assert_eq!(role(&world(false), FIXED, 0, 3), Role::None);
    assert_eq!(role(&world(true), FIXED, 0, 3), Role::Admin);
}

/// X's own vouch and an outsider's count for nothing.
#[test]
fn a_vouch_by_the_removed_node_or_an_outsider_counts_for_nothing() {
    let mut b = B::new(&[FULL, FULL, None, None]);
    let g = b.op(X, 3, FULL, 1, &[(3, 1)]);
    let r = b.op(H, X, None, 4, &[(2, 4), (3, 4)]);
    b.vouch(X, 5, r, &[g], &[(H, 6)]);
    b.vouch(2, 5, r, &[g], &[(H, 6)]);
    let w = b.0;
    assert!(judge(&w, FIXED, 0).counted.is_empty());
    assert_eq!(safety(&w, FIXED, 0).1, 0);
    assert_eq!(safety(&w, FIXED, 0).2, 0);
}

/// X, lowered by H to write with invite read, still invites: it vouches for its own backdated
/// invite grant, which no other node received, and it applies at its own `ts`. The A1 rule
/// (nobody vouches for its own signer's commit) closes it; S3 leaves it.
#[test]
fn a_demoted_node_vouches_for_its_own_backdated_invite() {
    let mut b = B::new(&[FULL, FULL, None]);
    let g = b.op(X, 2, Some(Edge { role: Role::Read, until: NEVER, invite: Role::None }), 2, &[]);
    let r = b.op(H, X, Some(Edge { role: Role::Write, until: NEVER, invite: Role::Read }), 4, &[(2, 4)]);
    b.vouch(X, 5, r, &[g], &[(H, 5), (2, 5)]);
    let w = b.0;
    assert_eq!(judge(&w, FIXED, 0).counted.len(), 1);
    assert_eq!(role(&w, FIXED, 0, 2), Role::Read);
    assert_eq!(safety(&w, FIXED, 0), (1, 0, 1));
}

/// X removes Y long before the theft; H received it, so H's removal of X lists it. Y, holding
/// nothing, writes a grant of admin to H stamped before H's removal (skipped). Y stays removed
/// (notes/account-membership-design.md §4, What a list leaves out: "a removal X made long before the
/// theft stays made").
#[test]
fn a_removed_node_writing_a_grant_to_the_remover_stays_removed() {
    const Y: usize = 2;
    let world = |junk: bool| {
        let mut b = B::new(&[FULL, FULL, FULL]);
        b.op(X, Y, None, 1, &[(H, 1)]);
        if junk {
            b.op(Y, H, FULL, 2, &[]);
        }
        b.op(H, X, None, 4, &[]);
        b.0
    };
    assert_eq!(role(&world(false), FIXED, 0, Y), Role::None);
    assert_eq!(role(&world(true), FIXED, 0, Y), Role::None);
    assert_eq!(stays_made(&world(true), FIXED, 0), (1, 0));
}

#[test]
#[ignore = "property"]
fn random_worlds_hold_plain() {
    let st = random(4000, FIXED);
    assert_eq!(st.failures(), 0, "{}", st.ex.first().map_or(String::new(), |(l, w)| format!("{l}:\n{w}")));
    assert!(st.counted > 0 && st.kept_checked > 0 && st.made_checked > 0 && st.safety_checked > 0);
}

#[test]
#[ignore = "property"]
fn family_sample_holds_and_each_control_fails_plain() {
    let st = exhaustive(FIXED, 397);
    assert_eq!(st.failures(), 0);
    assert!(st.counted > 0);
    for rules in [Rules { vouches: false, ..FIXED }, Rules { rewrite: false, ..FIXED }] {
        assert!(exhaustive(rules, 397).failures() > 0, "{rules:?}");
    }
}

// a failing world shrinks under the rules searched: its honest vouches are the ones they write
// (a shrink rewriting them under `FIXED` printed a hybrid the searched rules never make)
#[test]
fn a_control_shrinks_under_its_own_rules() {
    let once = Rules { rewrite: false, ..FIXED };
    let st = exhaustive(once, 397);
    let (label, w) = st.ex.first().expect("the control fails");
    let s = shrunk(w, label, once);
    assert!(fails(label, &s, once), "{s}");
    assert_eq!(format!("{}", s.rederived(once)), format!("{s}"));
    // every candidate of a world the two writings tell apart is written by the searched rules
    let mut rng = Rng(0);
    let w = std::iter::repeat_with(|| random_world(&mut rng, once)).find(|w| format!("{}", w.rederived(once)) != format!("{}", w.rederived(FIXED))).unwrap();
    for c in crate::shrink::Shrink::smaller(&Shrinking { w, rules: once }) {
        assert_eq!(format!("{}", c.w.rederived(once)), format!("{}", c.w));
    }
}

#[test]
#[ignore]
fn random_worlds_hold_large() {
    assert_eq!(random(40_000, FIXED).failures(), 0);
}

#[test]
#[ignore]
fn small_family_holds_exhaustive() {
    assert_eq!(exhaustive(FIXED, 1).failures(), 0);
}

/// A (node 0) leaves at 3; X (node 3), granted admin at 2, edits its own edge at 2 (role down,
/// invite up), which A received; A removes X at 6 and X removes A at 6, after it. As written,
/// A's removal is void (A left). With an empty list, X's edit is contested, X stays admin, its
/// removal of A audits A's leaving, and A's removal applies at its key, leaving X's removal
/// void: the empty baseline revives A, so `listing` sets it aside.
#[test]
fn an_empty_list_reviving_its_author_is_set_aside() {
    let admin = Some(Edge { role: Role::Admin, until: NEVER, invite: Role::None });
    let edit = Some(Edge { role: Role::Read, until: 5, invite: Role::Read });
    let mut b = B::new(&[admin, None, admin, Some(Edge { role: Role::Write, until: NEVER, invite: Role::Write })]);
    b.op(2, 3, admin, 2, &[]);
    b.op(3, 3, edit, 2, &[(H, 1)]);
    b.op(H, H, None, 3, &[]);
    let r = b.op(H, 3, None, 6, &[]);
    b.op(3, H, None, 6, &[]);
    let w = b.0;
    assert_eq!(judge(&w, FIXED, 1 << r).active, 0);
    assert_eq!(listing(&w, FIXED), Listing { checked: 2, fail: 0, lowered: 0, accomplice: 0, revived: 1 });
}

/// What vouches keep, as spec/permissions.md §5.1 promises it (`kept_end`), under the
/// state-based writing; the control without vouches fails it.
#[test]
#[ignore = "property"]
fn state_writing_keeps_what_the_spec_promises_plain() {
    let state = Rules { state: true, ..FIXED };
    let st = random(2000, state);
    assert_eq!(st.kept_end_fail, 0, "{}", st.ex.iter().find(|(l, _)| *l == "kept_end").map_or(String::new(), |(_, w)| format!("{w}")));
    assert!(st.kept_end_checked > 0);
    assert!(random(2000, Rules { vouches: false, ..state }).kept_end_fail > 0);
}

/// `family_world` decodes each index below one block of subsets to a distinct history: the
/// small family's subsets of X's writes, each once.
#[test]
fn family_worlds_are_distinct() {
    let m = family_size() / 36;
    let mut seen = std::collections::BTreeSet::new();
    for i in 0..m {
        let w = family_world(FIXED, i);
        let xs: Vec<_> = w.h.writes.iter().filter(|x| x.author == 1).map(|x| (x.t, x.ops.clone(), w.h.recv[x.id as usize].clone())).collect();
        assert!(xs.len() <= 3);
        assert!(seen.insert(format!("{xs:?}")), "index {i}");
    }
}

/// The writers' leaving out on today's walk: H
/// leaves out of its list X's removal of H, with which its removal would not apply, and a
/// witness's vouch leaves it out too; H's removal applies trusted, and the listing set-aside is
/// not needed. Likewise for the accomplice: H leaves out Y's removal of H from its removal of Y.
#[test]
fn the_writers_leave_out_what_their_removal_does_not_apply_with() {
    let stands = Rules { stands: true, ..FIXED };
    let mut b = B::new(&[FULL, FULL, FULL]);
    b.op(X, H, None, 1, &[(H, 2), (2, 2)]);
    let r = b.op(H, X, None, 4, &[(2, 5)]);
    let w = b.honest(stands);
    assert_eq!(judge(&w, stands, 1 << r).active, 1 << r);
    assert_eq!(listing(&w, stands), Listing { checked: 2, fail: 0, lowered: 0, accomplice: 0, revived: 0 });
    let mut b = B::new(&[FULL, FULL, None]);
    b.op(X, 2, FULL, 1, &[(H, 1), (2, 1)]);
    b.op(2, H, None, 2, &[(H, 2)]);
    let rx = b.op(H, X, None, 4, &[(2, 4)]);
    let ry = b.op(H, 2, None, 5, &[(2, 5)]);
    let w = b.honest(stands);
    assert_eq!(listing(&w, stands), Listing { checked: 3, fail: 0, lowered: 0, accomplice: 0, revived: 0 });
    assert_eq!(judge(&w, stands, 1 << rx | 1 << ry).active, 1 << rx | 1 << ry);
}
