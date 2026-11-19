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
        B(World { h: EHist { genesis: genesis.to_vec(), writes: vec![], recv: vec![], lists: Lists::default() }, vouches: vec![] })
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

/// X demoted W before the theft; only W received it. W vouches for its own demotion (an edge
/// write lowering its own edge always applies): the demotion stays made, in two walks.
#[test]
fn a_demotion_only_its_victim_received_stays_made() {
    let mut b = B::new(&[FULL, FULL, FULL]);
    b.op(X, 2, WRITE, 1, &[(2, 1)]);
    b.op(H, X, None, 4, &[(2, 5)]);
    let w = b.honest(FIXED);
    assert_eq!(role(&w, FIXED, 0, 2), Role::Write);
    let off = Rules { vouches: false, ..FIXED };
    assert_eq!(role(&w, off, 0, 2), Role::Admin);
}

/// The thief removes H; H receives it and removes X, listing it (finding 7). Trusted, H's
/// removal applies: the entry is read as absent. Without the rule it is void.
#[test]
fn a_removal_listing_the_thiefs_removal_of_its_author_applies() {
    let mut b = B::new(&[FULL, FULL, FULL]);
    b.op(X, H, None, 1, &[(H, 2), (2, 2)]);
    let r = b.op(H, X, None, 4, &[(2, 5)]);
    let w = b.0;
    assert_eq!(judge(&w, FIXED, 1 << r).active, 1 << r);
    assert_eq!(listing(&w, FIXED), (2, 0, 0));
    let no = Rules { absent: false, ..FIXED };
    assert_eq!(judge(&w, no, 1 << r).active, 0);
    assert_eq!(listing(&w, no).1, 1);
}

/// H never received the thief's removal of it; W did and vouches for it, as for every write of
/// X it received. Without the rule the vouch voids H's trusted removal.
#[test]
fn a_vouch_naming_the_thiefs_removal_of_the_remover_is_absent() {
    let world = |rules| {
        let mut b = B::new(&[FULL, FULL, FULL]);
        b.op(X, H, None, 1, &[(2, 2)]);
        b.op(H, X, None, 4, &[(2, 5)]);
        b.honest(rules)
    };
    let r = 1;
    assert_eq!(judge(&world(FIXED), FIXED, 1 << r).active, 1 << r);
    let no = Rules { absent: false, ..FIXED };
    let w = world(no);
    assert!(!w.vouches.is_empty());
    assert_eq!(judge(&w, no, 1 << r).active, 0);
    assert_eq!(listing(&w, no).1, 1);
}

/// X grants Y admin; Y removes H; H received both and removes X. Trusted alone, H's removal is
/// void as written and applies with an empty list: the accomplice's lowering is not X's write.
/// H removing Y too (both trusted) applies both: that lowering is struck from H's removal of Y.
#[test]
fn an_accomplices_removal_is_answered_by_removing_the_accomplice() {
    let mut b = B::new(&[FULL, FULL, None]);
    b.op(X, 2, FULL, 1, &[(H, 1), (2, 1)]);
    b.op(2, H, None, 2, &[(H, 2)]);
    let rx = b.op(H, X, None, 4, &[(2, 4)]);
    let ry = b.op(H, 2, None, 5, &[(2, 5)]);
    let w = b.0;
    assert_eq!(listing(&w, FIXED).2, 1);
    assert_eq!(judge(&w, FIXED, 1 << rx).active, 0);
    let both = 1 << rx | 1 << ry;
    assert_eq!(judge(&w, FIXED, both).active, both);
    let no = Rules { absent: false, ..FIXED };
    assert_eq!(judge(&w, no, both).active, 0);
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

#[test]
fn random_worlds_hold() {
    let st = random(400, FIXED);
    assert_eq!(st.failures(), 0, "{}", st.ex.first().map_or(String::new(), |(l, w)| format!("{l}:\n{w}")));
    assert!(st.counted > 0 && st.kept_checked > 0 && st.safety_checked > 0);
}

#[test]
fn family_sample_holds_and_each_control_fails() {
    let st = exhaustive(FIXED, 397);
    assert_eq!(st.failures(), 0);
    assert!(st.counted > 0);
    for rules in [Rules { vouches: false, ..FIXED }, Rules { rewrite: false, ..FIXED }, Rules { absent: false, ..FIXED }] {
        assert!(exhaustive(rules, 397).failures() > 0, "{rules:?}");
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
