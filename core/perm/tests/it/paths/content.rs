//! Small worlds of content, addenda, covers and purges (A1 step 3b): the model's `tiny`
//! worlds hold grant writes alone, so these are drawn here over the model's `World` and judged by
//! the model as the oracle. Account A (H's) mints T1, A2 is K's; at 1 H pairs B, X and N5, shares
//! T1 with A2 at write, and K gives Z write on A2; halfway H removes X. Parties (X one in three)
//! write A's grants (admin or none,
//! each listing earlier commits at random), T1's grants along [A] (A2's grant: write or
//! none), content on T1 along [A] or [A2] (a purge author of the signer or the listed thing),
//! one commit writing a grant on A and A2's on T1 (write, admin or none), addenda against an
//! earlier lowering, covers carrying earlier content and purges by author.
//! spec/permissions.md §5.1, §5.2, §6.

use super::diff;
use crate::common::{seeded, sharded};
use roles_model::paths::{self as m, Id, Kind, Set, Thing, View, World};
use roles_model::{Rng, Role};

const PARTIES: [Thing; 6] = [m::H, m::B, m::X, m::N5, m::Z, m::K];

/// One in three commits of other signers may be listed too.
fn rng_free(j: Id) -> bool {
    j.is_multiple_of(3)
}

/// Content world `i`: 4 to 15 commits, its view (every commit held, or one in four dropped at
/// random) trusting nothing or (every third world) one held lowering.
pub fn world(i: u64) -> (World, View) {
    let mut rng = Rng::thread(0xc0a7, i as usize);
    let mut w = m::account();
    // H pairs B, X and N5 on A, shares T1 with A2 at write; K gives Z write on A2
    for h in [m::B, m::X, m::N5] {
        w.grant(m::H, 1, &[], m::A, h, Role::Admin, &[]);
    }
    w.grant(m::H, 1, &[m::A], m::T1, m::A2, Role::Write, &[]);
    w.grant(m::K, 1, &[], m::A2, m::Z, Role::Write, &[]);
    let n = 4 + (i % 12) as usize;
    let pick = |rng: &mut Rng, xs: &[Id]| -> Option<Id> { (!xs.is_empty()).then(|| xs[rng.below(xs.len())]) };
    let mut removal: Option<Id> = None;
    for step in 0..n {
        // halfway, H removes X from A at the middle tick, listing each earlier commit by one half
        if step == n / 2 {
            let l: Vec<Id> = (0..w.commits.len()).filter(|_| rng.below(2) == 0).collect();
            removal = Some(w.grant(m::H, 2 + (n / 2) as u32, &[], m::A, m::X, Role::None, &l));
        }
        // X, the removed party, signs one in three
        let s = if rng.below(3) == 0 { m::X } else { PARTIES[rng.below(PARTIES.len())] };
        let ts = 2 + rng.below(n) as u32;
        let earlier: Vec<Id> = (0..w.commits.len()).collect();
        let list = |rng: &mut Rng, f: &dyn Fn(Id) -> bool| -> Vec<Id> { earlier.iter().copied().filter(|&j| f(j) && rng.below(2) == 0).collect() };
        let lowerings: Vec<Id> = match removal {
            // against H's removal of X two times in three
            Some(r) if rng.below(3) > 0 => vec![r],
            _ => earlier.iter().copied().filter(|&j| w.lowers(j).is_some()).collect(),
        };
        let contents: Vec<Id> = earlier.iter().copied().filter(|&j| matches!(w.commits[j].kind, Kind::Content)).collect();
        match rng.below(12) {
            0 | 1 => {
                let h = PARTIES[rng.below(PARTIES.len())];
                let role = if rng.below(2) == 0 { Role::Admin } else { Role::None };
                let l = list(&mut rng, &|_| true);
                w.grant(s, ts, &[], m::A, h, role, &l);
            }
            2 => {
                let role = if rng.below(2) == 0 { Role::Write } else { Role::None };
                let l = list(&mut rng, &|_| true);
                if rng.below(2) == 0 {
                    w.grant(s, ts, &[m::A], m::T1, m::A2, role, &l);
                } else {
                    // one commit writing two things: a holder's grant on A and A2's on T1 (admin one
                    // time in two)
                    let h = PARTIES[rng.below(PARTIES.len())];
                    let a = if rng.below(2) == 0 { Role::Admin } else { Role::None };
                    let role = if role == Role::Write && rng.below(2) == 0 { Role::Admin } else { role };
                    let (fa, ft) = (w.cut(&l), w.cut(&list(&mut rng, &|_| true)));
                    // in the commit's part order (spec/permissions.md §5.1 step 1): the signer's
                    // own grant on A is a hop of the path stated for T1, so its part comes last
                    let on_a = |w: &mut World| w.push(s, ts, &[], m::A, Kind::set(h, a).listing(fa.clone()));
                    let on_t = |w: &mut World| w.push(s, ts, &[m::A], m::T1, Kind::set(m::A2, role).listing(ft.clone()));
                    let ids = if h == s { [on_t(&mut w), on_a(&mut w)] } else { [on_a(&mut w), on_t(&mut w)] };
                    w.group(&ids);
                }
            }
            3 | 4 => {
                let (path, ix) = if rng.below(3) == 0 { (vec![m::A2], rng.below(2)) } else { (vec![m::A], rng.below(2)) };
                w.content_as(s, ts, &path, m::T1, ix);
            }
            6 => {
                let carries: Set = list(&mut rng, &|j| contents.contains(&j)).into_iter().collect();
                w.push(s, ts, &[m::A], m::T1, Kind::Cover { carries });
            }
            7 => {
                let author = if rng.below(2) == 0 { m::A } else { s };
                w.purge(s, ts, &[m::A], m::T1, author);
            }
            _ => {
                // stamped after its removal, listing content before it
                if let Some(r) = pick(&mut rng, &lowerings) {
                    let rts = w.commits[r].ts;
                    let x = w.sets(r).map(|e| e.0);
                    let l = list(&mut rng, &|j| contents.contains(&j) && w.commits[j].ts <= rts && (Some(w.commits[j].signer) == x || rng_free(j)));
                    w.addendum(s, ts.max(rts + 1), &[m::A], m::T1, r, &l);
                }
            }
        }
    }
    let mut v = View::all(&w);
    if i % 4 == 1 {
        let gone: Vec<Id> = (0..w.commits.len()).filter(|_| rng.below(4) == 0).collect();
        v = v.without(&gone);
    }
    let lows: Vec<Id> = v.held.iter().copied().filter(|&k| w.lowers(k).is_some()).collect();
    if i.is_multiple_of(3) && !lows.is_empty() {
        v.trust.insert(lows[(i / 3) as usize % lows.len()]);
    }
    (w, v)
}

/// Content worlds `start..start + n`; the failures, at most three.
pub fn run(start: u64, n: u64, disputes: bool) -> Vec<String> {
    let mut fails = vec![];
    for i in start..start + n {
        let (w, v) = world(i);
        if let Some(d) = diff(&w, &v, disputes) {
            fails.push(format!("content world {i}: {d}\nheld {:?} trust {:?}\n{}", v.held, v.trust, m::tiny_trace(&w)));
            if fails.len() >= 3 {
                return fails;
            }
        }
    }
    fails
}

// spec/permissions.md §5.2: the walk reads small worlds of content, addenda, covers and
// purges as the model does, disputes included in a share.
#[test]
#[ignore = "property"]
fn paths_content_agree_plain() {
    let f = run(0, 60, true);
    assert!(f.is_empty(), "{}", f.join("\n"));
    let f = run(60, 600, false);
    assert!(f.is_empty(), "{}", f.join("\n"));
}

// spec/permissions.md §5.2: as above, a sample (a property).
#[test]
#[ignore = "property"]
fn paths_content_agree_large() {
    let f: Vec<String> = sharded(200_000, 0x5eed_0a1c, |n, seed| {
        let start = seeded(seed) % (1 << 40);
        let mut f = run(start, n / 10, true);
        f.extend(run(start + n, n - n / 10, false));
        f
    })
    .concat();
    assert!(f.is_empty(), "{}", f.join("\n"));
}

