//! A3's delivery duty (the errand; notes/a3-spec/README.md, held_model::evidence `Runners`,
//! `Rule::lag`, `Ev::Gone`, `Ev::Pass`): any honest holder of a removal runs it (no designated
//! device), it runs in its runner's passes (a race with the thief), and the remover's node may be
//! destroyed right after removing. Findings in notes/evidence-model-findings.md (29, 30).
use held_model::evidence::names::*;
use held_model::evidence::*;
use roles_model::paths::{Id, Set};
use roles_model::Role;

/// R's mint admin (finding 19's world).
const V: roles_model::paths::Thing = 7;

/// X removes K from A at 6; K's node is the thief; A writes D; X and Q sync A, Y syncs D, nobody
/// honest syncs both. `gone`: X's node is destroyed right after removing. Then the thief writes D
/// through [A] at 8, then `passer` passes (its errands run, under `Rule::lag`). Returns the world,
/// the removal and the thief's write.
fn race(gone: bool, passer: Option<usize>) -> (World, Id, Id) {
    let pw = roles_model::paths::World::new(&[(X, A), (Y, D)]);
    let mut w = World::new(pw, &[A, D]);
    let (x, y, q, k) = (w.node(true, &[A]), w.node(true, &[D]), w.node(true, &[A]), w.node(false, &[]));
    w.write(x, |p| p.edge(X, 1, &[], A, K, Role::Write, &[]));
    w.write(x, |p| p.edge(X, 1, &[], A, Q, Role::Write, &[]));
    w.write(y, |p| p.edge(Y, 1, &[], D, A, Role::Write, &[]));
    let r = w.write(x, |p| p.edge(X, 6, &[], A, K, Role::None, &[]));
    if gone {
        w.gone(x);
    }
    let late = w.write(k, |p| p.content(K, 8, &[A], D));
    if let Some(n) = passer {
        w.pass([x, q][n]);
    }
    (w, r, late)
}

/// Per step: P1, P1 after every live node passed (`pass_all`), P8 on a complete pass.
struct Steps {
    p1: Vec<Vec<Fail>>,
    window: Vec<Vec<Fail>>,
    p8: Vec<Vec<Fail>>,
}

fn steps(w: &World, rule: &Rule) -> (Steps, State) {
    let mut s = Steps { p1: vec![], window: vec![], p8: vec![] };
    let st = w.run(rule, |st| {
        s.p1.push(w.p1(rule, st));
        s.window.push(window(w, rule, st));
        s.p8.push(w.p8_acts(rule, st, ActWhen::AfterPass, 0));
    });
    assert!(!st.unsettled);
    (s, st)
}

/// P1-window: once every live honest node has passed (its errands run), the one-sync-ID readers
/// judge as the node holding everything: the only delay is the duty's.
fn window(w: &World, rule: &Rule, st: &State) -> Vec<Fail> {
    let after = w.pass_all(rule, st);
    w.p1(rule, &after).into_iter().map(|f| Fail { prop: "P1-window", ..f }).collect()
}

/// The checks at the end of a world whose live nodes all passed last: P1, P3, P4, P7, P8.
fn settled(w: &World, rule: &Rule, st: &State) -> Vec<Fail> {
    let mut out = w.p1(rule, st);
    out.extend(w.p3(rule, st));
    out.extend(w.p4(rule, st, false));
    out.extend(w.p7_leaf_waits(rule, st));
    out.extend(w.p8_acts(rule, st, ActWhen::AfterPass, 0));
    out
}

fn lagged(runners: Runners) -> Rule {
    Rule { runners, lag: true, ..Rule::listed() }
}

/// Finding 29: between the removal and its runner's next pass reaching D, the thief's write on D
/// shows valid at D's reader, and a complete pass of D acts on it (promotes it, shows it as settled)
/// where the node holding everything judges it invalid. Once X passes, both agree. P1-window holds
/// at every step: the errand's lag is the only delay.
#[test]
fn f29_a_thief_racing_the_errand_is_shown_and_acted_on_until_the_copy_lands() {
    let (w, r, late) = race(false, Some(0));
    let rule = lagged(Runners::Remover);
    let (s, st) = steps(&w, &rule);
    let n = s.p1.len();
    // the thief's write is the step before the pass
    assert!(s.p1[n - 2].iter().any(|f| f.prop == "P1" && f.sid == D && f.id == late && f.reader == Some(Verdict::Valid) && f.full == Some(Verdict::Invalid)), "{:?}", s.p1[n - 2]);
    assert!(s.p8[n - 2].iter().any(|f| f.sid == D && f.id == late && f.reader == Some(Verdict::Valid)), "{:?}", s.p8[n - 2]);
    assert!(s.window.iter().all(Vec::is_empty), "{:?}", s.window);
    assert_eq!((s.p1[n - 1].clone(), s.p8[n - 1].clone()), (vec![], vec![]));
    assert!(st.entries[&D].contains(&r));
    assert_eq!(settled(&w, &rule, &st), vec![]);
    // with the errand run as the removal is written, no window
    let (s, _) = steps(&w, &Rule::listed());
    assert!(s.p1.iter().all(Vec::is_empty));
}

/// No designated device: X's node is destroyed right after removing K, before any pass. Q, an
/// honest holder of the removal (it syncs A), runs the duty in its pass, and D's reader judges the
/// thief's write invalid. With the remover alone running it, D never gets the removal.
#[test]
fn the_errand_runs_at_any_honest_holder_when_the_removers_node_is_lost() {
    let (w, r, late) = race(true, Some(1));
    let (s, st) = steps(&w, &lagged(Runners::Remover));
    assert!(s.p1.last().unwrap().iter().any(|f| f.sid == D && f.id == late && f.reader == Some(Verdict::Valid) && f.full == Some(Verdict::Invalid)));
    assert!(s.window.last().unwrap().iter().any(|f| f.sid == D && f.id == late), "nobody live runs it");
    assert!(!st.entries[&D].contains(&r));
    let rule = lagged(Runners::AnyHolder);
    let (s, st) = steps(&w, &rule);
    assert!(s.window.iter().all(Vec::is_empty), "{:?}", s.window);
    assert!(st.entries[&D].contains(&r));
    assert_eq!(settled(&w, &rule, &st), vec![]);
}

/// Finding 30: K writes c on D through [A]; X removes K listing c (D's leaf) and is destroyed
/// before any pass; Q runs the duty. A leaf only its remover held dies with it: D's reader holds
/// the removal from Q, which cuts c, and waits for good for a leaf nobody live holds, where the
/// node holding everything shows c. Kept with the removal wherever it is a body (under A's sync
/// ID), every holder of the removal holds its leaves and Q carries them.
#[test]
fn f30_a_leaf_only_the_lost_remover_held_strands_what_it_lists() {
    let pw = roles_model::paths::World::new(&[(X, A), (Y, D)]);
    let mut w = World::new(pw, &[A, D]);
    let (x, y, q, k) = (w.node(true, &[A]), w.node(true, &[D]), w.node(true, &[A]), w.node(false, &[]));
    w.write(x, |p| p.edge(X, 1, &[], A, K, Role::Write, &[]));
    w.write(y, |p| p.edge(Y, 1, &[], D, A, Role::Write, &[]));
    let c = w.write(k, |p| p.content(K, 2, &[A], D));
    w.write(x, |p| p.edge(X, 6, &[], A, K, Role::None, &[c]));
    w.gone(x);
    w.write(k, |p| p.content(K, 8, &[A], D));
    w.pass(q);
    let away = Rule { leaves_home: Home::None, ..lagged(Runners::AnyHolder) };
    let (_, st) = steps(&w, &away);
    let f = settled(&w, &away, &st);
    assert!(f.iter().any(|f| f.prop == "P1" && f.sid == D && f.id == c && f.reader == Some(Verdict::Pending) && f.full == Some(Verdict::Valid)), "{f:?}");
    let rule = lagged(Runners::AnyHolder);
    let (s, st) = steps(&w, &rule);
    assert!(s.window.iter().all(Vec::is_empty), "{:?}", s.window);
    assert_eq!(settled(&w, &rule, &st), vec![]);
    assert_eq!(st.leaves[&A].len(), 1, "the leaf stays with its removal under A");
}

/// Idempotence: with every holder running the duty, a sync ID holds exactly what it holds with the
/// remover alone (copies are identified by (commit, thing): several runners log one entry), and
/// every property holds, over a slice of the family.
#[test]
fn several_runners_log_one_entry_per_copy_on_a_slice_of_the_family() {
    for i in (0..FAMILY).step_by(97 * 3) {
        let w = family(Shape::nth(i));
        let (one, any) = (Rule::listed(), Rule { runners: Runners::AnyHolder, ..Rule::listed() });
        let (mut a, mut b) = (vec![], vec![]);
        w.run(&one, |st| a.push((st.entries.clone(), st.leaves.clone())));
        w.run(&any, |st| b.push((st.entries.clone(), st.leaves.clone())));
        assert_eq!(a, b, "{:?}", Shape::nth(i));
    }
}

/// `w` with node `x` destroyed right after its last write (None when none of its writes is a
/// removal), node `q` syncing A, and a pass of every other honest node at the end.
pub fn remover_lost(mut w: World, x: usize, q: usize) -> Option<World> {
    let mine: Vec<usize> = (0..w.events.len()).filter(|&k| matches!(w.events[k], Ev::Write(i) if w.by[i] == x)).collect();
    if !mine.iter().any(|&k| matches!(w.events[k], Ev::Write(i) if w.removes(i).is_some())) {
        return None;
    }
    w.events.insert(mine.last().unwrap() + 1, Ev::Gone(x));
    w.nodes[q].syncs.insert(A);
    for n in (0..w.nodes.len()).filter(|&n| n != x && w.nodes[n].honest) {
        w.events.push(Ev::Pass(n));
    }
    Some(w)
}

/// Every check of a lost-remover world: P1-window at every step, the rest once all passed.
pub fn lost_fails(w: &World, rule: &Rule) -> Vec<Fail> {
    let (s, st) = steps(w, rule);
    let mut out: Vec<Fail> = s.window.into_iter().flatten().collect();
    out.extend(settled(w, rule, &st));
    out
}

/// The family with X's node destroyed right after its last write (the removal, or a re-grant or a
/// raise after it), the errand run only in passes: under any holder every property holds (Q holds
/// the removal); under the remover alone some worlds fail (the control).
#[test]
fn a_lost_removers_duty_falls_to_another_holder_on_a_slice_of_the_family() {
    let mut control = 0;
    for i in (0..FAMILY).step_by(97 * 3) {
        let sh = Shape::nth(i);
        let Some(w) = remover_lost(family(sh), 0, family_q(sh)) else { continue };
        assert_eq!(lost_fails(&w, &lagged(Runners::AnyHolder)), vec![], "{sh:?}");
        control += usize::from(!lost_fails(&w, &lagged(Runners::Remover)).is_empty());
    }
    assert!(control > 0);
}

/// The family's node index of Q (`family`: X, Y, W where O stands apart, Q).
pub fn family_q(sh: Shape) -> usize {
    if sh.org_apart { 3 } else { 2 }
}

fn search(family_step: usize, random_worlds: u64) {
    let mut jobs: Vec<Box<dyn Fn() -> (String, Vec<Fail>) + Sync>> = vec![];
    for i in (0..FAMILY).step_by(family_step) {
        jobs.push(Box::new(move || {
            let sh = Shape::nth(i);
            let f = remover_lost(family(sh), 0, family_q(sh)).map(|w| lost_fails(&w, &lagged(Runners::AnyHolder))).unwrap_or_default();
            (format!("{sh:?}"), f)
        }));
    }
    let start = std::env::var("OSIS_HELD_START").ok().filter(|v| !v.is_empty()).map_or(0, |v| v.parse::<u64>().expect("OSIS_HELD_START is a decimal u64"));
    eprintln!("errand: random seeds {start}..{}", start + random_worlds);
    for seed in start..start + random_worlds {
        // random: x is node 0, q node 3
        jobs.push(Box::new(move || (format!("random seed {seed}"), remover_lost(random(seed, 14), 0, 3).map(|w| lost_fails(&w, &lagged(Runners::AnyHolder))).unwrap_or_default())));
    }
    let next = std::sync::atomic::AtomicUsize::new(0);
    let bad = std::sync::Mutex::new(vec![]);
    let threads = std::thread::available_parallelism().map_or(1, |n| n.get());
    std::thread::scope(|sc| {
        for _ in 0..threads {
            sc.spawn(|| loop {
                let Some(j) = jobs.get(next.fetch_add(1, std::sync::atomic::Ordering::Relaxed)) else { return };
                let (name, f) = j();
                if !f.is_empty() {
                    bad.lock().unwrap().push(format!("{name}: {:?}", f[0]));
                }
            });
        }
    });
    let bad = bad.into_inner().unwrap();
    assert!(bad.is_empty(), "{} worlds fail, first: {}", bad.len(), bad[0]);
}

#[test]
#[ignore = "property"]
fn a_lost_removers_duty_falls_to_another_holder_plain() {
    search(41, 20);
}

#[test]
#[ignore = "property"]
fn a_lost_removers_duty_falls_to_another_holder_large() {
    search(7, 200);
}

/// Finding 19's world (K writes R through [A, O, D]; Y, syncing D and A, removes O from D; N syncs
/// A and R; V syncs R alone) with W's node (O's only syncer) destroyed after granting A write on
/// O, Y's node destroyed right after removing, then the stolen K's late write on R, then a pass of
/// every live node. Returns the world and the late write.
fn keys_open_lost() -> (World, Id) {
    let pw = roles_model::paths::World::new(&[(X, A), (W, O), (Y, D), (V, R)]);
    let mut w = World::new(pw, &[A, O, D, R]);
    let (x, wn, y, v, k) = (w.node(true, &[A]), w.node(true, &[O]), w.node(true, &[D, A]), w.node(true, &[R]), w.node(false, &[]));
    let n = w.node(true, &[A, R]);
    w.write(x, |p| p.edge(X, 1, &[], A, K, Role::Write, &[]));
    w.write(wn, |p| p.edge(W, 1, &[], O, A, Role::Write, &[]));
    w.gone(wn);
    w.write(y, |p| p.edge(Y, 1, &[], D, O, Role::Write, &[]));
    w.write(v, |p| p.edge(V, 1, &[], R, D, Role::Write, &[]));
    w.write(k, |p| p.content(K, 2, &[A, O, D], R));
    w.write(y, |p| p.edge(Y, 6, &[], D, O, Role::None, &[]));
    w.gone(y);
    let late = w.write(k, |p| p.content(K, 8, &[A, O, D], R));
    for m in [x, v, n] {
        w.pass(m);
    }
    (w, late)
}

/// Finding 31: Role changes travel's keys-open half carries a removal the duty cannot once the
/// remover's node is lost before its first pass. Today Y logs its removal under A as it writes it
/// (A reads through O), N carries it to R as evidence of the thief's write there. As drafted (the
/// keys-open half gone) only the syncers of D and of O (the holder's own sync ID) hold it, and
/// none is live: nobody runs the duty and R's reader shows the late write for good. With the half
/// kept (`Stage::A3`), A3 holds as today.
#[test]
fn f31_dropping_the_keys_open_half_loses_a_removal_when_its_remover_is_lost() {
    let (w, late) = keys_open_lost();
    let at = |stage: Stage, keys_open: bool| {
        let mut w = w.clone();
        let rule = Rule { runners: Runners::AnyHolder, lag: true, keys_open, ..stage.set(&mut w, Rule::listed()) };
        lost_fails(&w, &rule).into_iter().filter(|f| f.sid == R && f.id == late).collect::<Vec<_>>()
    };
    let drafted = at(Stage::A3, false);
    assert!(drafted.iter().any(|f| f.prop == "P1-window" && f.reader == Some(Verdict::Valid) && f.full == Some(Verdict::Invalid)), "{drafted:?}");
    assert_eq!(at(Stage::Today, true), vec![]);
    assert_eq!(at(Stage::A3, true), vec![]);
}

/// Finding 32: the duty's right is per target, not per removal. X removes K from A; A writes D, D
/// writes E; X syncs A and D (so the removal is under D at once), Y syncs D alone (it reads D,
/// not A), V syncs E alone. X's node is destroyed right after removing; the stolen K writes E
/// through [A, D]; Y passes. Y holds the removal and read on E (through D), not on A: run by every
/// holder, its duty reaches E; by the remover alone (the outcome of the draft's "read or above on
/// the target t", which Y lacks), E's reader shows the write for good.
#[test]
fn f32_a_holder_reading_only_a_reached_thing_runs_the_duty_there() {
    let pw = roles_model::paths::World::new(&[(X, A), (Y, D), (V, E)]);
    let mut w = World::new(pw, &[A, D, E]);
    let (x, y, v, k) = (w.node(true, &[A, D]), w.node(true, &[D]), w.node(true, &[E]), w.node(false, &[]));
    w.write(x, |p| p.edge(X, 1, &[], A, K, Role::Write, &[]));
    w.write(y, |p| p.edge(Y, 1, &[], D, A, Role::Write, &[]));
    w.write(v, |p| p.edge(V, 1, &[], E, D, Role::Write, &[]));
    let r = w.write(x, |p| p.edge(X, 6, &[], A, K, Role::None, &[]));
    w.gone(x);
    let late = w.write(k, |p| p.content(K, 8, &[A, D], E));
    w.pass(y);
    let rule = lagged(Runners::AnyHolder);
    let (s, st) = steps(&w, &rule);
    assert!(s.window.iter().all(Vec::is_empty), "{:?}", s.window);
    assert!(st.entries[&E].contains(&r));
    assert_eq!(settled(&w, &rule, &st), vec![]);
    let f = lost_fails(&w, &lagged(Runners::Remover));
    assert!(f.iter().any(|f| f.prop == "P1-window" && f.sid == E && f.id == late && f.reader == Some(Verdict::Valid)), "{f:?}");
}

/// Finding 33: an act after a complete pass that no rule undoes (a drop of a body judged invalid)
/// is wrong while an earlier-ordered removal voiding the cut has not landed. Q, made admin of A by
/// X, removes K (6) listing nothing; K's write c on D (2) is cut by it; K's node is gone. Q's pass
/// logs its removal under D, whose reader drops c after a complete pass. X then removes Q at 5
/// (before Q's removal by key: it is void), so c is valid at the node holding everything; until
/// X's pass reaches D, D's reader holds the void removal alone and drops c, which nobody else holds.
#[test]
fn f33_a_drop_after_a_complete_pass_is_wrong_while_a_voiding_removal_lags() {
    let pw = roles_model::paths::World::new(&[(X, A), (Y, D)]);
    let mut w = World::new(pw, &[A, D]);
    let (x, q, y, k) = (w.node(true, &[A]), w.node(true, &[A]), w.node(true, &[D]), w.node(true, &[]));
    w.write(x, |p| p.edge(X, 1, &[], A, Q, Role::Admin, &[]));
    w.write(x, |p| p.edge(X, 1, &[], A, K, Role::Write, &[]));
    w.write(y, |p| p.edge(Y, 1, &[], D, A, Role::Write, &[]));
    let c = w.write(k, |p| p.content(K, 2, &[A], D));
    w.gone(k);
    w.write(q, |p| p.edge(Q, 6, &[], A, K, Role::None, &[]));
    w.pass(q);
    w.write(x, |p| p.edge(X, 5, &[], A, Q, Role::None, &[]));
    w.pass(x);
    let rule = lagged(Runners::AnyHolder);
    let (s, st) = steps(&w, &rule);
    let n = s.p8.len();
    assert!(s.p8[n - 3].is_empty(), "the drop agrees before the void removal: {:?}", s.p8[n - 3]);
    assert!(s.p8[n - 2].iter().any(|f| f.sid == D && f.id == c && f.reader == Some(Verdict::Invalid) && f.full == Some(Verdict::Valid)), "{:?}", s.p8[n - 2]);
    assert!(s.window.iter().all(Vec::is_empty), "{:?}", s.window);
    assert_eq!(settled(&w, &rule, &st), vec![]);
}

/// Finding 34: a removal's leaf for its own thing is read only by bodies on that thing, which sit
/// with the removal in every unit it is a body of, so it leaves with the last of them; kept with
/// the removal for good (`Home::All`), a thing's own removals keep every list they made.
#[test]
fn f34_a_removals_leaf_for_its_own_thing_leaves_with_what_it_reads() {
    let pw = roles_model::paths::World::new(&[(X, A)]);
    let mut w = World::new(pw, &[A]);
    let (x, k) = (w.node(true, &[A]), w.node(true, &[A]));
    w.write(x, |p| p.edge(X, 1, &[], A, K, Role::Write, &[]));
    let c = w.write(k, |p| p.content(K, 2, &[], A));
    w.write(x, |p| p.edge(X, 6, &[], A, K, Role::None, &[c]));
    for (home, left) in [(Home::Far, 0), (Home::All, 1)] {
        let rule = Rule { leaves_home: home, ..Rule::listed() };
        let mut st = w.run(&rule, |_| {});
        assert_eq!(st.leaves[&A].len(), 1);
        assert_eq!(w.verdicts(&w.reader(&rule, &st, A, &Set::new()), &Set::from([c]))[&c], Verdict::Valid);
        w.forget(&rule, &mut st, c);
        assert_eq!(st.leaves[&A].len(), left, "{home:?}");
        assert_eq!(w.p4(&rule, &st, false), vec![]);
    }
}
