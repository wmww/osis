//! Delete-key steps (spec/permissions.md §4 Evidence of a commit; spec/crypto.md §7 Checked keys):
//! a part listing a level-1 or level-3 key for its delete base B brings every held `sync.0` write
//! on B recording a step on the path from B's genesis to a step bearing that key, whatever order
//! they arrive in. held-model has no steps (notes/a2-spec/README.md Open 3), so these are hand
//! worlds only; each step incremental equals from scratch.
use osis_engine::evidence::{Config, CopyId, Del, Evidence, Kind, Level, Part, Reason, Step};
use std::collections::BTreeSet;

type E = Evidence<u32, u16, u32>;
type Copies = BTreeSet<CopyId<u32, u16>>;

const X: u16 = 1;
const B: u16 = 50;
const D: u16 = 100;
/// A thing outside D's unit whose part on it lists a key of B.
const O: u16 = 60;

fn req(ev: &E) -> Copies {
    ev.check().unwrap();
    ev.required(&D).unwrap().keys().copied().collect()
}

fn d_unit() -> E {
    let mut ev = E::new(Config::default());
    ev.add_sid(D, D);
    ev.join(&D, D);
    ev
}

/// Step `id` with parent `prev`, bearing delete key `10 + id` and write key `20 + id`.
fn step(id: u32, prev: Option<u32>) -> Step<u32> {
    Step { id, prev, delete: 10 + id, write: 20 + id }
}

/// A `sync.0` write on B recording `steps`, signed by B's mint admin.
fn sync0(steps: Vec<Step<u32>>) -> Vec<Part<u16, u32>> {
    vec![Part { steps, ..Part::new(Kind::Content, Some(vec![(X, B)])) }]
}

/// A content part on `on` listing `key` at `level` for base B.
fn listing(on: u16, level: Level, key: u32) -> Vec<Part<u16, u32>> {
    vec![Part { dels: vec![Del { base: B, level, key }], ..Part::new(Kind::Content, Some(vec![(X, on)])) }]
}

/// B's steps: genesis 1, then 2, then 3; 4 a sibling of 2. A body of D listing step 3's delete key
/// brings the writes recording 1, 2 and 3, never the sibling's, in whichever order they arrive.
#[test]
fn a_listed_key_brings_the_steps_from_genesis_to_it_spec_permissions_4() {
    let writes = [(1, vec![step(1, None)]), (2, vec![step(2, Some(1))]), (3, vec![step(3, Some(2))]), (4, vec![step(4, Some(1))])];
    for reversed in [false, true] {
        let mut ev = d_unit();
        ev.add((9, D), listing(D, Level::Admin, 13));
        let mut order: Vec<_> = writes.iter().collect();
        if reversed {
            order.reverse();
        }
        for (c, steps) in order {
            ev.add((*c, B), sync0(steps.clone()));
            req(&ev);
        }
        assert_eq!(req(&ev), Copies::from([(1, B), (2, B), (3, B)]), "reversed {reversed}");
        assert_eq!(ev.required(&D).unwrap().get(&(2, B)), Some(&Reason::Step(B, 2)));
        // the write key (level 3) of step 2: genesis and 2
        let mut ev3 = d_unit();
        for (c, steps) in &writes {
            ev3.add((*c, B), sync0(steps.clone()));
        }
        ev3.add((9, D), listing(D, Level::Writer, 22));
        assert_eq!(req(&ev3), Copies::from([(1, B), (2, B)]));
    }
}

/// A key bearing no held step brings nothing until its step arrives; a step's write forgotten
/// leaves, and the steps above it stay only as far as the held chain reaches; the last body
/// listing the key gone, every step write leaves.
#[test]
fn steps_follow_what_is_held_spec_permissions_4() {
    let mut ev = d_unit();
    ev.add((1, B), sync0(vec![step(1, None)]));
    ev.add((9, D), listing(D, Level::Admin, 12));
    assert_eq!(req(&ev), Copies::new());
    // one write recording two steps
    ev.add((2, B), sync0(vec![step(2, Some(1)), step(3, Some(2))]));
    assert_eq!(req(&ev), Copies::from([(1, B), (2, B)]));
    ev.forget(&(1, B));
    assert_eq!(req(&ev), Copies::from([(2, B)]));
    ev.add((1, B), sync0(vec![step(1, None)]));
    assert_eq!(req(&ev), Copies::from([(1, B), (2, B)]));
    ev.forget(&(9, D));
    assert_eq!(req(&ev), Copies::new());
}

/// A copy outside the unit listing a key brings its steps too (the evidence of the evidence): K's
/// write on D through [O] brings O's writes on (K, O), one of which lists a key of B.
#[test]
fn a_member_listing_a_key_brings_its_steps_spec_permissions_4() {
    const K: u16 = 2;
    let mut ev = d_unit();
    ev.add((1, B), sync0(vec![step(1, None)]));
    let grant = Part { dels: vec![Del { base: B, level: Level::Admin, key: 11 }], ..Part::new(Kind::Write(osis_engine::evidence::Write { holder: K, gives_read: true }), Some(vec![(X, O)])) };
    ev.add((5, O), vec![grant]);
    assert_eq!(req(&ev), Copies::new());
    ev.add((9, D), vec![Part::new(Kind::Content, Some(vec![(K, O), (O, D)]))]);
    assert_eq!(req(&ev), Copies::from([(5, O), (1, B)]));
}

/// Count: a body listing a key other bodies already list walks no step, the same at a chain of n
/// and 10n steps.
#[test]
fn a_body_listing_a_placed_key_walks_no_step() {
    let at = |n: u32| {
        let mut ev = d_unit();
        ev.add((1, B), sync0((1..=n).map(|i| step(i, (i > 1).then(|| i - 1))).collect()));
        ev.add((1000, D), listing(D, Level::Admin, 10 + n));
        assert_eq!(req(&ev).len(), 1);
        let before = ev.counts();
        ev.add((1001, D), listing(D, Level::Admin, 10 + n));
        ev.counts() - before
    };
    let (a, b) = (at(10), at(100));
    assert_eq!(a, b);
    assert_eq!((a.steps, a.closes), (0, 0), "{a:?}");
}
