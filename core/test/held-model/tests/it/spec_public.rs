//! Public things in a sync unit (held_model::closure::public; spec/sync-set.md §2 T's keys open,
//! Public pieces; spec/permissions.md §1 The public). Findings: notes/public-and-cards-brief.md, Models.
use held_model::closure::public::{random, Net, Rule};
use held_model::closure::{Kind, Role, Set, World, T};

const T0: T = 0;
const P: T = 1;
const H: T = 2;
const X: T = 3;
const D: T = 4;

fn set(x: &[T]) -> Set {
    x.iter().copied().collect()
}

/// T strongs a profile P (public read) and X; P strongs its dependent D; the public reads H, which
/// reads X.
fn world() -> Net {
    use Kind::*;
    let mut net = Net { w: World { kinds: vec![Independent, Independent, Independent, Independent, Dependent(P)], ..World::default() }, t: T0, ..Net::default() };
    net.public.insert(P, Role::Read);
    net.public.insert(H, Role::Read);
    net.w.grants.insert((H, X), Role::Read);
    net.strongs = [(T0, P), (T0, X), (P, D)].into_iter().collect();
    net
}

/// Whether a rule breaks a property: `agree` (a reader served only T's sync ID computes the unit
/// the logger logged) or `owed` (every thing the public reads that a strong of the unit reaches is
/// in it).
fn breaks(net: &Net, rule: Rule) -> (bool, bool) {
    let logged = net.logged(rule);
    (net.read(rule) != logged, !net.owed(rule).is_subset(&logged))
}

// spec/sync-set.md §2 (T's keys open; Public pieces): T's unit carries P and its dependent D whole,
// and a reader served only T's sync ID by a store computes the same unit; X, read by the public only
// through H, is not carried.
#[test]
fn a_public_thing_a_strong_reaches_is_carried_and_agreed() {
    let net = world();
    assert_eq!(net.logged(Rule::SPEC), set(&[T0, P, D]));
    assert_eq!(net.read(Rule::SPEC), set(&[T0, P, D]));
}

// Control: without the clause the profile is not carried, so a reader served by a store keeping T
// unread never gets it.
#[test]
fn without_the_clause_the_profile_is_not_carried() {
    let rule = Rule { clause: false, ..Rule::SPEC };
    assert_eq!(breaks(&world(), rule), (false, true));
}

// Control: without the public pieces a reader knows the public reads P only from P's own bodies,
// which T's sync ID carries only once P is in the unit: founded, it never enters P.
#[test]
fn without_pieces_the_reader_never_enters_the_profile() {
    let rule = Rule { pieces: false, ..Rule::SPEC };
    let net = world();
    assert_eq!(net.read(rule), set(&[T0]));
    assert_eq!(breaks(&net, rule), (true, false));
}

// Control: counting the public's read through a holder (public read on H, H read on X) makes the
// logger carry X, which no reader of T can found: H's grant on X is in X's bodies or H's key part,
// neither under T's sync ID.
#[test]
fn counting_the_public_through_holders_splits_logger_and_reader() {
    let rule = Rule { chains: true, ..Rule::SPEC };
    let net = world();
    assert_eq!(net.logged(rule), set(&[T0, P, D, X]));
    assert!(!net.read(rule).contains(&X));
    assert!(breaks(&net, rule).0);
}

// Control: a strong to a dependent of a public thing, with pieces only on the independent things
// strongs reach: the logger carries the dependent (the public opens its independent), the reader
// has nothing telling it so.
#[test]
fn a_strong_to_a_public_things_dependent_needs_its_independents_piece() {
    let mut net = world();
    net.strongs = [(T0, D)].into_iter().collect();
    assert_eq!(net.read(Rule::SPEC), set(&[T0, D]));
    let rule = Rule { exact: true, ..Rule::SPEC };
    assert_eq!(net.read(rule), set(&[T0]));
    assert!(breaks(&net, rule).0);
}

// Random worlds: the spec breaks neither property; each control breaks its own.
#[test]
fn public_explore() {
    let rules = [
        ("spec", Rule::SPEC),
        ("no clause", Rule { clause: false, ..Rule::SPEC }),
        ("no pieces", Rule { pieces: false, ..Rule::SPEC }),
        ("chains", Rule { chains: true, ..Rule::SPEC }),
        ("exact", Rule { exact: true, ..Rule::SPEC }),
    ];
    let mut found = [(0usize, 0usize); 5];
    for seed in 0..5_000 {
        let net = random(seed, 6);
        for (i, &(_, rule)) in rules.iter().enumerate() {
            let (a, o) = breaks(&net, rule);
            found[i].0 += a as usize;
            found[i].1 += o as usize;
        }
    }
    assert_eq!(found[0], (0, 0), "spec");
    assert!(found[1].1 > 0, "no clause: owed");
    assert!(found[2].0 > 0, "no pieces: agree");
    assert!(found[3].0 > 0, "chains: agree");
    assert!(found[4].0 > 0, "exact: agree");
}

