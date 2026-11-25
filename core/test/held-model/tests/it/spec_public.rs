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


// Public pieces over time (held_model::closure::public_epochs): T strongs D, a dependent of the
// public thing X, and X rotates once after the public's grant. The rotation's open box is in the
// public's edge piece (spec/permissions.md §4 Key part: each role commit boxing it once set), so a
// reader served only T's sync ID holds X's current epoch and reads D's new commits; carrying only
// the commits writing the grant leaves it at the grant's epoch for good (X's bodies are not under
// T's sync ID: X is not in T's unit).
#[test]
fn a_public_things_rotation_reaches_a_reader_of_its_dependent() {
    use held_model::closure::public_epochs::{Ev, Pieces, World};
    let w = World { evs: vec![Ev::Grant, Ev::Rot], to_dep: true };
    assert_eq!(w.reader(Pieces::Edge, 2), (true, Some(1)));
    assert_eq!(w.reader(Pieces::GrantOnly, 2), (true, Some(0)));
    assert_eq!(w.breaks(Pieces::GrantOnly), (false, true));
    // T strongs X itself: X's rotation commits are bodies under T's sync ID, each opening with the
    // epoch before
    let w = World { evs: vec![Ev::Grant, Ev::Rot, Ev::Rot], to_dep: false };
    assert_eq!(w.breaks(Pieces::GrantOnly), (false, false));
}

// Control: the public's removal is carried while a strong reaches X, though the public no longer
// reads it; carried only while the public reads X, a reader that entered X keeps it.
#[test]
fn a_removal_of_the_public_is_carried_after_it() {
    use held_model::closure::public_epochs::{Ev, Pieces, World};
    let w = World { evs: vec![Ev::Grant, Ev::Remove], to_dep: false };
    assert_eq!(w.reader(Pieces::Edge, 2).0, false);
    assert_eq!(w.reader(Pieces::WhileRead, 2).0, true);
    assert!(w.breaks(Pieces::WhileRead).0);
}

// Every history of up to five grants, rotations and removals of the public on X, T strongs X or
// its dependent: the edge piece breaks neither property; each control breaks its own.
#[test]
fn public_epochs_explore() {
    use held_model::closure::public_epochs::{all, Pieces};
    let mut found = [(0usize, 0usize); 3];
    for w in all(5) {
        for (i, rule) in [Pieces::Edge, Pieces::GrantOnly, Pieces::WhileRead].into_iter().enumerate() {
            let (a, r) = w.breaks(rule);
            found[i].0 += a as usize;
            found[i].1 += r as usize;
        }
    }
    assert_eq!(found[0], (0, 0), "edge piece");
    assert!(found[1].1 > 0, "grant only: reads");
    assert!(found[2].0 > 0, "while read: agree");
}

// Who hears the public's grant changes (held_model::closure::public_epochs, Heard; spec/sync-opens.md
// §4, §6; spec/sync-set.md §5). P reads X by the public alone, offline while the public is removed
// (and, second, across a rotation boxing the public before it): a reader showing its superseded
// read secrets (lapsed) opens X toward it ended at once, served up to each epoch's supersession,
// so P walks to the removal within one sync and releases X. Control (`lapsed` off): nothing opens
// toward P and it keeps reading X for good.
#[test]
fn a_reader_by_the_public_offline_at_its_removal_hears_it() {
    use held_model::closure::public_epochs::{Ev, Heard, Step, World};
    for h in [[Step::X(Ev::Grant), Step::SyncP, Step::X(Ev::Remove), Step::X(Ev::Rot)], [Step::X(Ev::Grant), Step::SyncP, Step::X(Ev::Rot), Step::X(Ev::Remove)]] {
        assert_eq!(World::heard(&h, Heard::SPEC), Default::default(), "{h:?}");
        assert!(World::heard(&h, Heard { lapsed: false, ..Heard::SPEC }).agree, "newest only: P never hears");
    }
    // served whole on the lapsed secret, P gets the rotation written past the removal
    let h = [Step::X(Ev::Grant), Step::SyncP, Step::X(Ev::Remove), Step::X(Ev::Rot)];
    assert!(World::heard(&h, Heard { ended: false, ..Heard::SPEC }).sealed, "whole: served past the removal");
}

// P first syncs after the public's removal (a public link found later): it holds no epoch of X,
// hits no lapsed read secret and is served nothing. Control (`secret` off: the lapsed credential is
// the public entry, which any party hits): P is served X up to the removal.
#[test]
fn a_stranger_after_the_public_removal_is_served_nothing() {
    use held_model::closure::public_epochs::{Ev, Heard, Step, World};
    let h = [Step::X(Ev::Grant), Step::X(Ev::Rot), Step::X(Ev::Remove), Step::SyncP];
    assert_eq!(World::heard(&h, Heard::SPEC), Default::default());
    assert!(World::heard(&h, Heard { secret: false, ..Heard::SPEC }).stranger, "public entry: served the stranger");
}

// P offline across a rotation while the public still reads X: it tests the public entry while it
// holds the public's grant, and the answer's entry box gives the new epoch. Control (`tests` off)
// (tested only while redeeming): R shows its new read secret, P holds the old, and P reads nothing
// written since.
#[test]
fn a_reader_by_the_public_offline_at_a_rotation_takes_the_new_epoch() {
    use held_model::closure::public_epochs::{Ev, Heard, Step, World};
    let h = [Step::X(Ev::Grant), Step::SyncP, Step::X(Ev::Rot)];
    assert_eq!(World::heard(&h, Heard::SPEC), Default::default());
    assert!(World::heard(&h, Heard { tests: false, ..Heard::SPEC }).reads);
}

// K keeps X unread when X is made public: its head lists the public entry, and it reads X by it as
// a redeemer does. Control (`store` off): no commit it is served opens, and it never counts X public.
#[test]
fn a_sync_holder_hears_the_public_granted() {
    use held_model::closure::public_epochs::{Ev, Heard, Step, World};
    let h = [Step::SyncK, Step::X(Ev::Grant)];
    assert_eq!(World::heard(&h, Heard::SPEC), Default::default());
    assert!(World::heard(&h, Heard { store: false, ..Heard::SPEC }).agree);
}

// K reads X by its head's public entry, then opens the public's removal and drops its read epochs:
// it keeps X unread at the head it held while reading, which lists the public but bears a sync
// epoch the removal superseded, so it takes nothing and waits for R's Register. Control (`current`
// off): it takes that head's box again, reads X, opens the removal again and drops: for good
// (spec/sync-opens.md §4 Admissible).
#[test]
fn a_sync_holder_settles_after_the_public_removed() {
    use held_model::closure::public_epochs::{Ev, Heard, Step, World};
    let h = [Step::SyncK, Step::X(Ev::Grant), Step::SyncK, Step::X(Ev::Remove)];
    assert_eq!(World::heard(&h, Heard::SPEC), Default::default());
    assert!(World::heard(&h, Heard { current: false, ..Heard::SPEC }).settles, "stale head: K reads again");
}

// Every history of up to six events and syncs: the spec breaks no property; each control breaks
// its own.
#[test]
fn heard_explore() {
    use held_model::closure::public_epochs::{histories, Heard, World};
    let rules = [
        ("spec", Heard::SPEC),
        ("newest", Heard { lapsed: false, ..Heard::SPEC }),
        ("whole", Heard { ended: false, ..Heard::SPEC }),
        ("public entry", Heard { secret: false, ..Heard::SPEC }),
        ("redeem only", Heard { tests: false, ..Heard::SPEC }),
        ("store blind", Heard { store: false, ..Heard::SPEC }),
        ("stale head", Heard { current: false, ..Heard::SPEC }),
    ];
    let mut found = [(0usize, 0usize, 0usize, 0usize, 0usize); 7];
    for h in histories(6) {
        for (i, &(_, rule)) in rules.iter().enumerate() {
            let b = World::heard(&h, rule);
            found[i].0 += b.agree as usize;
            found[i].1 += b.reads as usize;
            found[i].2 += b.sealed as usize;
            found[i].3 += b.stranger as usize;
            found[i].4 += b.settles as usize;
        }
    }
    assert_eq!(found[0], (0, 0, 0, 0, 0), "spec");
    assert!(found[1].0 > 0, "newest: agree");
    assert!(found[2].2 > 0, "whole: sealed");
    assert!(found[3].3 > 0, "public entry: stranger");
    assert!(found[4].1 > 0, "redeem only: reads");
    assert!(found[5].0 > 0, "store blind: agree");
    assert!(found[6].4 > 0, "stale head: settles");
}
