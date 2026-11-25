//! Holder access (notes/holder-access-study.md, The model), held_model::closure::keys: the
//! holders held for keys, found from the things a node reads up, are the holders on the paths it
//! can act along.
use held_model::closure::keys::{for_keys, on_paths};
use held_model::closure::{keyless_of, Edges, Kind, NodeView, Role, Set, World, T};

/// A world of `n` independent things with `grants` written in order, the account thing 0.
fn world(n: usize, grants: &[(T, T, Role)]) -> World {
    let order: Vec<(T, T)> = grants.iter().map(|g| (g.0, g.1)).collect();
    World { kinds: vec![Kind::Independent; n], grants: grants.iter().map(|g| ((g.0, g.1), g.2)).collect(), keyless: keyless_of(&order), ..World::default() }
}

/// The account's node, its root strongs to `roots`.
fn node(roots: &[T]) -> (Edges, NodeView) {
    (roots.iter().map(|&r| (0, r)).collect(), NodeView { roots: Set::from([0]), own: Set::from([0]) })
}

fn set(x: &[T]) -> Set {
    x.iter().copied().collect()
}

// spec/sync-set.md §2 Held for keys: the account reads C directly and writes it through A and B,
// neither referenced: both are found from C up and held for keys.
#[test]
fn holders_named_up_from_a_read_thing_are_held_for_keys() {
    let (a, b, c) = (1, 2, 3);
    let w = world(4, &[(0, a, Role::Write), (a, b, Role::Admin), (b, c, Role::Admin), (0, c, Role::Read)]);
    let (e, n) = node(&[c]);
    assert_eq!(for_keys(&w, &e, &n), set(&[a, b]));
    // with no strong to C nothing is read, so nothing is found from it
    let (e, n) = node(&[]);
    assert_eq!(for_keys(&w, &e, &n), Set::new());
}

// A holder the node opens nothing of is on no path of its own; one it reads is held whole, not
// for keys; one with sync alone on a holder opens no key of it, and is found once that holder
// is read.
#[test]
fn only_holders_the_node_opens_and_does_not_read() {
    let (a, b, c, x) = (1, 2, 3, 4);
    let w = world(5, &[(0, c, Role::Read), (x, c, Role::Admin), (0, a, Role::Read), (a, c, Role::Write), (0, b, Role::Read), (b, a, Role::Sync)]);
    let (e, n) = node(&[c]);
    assert_eq!(for_keys(&w, &e, &n), set(&[a]), "X is a stranger's; B's sync on A gives no key of A");
    let (e, n) = node(&[c, a]);
    assert_eq!(for_keys(&w, &e, &n), set(&[b]), "A is read, held whole; B holds a role on it");
}

// The walk up from the read things finds exactly the holders on the paths the node can act along
// (`on_paths`): random worlds of five things, every strong set from the account's root.
#[test]
fn the_walk_up_is_the_holders_on_the_nodes_paths() {
    let mut seed: u64 = 0x9e3779b97f4a7c15;
    let mut next = |m: u64| {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        (seed >> 33) % m
    };
    let roles = [Role::Sync, Role::Read, Role::Write, Role::Admin];
    let mut held = 0;
    for _ in 0..4000 {
        let mut grants: Vec<(T, T, Role)> = Vec::new();
        for _ in 0..next(9) {
            let (h, t) = (next(5) as T, 1 + next(4) as T);
            if h != t && !grants.iter().any(|g| (g.0, g.1) == (h, t)) {
                grants.push((h, t, roles[next(4) as usize]));
            }
        }
        let w = world(5, &grants);
        let roots: Vec<T> = (1..5).filter(|_| next(2) == 0).collect();
        let (mut e, n) = node(&roots);
        for _ in 0..next(3) {
            e.insert((1 + next(4) as T, 1 + next(4) as T));
        }
        let got = for_keys(&w, &e, &n);
        held += got.len();
        assert_eq!(got, on_paths(&w, &e, &n), "{w:?} {e:?}");
    }
    assert!(held > 100, "the worlds hold holders for keys: {held}");
}
