//! Holder actors (spec/crypto.md §4): the keyset a box to a holder actor is sealed to (Seal),
//! when such a box is stale (Stale), and key access over actor grants (no key cycles; tainted
//! keysets and the knowing re-key). Pure functions of what a node holds; the engine gathers
//! their inputs. Nothing here looks at departures from a holder actor or below it: those reach
//! its boxers only as its new keysets.

use crate::epoch::newest_of;
use osis_perm::chain::{ancestors, joins};
use osis_base::Tid;
use osis_crypto::Epoch;
use std::collections::{BTreeMap, BTreeSet};

/// The keysets of one role of a holder actor that a node holds (spec/crypto.md §4, held keyset).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Keysets {
    /// Each held valid keyset, with the epochs its supersedes list names.
    pub valid: BTreeMap<Epoch, BTreeSet<Epoch>>,
    /// The held invalid keysets: every body the node holds writing one is invalid.
    pub invalid: BTreeSet<Epoch>,
    /// The key of each held valid keyset's earliest held valid body, where known (an account's
    /// chain is whole: none).
    pub since: BTreeMap<Epoch, osis_perm::Point>,
}

impl Keysets {
    /// Whether held valid keyset `k` descends from `j`: its list names `j`, or names a held valid
    /// keyset that descends from `j`. Invalid and unheld keysets pass nothing on: a removed
    /// admin's forgery lists every keyset, so descent through it would prove nothing.
    pub fn descends(&self, k: &Epoch, j: &Epoch) -> bool {
        ancestors(*k, |x| self.parents(x)).contains(j)
    }

    /// Whether held valid keyset `k` is past `j` (Left out): it descends from `j`, or, while no
    /// held valid keyset descends from `j` (the chain runs through a keyset not held valid, which
    /// no later body mends), it is ordered after `j` (judged by order, as an epoch whose secret
    /// the node lacks is).
    pub fn past(&self, k: &Epoch, j: &Epoch) -> bool {
        if self.descends(k, j) {
            return true;
        }
        let after = matches!((self.since.get(k), self.since.get(j)), (Some(a), Some(b)) if a > b);
        after && !self.valid.keys().any(|x| self.descends(x, j))
    }

    /// The epochs held valid keyset `x` lists (none when it is not held valid).
    fn parents(&self, x: Epoch) -> Vec<Epoch> {
        self.valid.get(&x).map(|l| l.iter().copied().collect()).unwrap_or_default()
    }
}

/// What Seal (rule 1) gives for one role of holder actor M (`seal_keyset`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Seal {
    /// Box M at this keyset.
    At(Epoch),
    /// M is left out of the role and the roles above, re-sealed once a keyset exists.
    Out,
    /// The anchors fork: no held valid keyset is or descends from each of them, tainted or not.
    /// No rotation, grant or re-seal of A boxing M is made until one is (M's merge).
    Wait,
}

/// Seal (rule 1): the keyset a rotation, grant or re-seal of A seals holder actor M to, for one
/// role: the newest held valid keyset of M that is not `tainted`, is or descends from each anchor
/// (the epochs of M the boxes to M at A's current epochs name, those held valid counting), and
/// descends from each keyset `left_out` names (the keysets of M A's current keysets record M was
/// left out at, those held valid counting): the rule an account's signing chain opens its epochs
/// by (`osis_perm::chain`). With none: `Wait` when no held valid keyset, tainted or not, is or
/// descends from each anchor (they fork), else `Out`.
///
/// Invariant: A's boxes to M move only to a keyset whose rotator had each anchor current, so a
/// keyset of M made without the knowledge an anchor was made with (a fork from an older keyset,
/// made beside it, perhaps winning the (n, nonce) order) never replaces it: a party removed from
/// M by the anchor's rotation never reads A's content through A's next epoch's history box. M's
/// own merge (`covers::merge_due`) moves M onto a keyset that lists the fork. Leaving M out of a
/// rotation of A over forked anchors would drop them: the next re-seal, finding no box to M at
/// A's current epochs, would seal M at its newest keyset, perhaps that fork (a Depth0.tla
/// counterexample). A tainted keyset leaves M out instead: its re-key descends from it, and waiting
/// would hold A's removals while a grant stays hidden from M's admins.
///
/// Invariant (left out): a keyset a knowing rotator of A left M out at, because a departed party
/// opens it as that rotator judged, is never sealed to by any node, nor any keyset that does not
/// descend from it (a rotation of M made knowing it, which supersedes it): a co-writer of A that
/// cannot judge that departure itself never re-seals M where the knowing node left it out
/// (Depth0.tla `D0_readers_g2_mark`). A left-out keyset never makes Seal wait: M stays out until
/// its rotation reaches the sealer. Where no held valid keyset descends from a left-out one (M's
/// chain runs through a keyset this node holds invalid or never got), a keyset ordered after it
/// is past it (`Keysets::past`): else no keyset could ever be, and M would be out for good.
pub fn seal_keyset(keysets: &Keysets, anchors: &BTreeSet<Epoch>, tainted: &BTreeSet<Epoch>, left_out: &BTreeSet<Epoch>) -> Seal {
    let anchors: Vec<&Epoch> = anchors.iter().filter(|q| keysets.valid.contains_key(q)).collect();
    let joined = |k: &&Epoch| joins(**k, anchors.iter().copied(), |x| keysets.parents(x));
    let past = |k: &&Epoch| left_out.iter().filter(|q| keysets.valid.contains_key(q)).all(|q| keysets.past(k, q));
    match newest_of(keysets.valid.keys().filter(|k| !tainted.contains(k)).filter(joined).filter(past)) {
        Some(k) => Seal::At(k),
        None if keysets.valid.keys().any(|k| joined(&k)) || anchors.is_empty() => Seal::Out,
        None => Seal::Wait,
    }
}

/// Stale (rule 2): whether a box of A to holder actor M naming M's epoch `k` is stale: `k` is
/// held invalid, `tainted`, or named by the supersedes list of a held valid keyset of M. A node
/// that may rotate A does not encrypt under an epoch of A with a stale box; it rotates first.
///
/// Invariant: once M's keyset rotated knowing a removal (it lists the keyset the removed party
/// opens), a removed admin's forgery is judged invalid, or a key cycle's grant is held, A's
/// writer holding that writes nothing under an epoch the removed party reaches. A keyset the
/// node holds nothing of is not stale: a co-writer may have sealed to a newer one not received
/// yet, and rotating onto an older one would move A off it (a staleness by "any newer keyset"
/// would move A onto an ignorant fork).
pub fn stale(k: &Epoch, keysets: &Keysets, tainted: &BTreeSet<Epoch>) -> bool {
    keysets.invalid.contains(k) || tainted.contains(k) || keysets.valid.values().any(|l| l.contains(k))
}

/// The epochs at which `boxes` (an actor's held box keys of one role, as (holder, epoch)) box a
/// holder whose grant on it is keyless (`no_access`): for a holder actor M, its tainted keysets
/// (rule 4b); for the actor A a node may rotate, the current epochs it re-keys (the knowing
/// re-key, rule 4).
///
/// Invariant (4b, with the knowing re-key: one predicate): a box to a holder with a keyless grant
/// is a key cycle a sealer lacking the earlier grant formed; a node holding that grant never
/// seals to such a keyset nor encrypts under an epoch boxing one, so a party removed from an
/// actor on the cycle reads none of its new content once the writer holds the grants and the
/// cycle's commits. While a grant stays hidden from a sealer, its re-seals re-form the cycle and
/// each costs the knowing side one more rotation.
pub fn boxing_keyless(boxes: impl IntoIterator<Item = (Tid, Epoch)>, no_access: impl Fn(&Tid) -> bool) -> BTreeSet<Epoch> {
    boxes.into_iter().filter(|(h, _)| no_access(h)).map(|(_, e)| e).collect()
}

/// An actor grant (spec/crypto.md §4, key access): `holder`'s standing on `target`, at `order`
/// in the agreed order (ties go by target, then holder).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Grant<K> {
    pub order: K,
    pub target: Tid,
    pub holder: Tid,
}

/// Key access (rule 4): the keyless grants, as (target, holder), among `grants` (those a node
/// holds). In the agreed order a grant gives key access unless its target's key already yields its holder's over the grants given key access
/// before it (the grant would close a cycle): the earlier grant wins.
///
/// Invariant: the grants given key access hold no cycle, so no actor's key yields its own
/// through others (a party removed from X reads nothing of X's new content through Y), and the
/// greedy choice keeps every grant that closes no cycle. Only a grant inside a strongly
/// connected component of all the grants can close one (any path between two of its actors stays
/// inside it), so only those are judged one by one: a graph without cycles costs one pass.
pub fn key_access<K: Ord>(mut grants: Vec<Grant<K>>) -> BTreeSet<(Tid, Tid)> {
    grants.sort_by(|a, b| (&a.order, a.target, a.holder).cmp(&(&b.order, b.target, b.holder)));
    let comp = components(grants.iter().map(|g| (g.holder, g.target)));
    let mut keyed: BTreeMap<Tid, Vec<Tid>> = BTreeMap::new();
    let mut out = BTreeSet::new();
    for g in grants {
        if comp.get(&g.holder) == comp.get(&g.target) && yields(&keyed, g.target, g.holder) {
            out.insert((g.target, g.holder));
        } else {
            keyed.entry(g.holder).or_default().push(g.target);
        }
    }
    out
}

/// Whether `h`'s key yields `a`'s over `keyed` (holder -> targets with key access): `h` is `a`,
/// or holds a keyed grant on an actor whose key yields `a`'s.
fn yields(keyed: &BTreeMap<Tid, Vec<Tid>>, h: Tid, a: Tid) -> bool {
    let mut seen = BTreeSet::from([h]);
    let mut work = vec![h];
    while let Some(x) = work.pop() {
        if x == a {
            return true;
        }
        work.extend(keyed.get(&x).into_iter().flatten().filter(|t| seen.insert(**t)));
    }
    false
}

/// The strongly connected component of each actor of the directed graph `edges` (from, to), as
/// a component number (Kosaraju, iterative: chains have no depth bound).
fn components(edges: impl Iterator<Item = (Tid, Tid)>) -> BTreeMap<Tid, usize> {
    let mut out_: BTreeMap<Tid, Vec<Tid>> = BTreeMap::new();
    let mut in_: BTreeMap<Tid, Vec<Tid>> = BTreeMap::new();
    for (a, b) in edges {
        out_.entry(a).or_default().push(b);
        out_.entry(b).or_default();
        in_.entry(b).or_default().push(a);
        in_.entry(a).or_default();
    }
    // finish order on the forward graph
    let mut order = Vec::with_capacity(out_.len());
    let mut seen = BTreeSet::new();
    for s in out_.keys() {
        if !seen.insert(*s) {
            continue;
        }
        let mut stack = vec![(*s, 0usize)];
        while let Some((v, i)) = stack.last_mut() {
            let next = out_.get(v).and_then(|n| n.get(*i)).copied();
            *i += 1;
            match next {
                Some(w) => {
                    if seen.insert(w) {
                        stack.push((w, 0));
                    }
                }
                None => {
                    order.push(*v);
                    stack.pop();
                }
            }
        }
    }
    // components on the reverse graph, latest finish first
    let mut comp = BTreeMap::new();
    for (c, s) in order.iter().rev().enumerate() {
        if comp.contains_key(s) {
            continue;
        }
        comp.insert(*s, c);
        let mut work = vec![*s];
        while let Some(v) = work.pop() {
            for w in in_.get(&v).into_iter().flatten() {
                if !comp.contains_key(w) {
                    comp.insert(*w, c);
                    work.push(*w);
                }
            }
        }
    }
    comp
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(i: u8) -> Tid {
        Tid::from_bytes([i; 15])
    }

    fn ep(n: u64, k: u8) -> Epoch {
        Epoch::new(n, [k; 32]).unwrap()
    }

    fn g(order: u32, target: u8, holder: u8) -> Grant<u32> {
        Grant { order, target: t(target), holder: t(holder) }
    }

    fn set(xs: &[Epoch]) -> BTreeSet<Epoch> {
        xs.iter().copied().collect()
    }

    /// M's keysets: 1 at n 1; the knowing rotation 2 (n 2) listing 1; an ignorant fork 3 (n 2,
    /// lower nonce: newer) listing 1 only through the pre-removal keyset 0 (n 1, listing nothing).
    fn fork_world() -> Keysets {
        let mut k = Keysets::default();
        k.valid.insert(ep(1, 1), set(&[]));
        k.valid.insert(ep(2, 9), set(&[ep(1, 1)]));
        k.valid.insert(ep(2, 0), set(&[ep(1, 1)]));
        k
    }

    // spec/crypto.md §4 (Seal): the newest held valid keyset that is or descends from each
    // anchor; with no anchor, the newest; none: wait while the anchors fork, else left out.
    #[test]
    fn seal_keyset_anchored() {
        let mut k = Keysets::default();
        assert_eq!(seal_keyset(&k, &set(&[]), &set(&[]), &set(&[])), Seal::Out, "no keyset held: left out");
        k.valid.insert(ep(1, 1), set(&[]));
        k.valid.insert(ep(2, 5), set(&[ep(1, 1)]));
        // the knowing keyset kk (3) lists 2; the ignorant fork f (3, lower nonce: newer) lists 1
        k.valid.insert(ep(3, 7), set(&[ep(2, 5)]));
        k.valid.insert(ep(3, 0), set(&[ep(1, 1)]));
        assert_eq!(seal_keyset(&k, &set(&[]), &set(&[]), &set(&[])), Seal::At(ep(3, 0)), "no anchor: the newest");
        assert_eq!(seal_keyset(&k, &set(&[ep(3, 7)]), &set(&[]), &set(&[])), Seal::At(ep(3, 7)), "anchored on kk, f does not descend from it");
        assert_eq!(seal_keyset(&k, &set(&[ep(2, 5)]), &set(&[]), &set(&[])), Seal::At(ep(3, 7)), "f does not descend from 2");
        assert_eq!(seal_keyset(&k, &set(&[ep(1, 1)]), &set(&[]), &set(&[])), Seal::At(ep(3, 0)), "both descend from 1");
        // the merge lists both: it descends from every anchor
        k.valid.insert(ep(4, 3), set(&[ep(3, 7), ep(3, 0)]));
        assert_eq!(seal_keyset(&k, &set(&[ep(3, 7)]), &set(&[]), &set(&[])), Seal::At(ep(4, 3)));
        // two anchors on two forks: only a keyset descending from both
        assert_eq!(seal_keyset(&k, &set(&[ep(3, 7), ep(3, 0)]), &set(&[]), &set(&[])), Seal::At(ep(4, 3)));
        k.valid.remove(&ep(4, 3));
        assert_eq!(seal_keyset(&k, &set(&[ep(3, 7), ep(3, 0)]), &set(&[]), &set(&[])), Seal::Wait, "no keyset descends from both forks: wait for the merge");
        // a tainted keyset is never sealed to
        assert_eq!(seal_keyset(&k, &set(&[ep(2, 5)]), &set(&[ep(3, 7)]), &set(&[])), Seal::At(ep(2, 5)), "the anchor itself");
        assert_eq!(seal_keyset(&k, &set(&[ep(2, 5)]), &set(&[ep(3, 7), ep(2, 5)]), &set(&[])), Seal::Out, "everything it anchors to tainted: left out until the re-key");
        assert_eq!(seal_keyset(&k, &set(&[]), &set(&[ep(1, 1), ep(2, 5), ep(3, 7), ep(3, 0)]), &set(&[])), Seal::Out, "no anchor, every keyset tainted");
        assert_eq!(seal_keyset(&k, &set(&[]), &set(&[ep(3, 0)]), &set(&[])), Seal::At(ep(3, 7)));
        // an anchor not held valid does not count
        assert_eq!(seal_keyset(&k, &set(&[ep(9, 9)]), &set(&[]), &set(&[])), Seal::At(ep(3, 0)));
    }

    // spec/crypto.md §4 (Seal, Left out): a keyset A's current keysets record M was left out at
    // is not sealed to, nor any keyset not descending from it; none: left out, never a wait; a
    // left-out keyset not held valid does not count.
    #[test]
    fn seal_keyset_past_left_out() {
        let mut k = Keysets::default();
        k.valid.insert(ep(1, 1), set(&[]));
        k.valid.insert(ep(2, 5), set(&[ep(1, 1)]));
        k.valid.insert(ep(2, 0), set(&[ep(1, 1)]));
        assert_eq!(seal_keyset(&k, &set(&[ep(1, 1)]), &set(&[]), &set(&[ep(2, 5)])), Seal::Out, "only 2.5 is past 1.1, and 2.5 is left out");
        assert_eq!(seal_keyset(&k, &set(&[]), &set(&[]), &set(&[ep(1, 1)])), Seal::At(ep(2, 0)), "past 1.1: the newest");
        k.valid.insert(ep(3, 2), set(&[ep(2, 5)]));
        assert_eq!(seal_keyset(&k, &set(&[ep(1, 1)]), &set(&[]), &set(&[ep(2, 5)])), Seal::At(ep(3, 2)), "M's rotation knowing it");
        assert_eq!(seal_keyset(&k, &set(&[ep(1, 1)]), &set(&[]), &set(&[ep(2, 5), ep(2, 0)])), Seal::Out, "nothing past both");
        assert_eq!(seal_keyset(&k, &set(&[ep(1, 1)]), &set(&[]), &set(&[ep(2, 5), ep(9, 9)])), Seal::At(ep(3, 2)), "an unheld one does not count");
    }

    // spec/crypto.md §4 (Left out): where no held valid keyset descends from the left-out one (M's
    // chain runs through a keyset not held valid), a keyset ordered after it is past it; while
    // one descends, only descent counts.
    #[test]
    fn left_out_past_by_order_where_the_chain_is_broken() {
        let at = |ts: u64| osis_perm::Point { ts: osis_base::Ts::from_u64(ts).unwrap(), node: Tid::from_bytes([0; 15]), commit: osis_base::CommitId([0; 32]) };
        let mut k = Keysets::default();
        k.valid.insert(ep(1, 1), set(&[]));
        k.valid.insert(ep(4, 2), set(&[ep(3, 3)]));
        k.since.extend([(ep(1, 1), at(1 << 20)), (ep(4, 2), at(4 << 20))]);
        assert_eq!(seal_keyset(&k, &set(&[]), &set(&[]), &set(&[ep(1, 1)])), Seal::At(ep(4, 2)), "4.2 lists 3.3, held by nothing here: ordered after 1.1");
        k.valid.insert(ep(2, 0), set(&[ep(1, 1)]));
        k.since.insert(ep(2, 0), at(2 << 20));
        assert_eq!(seal_keyset(&k, &set(&[]), &set(&[]), &set(&[ep(1, 1)])), Seal::At(ep(2, 0)), "a descendant held: descent only");
    }

    // spec/crypto.md §4 (Descends): through held valid keysets only; a forged keyset (invalid)
    // lists everything and passes nothing on.
    #[test]
    fn descent_skips_invalid_keysets() {
        let mut k = fork_world();
        // a forgery listing the knowing keyset, invalid here; an ignorant fork made from it
        k.invalid.insert(ep(3, 4));
        k.valid.insert(ep(4, 0), set(&[ep(3, 4)]));
        assert!(!k.descends(&ep(4, 0), &ep(2, 9)), "through the forgery: no descent");
        assert_eq!(seal_keyset(&k, &set(&[ep(2, 9)]), &set(&[]), &set(&[])), Seal::At(ep(2, 9)));
        // the same forgery held valid (its forger's removal unknown here) passes descent on
        k.invalid.clear();
        k.valid.insert(ep(3, 4), set(&[ep(2, 9), ep(2, 0)]));
        assert!(k.descends(&ep(4, 0), &ep(2, 9)));
        assert!(!k.descends(&ep(2, 0), &ep(2, 9)));
        assert!(!k.descends(&ep(9, 9), &ep(1, 1)), "an unheld keyset descends from nothing");
    }

    // spec/crypto.md §4 (Stale): invalid, tainted or listed by a held valid keyset; an unknown
    // keyset, or one only newer than another, is not.
    #[test]
    fn stale_keysets() {
        let mut k = fork_world();
        let none = set(&[]);
        assert!(stale(&ep(1, 1), &k, &none), "listed by both rotations");
        assert!(!stale(&ep(2, 9), &k, &none), "a fork is not stale for a newer fork beside it");
        assert!(!stale(&ep(7, 7), &k, &none), "unknown");
        assert!(stale(&ep(2, 9), &k, &set(&[ep(2, 9)])), "tainted");
        k.invalid.insert(ep(5, 5));
        assert!(stale(&ep(5, 5), &k, &none), "held invalid");
        // listed whether or not the listed keyset is held
        k.valid.insert(ep(3, 3), set(&[ep(2, 9), ep(2, 8)]));
        assert!(stale(&ep(2, 8), &k, &none));
    }

    // spec/crypto.md §4 (Tainted, knowing re-key): epochs boxing a holder with a keyless grant.
    #[test]
    fn boxing_keyless_epochs() {
        let boxes = vec![(t(1), ep(1, 1)), (t(2), ep(1, 1)), (t(2), ep(2, 2)), (t(3), ep(3, 3))];
        assert_eq!(boxing_keyless(boxes.clone(), |h| *h == t(2)), set(&[ep(1, 1), ep(2, 2)]));
        assert!(boxing_keyless(boxes, |_| false).is_empty());
    }

    // spec/crypto.md §4 (Key access): the later grant of a 2-cycle is keyless, whichever comes
    // first; grants outside cycles keep key access; the first admin's standing wins.
    #[test]
    fn key_access_two_cycle() {
        // edges (target, holder): Y holds X first, X holds Y later
        let k = key_access(vec![g(1, 1, 2), g(2, 2, 1)]);
        assert_eq!(k, BTreeSet::from([(t(2), t(1))]));
        let k = key_access(vec![g(2, 1, 2), g(1, 2, 1)]);
        assert_eq!(k, BTreeSet::from([(t(1), t(2))]), "the other order");
        // a hidden earlier grant: the later one alone has key access
        assert!(key_access(vec![g(2, 2, 1)]).is_empty());
        // an actor holding a role on itself
        assert_eq!(key_access(vec![g(1, 3, 3)]), BTreeSet::from([(t(3), t(3))]));
        // ties by target, then holder
        assert_eq!(key_access(vec![g(1, 2, 1), g(1, 1, 2)]), BTreeSet::from([(t(2), t(1))]));
    }

    // a 3-cycle: the last grant closing it is keyless; a holder below the cycle and an actor
    // the cycle holds keep theirs; two cycles through one actor each lose their last grant.
    #[test]
    fn key_access_three_cycle_and_below() {
        // X(1) in Y(2) in Z(3) in X: Y holds X, Z holds Y, X holds Z (last); W(4) holds X; X holds V(5)
        let gs = vec![g(1, 1, 2), g(2, 2, 3), g(3, 3, 1), g(0, 1, 4), g(4, 5, 1)];
        assert_eq!(key_access(gs), BTreeSet::from([(t(3), t(1))]));
        // another cycle X <-> W added later shares X
        let gs = vec![g(1, 1, 2), g(2, 2, 3), g(3, 3, 1), g(0, 1, 4), g(5, 4, 1)];
        assert_eq!(key_access(gs), BTreeSet::from([(t(3), t(1)), (t(4), t(1))]));
        // a chord: Z holds X too, later: Z's key yields X's already (through Y), X's yields
        // nothing of Z's, so it closes no cycle
        let gs = vec![g(1, 1, 2), g(2, 2, 3), g(3, 3, 1), g(4, 1, 3)];
        assert_eq!(key_access(gs), BTreeSet::from([(t(3), t(1))]));
    }

    // the greedy result over random graphs has no cycle among keyed grants and keeps every grant
    // that closes none (the reference: a cycle check per grant in order over all grants).
    #[test]
    fn key_access_random_matches_reference() {
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = |m: u64| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed % m
        };
        for _ in 0..300 {
            let n = 2 + next(6) as u8;
            let e = next(14) as u32;
            let gs: Vec<Grant<u32>> = (0..e).map(|i| g(next(5) as u32 * 100 + i, next(u64::from(n)) as u8, next(u64::from(n)) as u8)).collect();
            let mut dedup: BTreeMap<(Tid, Tid), Grant<u32>> = BTreeMap::new();
            for x in gs {
                dedup.entry((x.target, x.holder)).or_insert(x);
            }
            let gs: Vec<Grant<u32>> = dedup.into_values().collect();
            let got = key_access(gs.clone());
            let mut sorted = gs.clone();
            sorted.sort_by_key(|x| (x.order, x.target, x.holder));
            let mut keyed: BTreeMap<Tid, Vec<Tid>> = BTreeMap::new();
            let mut want = BTreeSet::new();
            for x in sorted {
                if yields(&keyed, x.target, x.holder) {
                    want.insert((x.target, x.holder));
                } else {
                    keyed.entry(x.holder).or_default().push(x.target);
                }
            }
            assert_eq!(got, want);
        }
    }
}
