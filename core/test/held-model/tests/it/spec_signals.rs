//! spec/commits.md §5 (Signals): a signal's writes are history from the moment they are
//! written under the entry governing their AK (issues/thing-history.md, Signals), never joined
//! into a state, kept while in history, until expiry or purge.
use crate::util::*;
use held_model::*;

const SIG: Aspect = Aspect::signal(5);

fn shown(h: &Held) -> Vec<CommitId> {
    evaluate(h).history.get(&(T, SIG)).map(|s| s.iter().map(|x| x.1).collect()).unwrap_or_default()
}

// spec/data-model.md §2, spec/commits.md §5 (Signals): never in state, never merged; every write
// is history from its own `ts`
#[test]
fn signal_writes_never_join_and_are_history_at_once_spec_commits_5() {
    let r = Retention::PLAIN;
    let h = held(3, vec![setting(5, 0, SIG, KEPT), reg(10, FIRST_ADMIN, 1, SIG, r, 7), reg(11, FIRST_ADMIN, 1, SIG, r, 8)]);
    let o = evaluate(&h);
    assert_eq!(read(&h, SIG), None);
    assert_eq!(o.states[&(T, SIG)], Frag::empty(0));
    assert_eq!(shown(&h), vec![10, 11]);
    assert_eq!(o.replaced_at[&(10, 0)], Some(at(1)));
    assert_eq!(o.fates[&(10, 0)], Fate::Keep(KeepWhy::Until));
}

// spec/commits.md §5 (Signals): kept while in history (D after written, until T), then a node
// may drop it and no read shows it; for good under forever; with no entry, never history
#[test]
fn signal_kept_while_in_history_spec_commits_5() {
    for (opt, last) in [(keep_after(2), 2), (keep_until(4), 3)] {
        let h = |now| held(now, vec![setting(5, 0, SIG, opt), reg(10, FIRST_ADMIN, 1, SIG, Retention::PLAIN, 7)]);
        assert_eq!(shown(&h(last)), vec![10]);
        assert_eq!(fate(&h(last), 10), Fate::Keep(KeepWhy::Until));
        assert!(shown(&h(last + 1)).is_empty());
        assert_eq!(fate(&h(last + 1), 10), Fate::MayDrop(DropWhy::PastBound));
        let dropped = act(&h(last + 1), &evaluate(&h(last + 1)), Some((10, 0)));
        assert!(shown(&dropped).is_empty(), "dropped or not, it is not listed");
        assert!(evaluate(&h(last)).deadlines.contains(&at(last + 1)));
    }
    let h = held(10_000, vec![setting(5, 0, SIG, KEPT), reg(10, FIRST_ADMIN, 1, SIG, Retention::PLAIN, 7)]);
    assert_eq!(fate(&h, 10), Fate::Keep(KeepWhy::Until));
    for opt in [Opt::None, Opt::Purge] {
        let h = held(1, vec![setting(5, 0, SIG, opt), reg(10, FIRST_ADMIN, 1, SIG, Retention::PLAIN, 7)]);
        assert!(shown(&h).is_empty(), "{opt:?}: no history, no listing");
        assert_eq!(fate(&h, 10), Fate::MayDrop(DropWhy::PastBound));
    }
    assert_eq!(fate(&held(1, vec![reg(10, FIRST_ADMIN, 1, SIG, Retention::PLAIN, 7)]), 10), Fate::MayDrop(DropWhy::PastBound), "no setting");
}

// spec/commits.md §5 (Signals, Purge), §6: purge and expiry act per write; the leftover may go
// once out of history
#[test]
fn signal_purge_and_expiry_per_write_spec_commits_5() {
    let r = Retention::PLAIN;
    let mut exp = reg(11, FIRST_ADMIN, 1, SIG, r, 8);
    exp.expires = Some(at(2));
    let item = PurgeItem::Commit { commit: 10, thing: T, aspect: SIG };
    let h = |now| held(now, vec![setting(5, 0, SIG, keep_after(5)), reg(10, FIRST_ADMIN, 1, SIG, r, 7), exp.clone(), reg(12, FIRST_ADMIN, 1, SIG, r, 9), purge(20, FIRST_ADMIN, 2, item)]);
    let o = evaluate(&h(3));
    assert_eq!(o.fates[&(10, 0)], Fate::Leftover(LeftoverWhy::Purged));
    assert_eq!(o.fates[&(11, 0)], Fate::Leftover(LeftoverWhy::Expired));
    assert_eq!(shown(&h(3)), vec![11, 12]);
    assert_eq!(fate(&h(7), 10), Fate::MayDrop(DropWhy::PastBound));
    assert_eq!(fate(&h(7), 11), Fate::MayDrop(DropWhy::PastBound));
}

// spec/permissions.md §5.2, §6: validity decides which writes show; a kick hides its target's
// writes from then on and a re-grant shows them again, the reads unchanged
#[test]
fn signal_kick_rejudges_history_spec_perm_5_2() {
    let r = Retention::PLAIN;
    let grant = edge(5, FIRST_ADMIN, 0, 1, Some(Role::Write), None);
    let msg = reg(10, 1, 1, SIG, r, 7);
    let kick = edge(20, FIRST_ADMIN, 2, 1, None, Some(vec![]));
    let keep = setting(6, 0, SIG, KEPT);
    assert_eq!(shown(&held(3, vec![keep.clone(), grant.clone(), msg.clone()])), vec![10]);
    let kicked = held(3, vec![keep, grant.clone(), msg.clone(), kick]);
    assert!(shown(&kicked).is_empty());
    assert_eq!(fate(&kicked, 10), Fate::MustDrop(DropWhy::Invalid));
    assert_eq!(read(&kicked, SIG), None);
}
