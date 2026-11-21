//! spec/commits.md §5 (Signals): a signal's writes are history from the moment they are
//! written under the entry governing their AK (spec/commits.md §5 Signals), never joined
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
    let r = PurgeBy::AuthorOrAdmin;
    let h = held(3, vec![setting(5, 0, SIG, KEPT), reg(10, MINT_ADMIN, 1, SIG, r, 7), reg(11, MINT_ADMIN, 1, SIG, r, 8)]);
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
        let h = |now| held(now, vec![setting(5, 0, SIG, opt), reg(10, MINT_ADMIN, 1, SIG, PurgeBy::AuthorOrAdmin, 7)]);
        assert_eq!(shown(&h(last)), vec![10]);
        assert_eq!(fate(&h(last), 10), Fate::Keep(KeepWhy::Until));
        assert!(shown(&h(last + 1)).is_empty());
        assert_eq!(fate(&h(last + 1), 10), Fate::MayDrop(DropWhy::PastBound));
        let dropped = act(&h(last + 1), &evaluate(&h(last + 1)), Some((10, 0)));
        assert!(shown(&dropped).is_empty(), "dropped or not, it is not listed");
        assert!(evaluate(&h(last)).deadlines.contains(&at(last + 1)));
    }
    let h = held(10_000, vec![setting(5, 0, SIG, KEPT), reg(10, MINT_ADMIN, 1, SIG, PurgeBy::AuthorOrAdmin, 7)]);
    assert_eq!(fate(&h, 10), Fate::Keep(KeepWhy::Until));
    for opt in [Opt::None, Opt::Purge] {
        let h = held(1, vec![setting(5, 0, SIG, opt), reg(10, MINT_ADMIN, 1, SIG, PurgeBy::AuthorOrAdmin, 7)]);
        assert!(shown(&h).is_empty(), "{opt:?}: no history, no listing");
        assert_eq!(fate(&h, 10), Fate::MayDrop(DropWhy::PastBound));
    }
    assert_eq!(fate(&held(1, vec![reg(10, MINT_ADMIN, 1, SIG, PurgeBy::AuthorOrAdmin, 7)]), 10), Fate::MayDrop(DropWhy::PastBound), "no setting");
}

// spec/commits.md §5 (signals; purge), §6: purge and expiry act per write; the leftover may go
// once out of history
#[test]
fn signal_purge_and_expiry_per_write_spec_commits_5() {
    let r = PurgeBy::AuthorOrAdmin;
    let mut exp = reg(11, MINT_ADMIN, 1, SIG, r, 8);
    exp.expires = Some(at(2));
    let item = PurgeItem::Commit { commit: 10, thing: T, aspect: SIG };
    let h = |now| held(now, vec![setting(5, 0, SIG, keep_after(5)), reg(10, MINT_ADMIN, 1, SIG, r, 7), exp.clone(), reg(12, MINT_ADMIN, 1, SIG, r, 9), purge(20, MINT_ADMIN, 2, item)]);
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
    let r = PurgeBy::AuthorOrAdmin;
    let grant = edge(5, MINT_ADMIN, 0, 1, Some(Role::Write), None);
    let msg = reg(10, 1, 1, SIG, r, 7);
    let kick = edge(20, MINT_ADMIN, 2, 1, None, Some(vec![]));
    let keep = setting(6, 0, SIG, KEPT);
    assert_eq!(shown(&held(3, vec![keep.clone(), grant.clone(), msg.clone()])), vec![10]);
    let kicked = held(3, vec![keep, grant.clone(), msg.clone(), kick]);
    assert!(shown(&kicked).is_empty());
    assert_eq!(fate(&kicked, 10), Fate::MustDrop(DropWhy::Invalid));
    assert_eq!(read(&kicked, SIG), None);
}

mod external {
    use crate::util::*;
    use held_model::edits::listed;
    use held_model::external::{fire, setting, EXT, OTHER, STRANGER, WRITER};
    use held_model::*;

    fn under(rule: ExternalFires, now: u64, cs: Vec<Commit>) -> Held {
        Held { external_fires: rule, ..held(now, cs) }
    }
    fn valid(h: &Held, c: CommitId) -> bool {
        evaluate(h).valid[&(c, 0)]
    }
    fn on(now: u64, cs: Vec<Commit>) -> Held {
        under(ExternalFires::Enabled, now, cs)
    }

    // spec/permissions.md §5.2 (External fires), spec/commits.md §5 (The setting): a party holding
    // no write fires an external signal validly only while the current setting enables it (an
    // entry of its own; the default never, another signal's never); an unnamed fire is listed
    // nowhere and not promoted. Without the rule (`Any`) it is valid, and listed nowhere either:
    // nothing keeps it.
    #[test]
    fn an_unnamed_external_fire_is_invalid_and_an_enabled_one_valid_spec_perm_5_2() {
        let f = fire(50, STRANGER, ts(2));
        for (s, ok) in [(None, false), (Some(setting(40, MINT_ADMIN, ts(1), &[EXT], false)), true), (Some(setting(40, MINT_ADMIN, ts(1), &[], true)), false), (Some(setting(40, MINT_ADMIN, ts(1), &[OTHER], true)), false)] {
            let h = on(3, s.iter().cloned().chain([f.clone()]).collect());
            let o = evaluate(&h);
            assert_eq!(o.valid[&(50, 0)], ok, "{s:?}");
            assert_eq!(promotes(&o, &h.commits.iter().find(|c| c.id == 50).unwrap().clone(), 0), ok);
            assert_eq!(listed(&h).contains(&50), ok, "kept for good where enabled");
            let any = under(ExternalFires::Any, 3, h.commits.clone());
            assert!(valid(&any, 50), "without the rule");
            assert_eq!(listed(&any).contains(&50), ok, "kept by name only");
        }
    }

    // spec/permissions.md §5.2 (External fires): a writer's fire is judged by its author's
    // authority whatever the setting; a removed writer's fire its removal does not list is judged
    // as any other party's
    #[test]
    fn a_writers_external_fire_ignores_the_setting_a_removed_writers_does_not_spec_perm_5_2() {
        let grant = edge(30, MINT_ADMIN, 0, WRITER, Some(Role::Write), None);
        let f = fire(50, WRITER, ts(2));
        assert!(valid(&on(3, vec![grant.clone(), f.clone()]), 50), "a writer's");
        let kick = edge(31, MINT_ADMIN, 3, WRITER, None, Some(vec![]));
        assert!(!valid(&on(4, vec![grant.clone(), f.clone(), kick.clone()]), 50), "removed, not listed");
        let listed_kick = edge(31, MINT_ADMIN, 3, WRITER, None, Some(vec![50]));
        assert!(valid(&on(4, vec![grant.clone(), f.clone(), listed_kick]), 50), "listed by the removal");
        assert!(valid(&on(4, vec![grant, f, kick, setting(40, MINT_ADMIN, ts(1), &[EXT], false)]), 50), "removed, enabled");
    }

    // spec/commits.md §5 (In force), spec/permissions.md §5.2: the current setting decides every
    // fire whatever its `ts`: a later disabling setting turns an earlier fire invalid, a later
    // enabling one an earlier fire valid, in whatever order they arrive
    #[test]
    fn the_current_setting_decides_every_fire_whatever_its_ts_spec_commits_5() {
        let (on1, off3, f2) = (setting(40, MINT_ADMIN, ts(1), &[EXT], false), setting(41, MINT_ADMIN, ts(3), &[], false), fire(50, STRANGER, ts(2)));
        assert!(valid(&on(4, vec![on1.clone(), f2.clone()]), 50));
        assert!(!valid(&on(4, vec![on1.clone(), f2.clone(), off3.clone()]), 50), "disabled after it");
        assert!(!valid(&on(4, vec![f2.clone(), off3.clone()]), 50));
        let on3 = setting(42, MINT_ADMIN, ts(3), &[EXT], false);
        assert!(valid(&on(4, vec![f2.clone(), on3]), 50), "enabled after it");
    }

    // The rejected reading, the setting in force at the fire's key (`AtKey`), and its two holes:
    // a party stamping a fire back to before a disabling setting has it valid and promoted, and a
    // fire between two settings that both enable turns invalid when the older one drops
    #[test]
    fn the_setting_at_a_fires_key_lets_backdated_fires_stand_spec_commits_5() {
        let (on1, off3, f2) = (setting(40, MINT_ADMIN, ts(1), &[EXT], false), setting(41, MINT_ADMIN, ts(3), &[], false), fire(50, STRANGER, ts(2)));
        let late = vec![on1.clone(), off3, f2.clone()];
        assert!(valid(&under(ExternalFires::AtKey, 4, late.clone()), 50), "backdated: valid at its key");
        assert!(!valid(&on(4, late), 50));
        let on3 = setting(41, MINT_ADMIN, ts(3), &[EXT], false);
        let dropped = vec![missing(on1.clone(), 0), on3.clone(), f2.clone()];
        assert!(valid(&under(ExternalFires::AtKey, 4, vec![on1, on3, f2]), 50));
        assert!(!valid(&under(ExternalFires::AtKey, 4, dropped.clone()), 50), "the setting before it dropped");
        assert!(valid(&on(4, dropped), 50));
    }
}
