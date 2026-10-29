//! The notes actions over an in-memory database.
use osis::core::{BODY, GROUP, NAME};
use osis::{Config, Osis};
use osis_app::notes::Notes;

fn notes() -> Notes {
    Notes::new(Osis::create(Config::memory()).unwrap().0)
}

#[test]
fn create_select_rename_delete() {
    let n = notes();
    assert!(n.list().unwrap().is_empty());
    assert_eq!(n.selected().unwrap(), None);
    let a = n.create("b note").unwrap();
    let b = n.create("A note").unwrap();
    assert_eq!(n.selected().unwrap(), Some(b), "a new note is selected");
    assert_eq!(n.list().unwrap(), vec![(b, "A note".into()), (a, "b note".into())], "sorted case-folded");
    n.select(Some(a)).unwrap();
    assert_eq!(n.selected().unwrap(), Some(a));
    let s = n.db.edit_text(a, BODY, osis::Path::root()).unwrap();
    s.insert(0, "hello").unwrap();
    s.commit().unwrap();
    assert_eq!(n.db.get(a, BODY).unwrap().as_deref(), Some("hello"));
    n.delete(a).unwrap();
    assert_eq!(n.list().unwrap(), vec![(b, "A note".into())]);
    assert_eq!(n.selected().unwrap(), None, "deleting the selected note clears the selection");
    assert_eq!(n.db.get(a, NAME).unwrap(), None);
}

/// The notes group is a subgroup of home (so its items sync, not only its own aspects) and
/// carries no `/tag`; one group however often it is asked for.
#[test]
fn one_internal_group_under_home() {
    let n = notes();
    let g = n.main_group().unwrap();
    assert_eq!(n.main_group().unwrap(), g);
    let home = n.db.get(n.db.home(), GROUP).unwrap().unwrap();
    assert!(home.items.contains(&g) && home.subgroups.contains(&g));
    assert_eq!(n.db.get(g, osis::core::TAG).unwrap(), None);
    let t = n.create("x").unwrap();
    assert!(n.db.groups_of(t).contains(&n.db.home()));
}

/// Typing spliced into a session whose buffer holds a remote merge the widget does not show yet
/// keeps the merge (`shown` is the widget's text before the keystroke).
#[test]
fn splice_keeps_unshown_remote_merge() {
    use osis_app::ui::splice;
    let n = notes();
    let t = n.create("x").unwrap();
    let s = n.db.edit_text(t, BODY, osis::Path::root()).unwrap();
    let shown = "hello world";
    s.insert(0, shown).unwrap();
    // the "remote" merge, ahead of the widget
    s.insert(6, "brave ").unwrap();
    splice(&s, shown, "hello world!").unwrap();
    assert_eq!(s.text(), "hello brave world!", "after the merge");
    splice(&s, "hello world!", ">hello world!").unwrap();
    assert_eq!(s.text(), ">hello brave world!", "before the merge");
    splice(&s, ">hello world!", ">hellX world!").unwrap();
    assert_eq!(s.text(), ">hellX brave world!", "a replace before the merge");
    // " wo" -> "_" is disjoint from the merge read as " brave" after "X": both apply
    splice(&s, ">hellX world!", ">hellX_rld!").unwrap();
    assert_eq!(s.text(), ">hellX brave_rld!", "a replace right after the merge");
    let len = s.text().chars().count();
    s.replace(0..len, ">hellX brave world!").unwrap();
    // a deletion across the merge point: the merge wins, only what was typed lands, after it
    splice(&s, ">hellX world!", ">hell_rld!").unwrap();
    assert_eq!(s.text(), ">hellX brave _world!");
    splice(&s, ">hellX brave _world!", ">hellX brave _world").unwrap();
    assert_eq!(s.text(), ">hellX brave _world", "no merge pending: the plain splice");
}

/// Random shown text, remote edit and local edit (one splice each, over a 2-letter alphabet so
/// diffs are ambiguous). Disjoint edits give both applied, under some reading of each edit as one
/// splice (`aa -> aaa` inserts at any of three points); overlapping ones keep the typed text and
/// lose at most the chars the user removed.
#[test]
fn splice_random_against_reference() {
    use osis_app::ui::splice;
    let n = notes();
    let t = n.create("x").unwrap();
    let s = n.db.edit_text(t, BODY, osis::Path::root()).unwrap();
    let mut x = 0x9e37_79b9_7f4a_7c15u64;
    let mut rnd = move |m: usize| {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        (x % m as u64) as usize
    };
    let word = |rnd: &mut dyn FnMut(usize) -> usize, n: usize| -> Vec<char> { (0..rnd(n)).map(|_| if rnd(2) == 0 { 'a' } else { 'b' }).collect() };
    let apply = |t: &[char], at: usize, del: usize, ins: &[char]| -> Vec<char> { [&t[..at], ins, &t[at + del..]].concat() };
    // every (at, del, ins) with apply(a, at, del, ins) == b
    let readings = |a: &[char], b: &[char]| -> Vec<(usize, usize, Vec<char>)> {
        let mut v = vec![];
        for at in 0..=a.len() {
            for del in 0..=a.len() - at {
                let keep = a.len() - del;
                if keep <= b.len() && a[..at] == b[..at] && a[at + del..] == b[b.len() - (a.len() - at - del)..] {
                    v.push((at, del, b[at..b.len() - (a.len() - at - del)].to_vec()));
                }
            }
        }
        v
    };
    let st = |v: &[char]| v.iter().collect::<String>();
    for _ in 0..5000 {
        let sh = word(&mut rnd, 9);
        let (rat, ldat) = (rnd(sh.len() + 1), rnd(sh.len() + 1));
        let (rdel, ldel) = (rnd(sh.len() - rat + 1), rnd(sh.len() - ldat + 1));
        let (rins, lins) = (word(&mut rnd, 4), word(&mut rnd, 4));
        let remote = apply(&sh, rat, rdel, &rins);
        let new = apply(&sh, ldat, ldel, &lins);
        let len = s.text().chars().count();
        s.replace(0..len, &st(&remote)).unwrap();
        splice(&s, &st(&sh), &st(&new)).unwrap();
        let got: Vec<char> = s.text().chars().collect();
        let case = format!("shown {:?} remote {:?} new {:?} got {:?}", st(&sh), st(&remote), st(&new), st(&got));
        if ldat + ldel <= rat || ldat >= rat + rdel {
            let mut want = vec![];
            for (ra, rd, ri) in readings(&sh, &remote) {
                for (la, ld, li) in readings(&sh, &new) {
                    if la + ld <= ra {
                        want.push(apply(&remote, la, ld, &li));
                    }
                    if la >= ra + rd {
                        want.push(apply(&remote, la + ri.len() - rd, ld, &li));
                    }
                }
            }
            assert!(want.contains(&got), "{case}: want one of {:?}", want.iter().map(|w| st(w)).collect::<Vec<_>>());
        } else {
            let ok = readings(&sh, &new).into_iter().any(|(_, ld, li)| {
                st(&got).contains(&st(&li)) && got.len() + ld >= remote.len() + li.len() && got.len() <= remote.len() + li.len()
            });
            assert!(ok, "{case}");
        }
    }
}
