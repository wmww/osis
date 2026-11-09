//! The cost harness over kit's views (notes/fast-design.md section 4).
use crate::view_tree::data;
use osis_kit::testing::check_views;

/// Every registered view: a node reads no address twice, a write to what it did not read runs
/// nothing, a write to what it read runs exactly that.
#[test]
fn every_view_reads_exactly_what_it_shows() {
    let fails = check_views(&data());
    assert!(fails.is_empty(), "{}", fails.join("\n"));
}

mod rows {
    use osis::core::NAME;
    use osis_kit::facets::create;
    use osis_kit::testing::Screen;
    use osis_kit::view::{Config, Cx, Graph, Tree, ViewSpec, WindowState};
    use crate::view_tree::data;

    fn name(d: &osis_kit::store::Data, t: osis::Tid, n: &str) {
        let mut w = d.db.write();
        w.at(t, NAME).set(&n.to_string()).unwrap();
        w.commit().unwrap();
    }

    fn work(arrange: &str, n: usize) -> (u64, u64, u64, u64, u64) {
        let d = data();
        let tag = create(&d, "tag").unwrap();
        let g = d.main_group().unwrap();
        let mut x = d.db.write();
        let notes: Vec<osis::Tid> = (0..n).map(|i| {
            let t = x.create().unwrap();
            x.at(t, NAME).set(&format!("note {i}")).unwrap();
            x.group(g).add(osis::Member::Item(t)).unwrap();
            x.group(tag).add(osis::Member::Item(t)).unwrap();
            t
        }).collect();
        x.commit().unwrap();
        let w = WindowState::default();
        Cx::new(&d, &w, false);
        let (mut tree, mut screen) = (Tree::default(), Screen::default());
        let mut spec = ViewSpec::new("collection", tag);
        spec.config = Config::default().with("arrange", arrange);
        tree.show(&w, &mut screen, "c", &spec).unwrap();
        w.graph.take_costs();
        screen.rows = 0;
        let step = |tree: &mut Tree, screen: &mut Screen, w: &WindowState| {
            Cx::new(&d, w, false);
            tree.update(w, screen).unwrap();
            w.graph.take_costs()
        };
        // changing one row
        name(&d, notes[n / 2], "note changed");
        let c = step(&mut tree, &mut screen, &w);
        let changed = std::mem::take(&mut screen.rows);
        assert_eq!(c.renders, 1, "one collection render: {c:?}");
        // a new row
        let added = d.create_note().unwrap();
        name(&d, added, "note added");
        d.add_tag(added, tag).unwrap();
        let c2 = step(&mut tree, &mut screen, &w);
        assert_eq!(c2.renders, 1, "one collection render: {c2:?}");
        let inserted = std::mem::take(&mut screen.rows);
        // an unrelated write: nothing
        let other = d.create_note().unwrap();
        name(&d, other, "elsewhere");
        let c3 = step(&mut tree, &mut screen, &w);
        (changed, inserted, c.memo_runs, c2.memo_runs + c3.memo_runs, Graph::len(&w.graph) as u64)
    }

    /// Inserting or changing one row builds one row, in stream, cards and rows, whatever the size.
    #[test]
    fn one_row_changed_builds_one_row() {
        for arrange in ["stream", "cards", "rows"] {
            for n in [20, 100] {
                let (changed, inserted, _, _, _) = work(arrange, n);
                assert_eq!((changed, inserted), (1, 1), "{arrange} at {n}");
            }
        }
    }

    /// The memo work of one change does not grow with the rows shown.
    #[test]
    fn one_change_costs_the_same_at_n_and_10n() {
        let (_, _, c20, _, _) = work("rows", 20);
        let (_, _, c100, _, _) = work("rows", 100);
        assert_eq!(c20, c100, "memo reruns of one change at 20 and 100 rows");
    }
}
