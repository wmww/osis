//! The cost harness over kit's views (notes/fast-design.md section 4).
use crate::view_tree::data;
use osis_kit::testing::{check_view_scale, check_views};

/// Every registered view: a node reads no address twice, a write to what it did not read runs
/// nothing, a write to what it read runs exactly that.
#[test]
fn every_view_reads_exactly_what_it_shows() {
    let fails = check_views(&data(), |_| true);
    assert!(fails.is_empty(), "{}", fails.join("\n"));
}

/// Every registered view that grows: at n and 10n a window of rows at most, and a flat cost to
/// add one.
#[test]
fn every_view_grows_flat() {
    let fails = check_view_scale(&data());
    assert!(fails.is_empty(), "{}", fails.join("\n"));
}

mod rows {
    use osis::core::NAME;
    use osis_kit::facets::create;
    use osis_kit::testing::Screen;
    use osis_kit::view::{Config, Costs, Cx, Tree, ViewSpec, WindowState};
    use crate::view_tree::{data, name};

    /// Rows built by changing one row and by adding one, and the memo runs of the change.
    fn work(arrange: &str, n: usize) -> (u64, u64, u64) {
        let d = data();
        let tag = big(&d, n);
        let first = rows_keys(&d, &WindowState::default(), &rows_spec(tag))[0].parse().unwrap();
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
        name(&d, first, "note 0 changed");
        let c = step(&mut tree, &mut screen, &w);
        let changed = std::mem::take(&mut screen.rows);
        assert_eq!(c.renders, 1, "one collection render: {c:?}");
        // a new row
        let added = d.create_note().unwrap();
        name(&d, added, "a note added");
        d.add_tag(added, tag).unwrap();
        let c2 = step(&mut tree, &mut screen, &w);
        assert_eq!(c2.renders, 1, "one collection render: {c2:?}");
        let inserted = std::mem::take(&mut screen.rows);
        // an unrelated write: nothing (a window opening it moves only backlinks off `holds.0`)
        let other = d.create_note().unwrap();
        name(&d, other, "elsewhere");
        w.graph.record();
        let c3 = step(&mut tree, &mut screen, &w);
        assert_eq!(c3, Costs::default(), "an unrelated write runs nothing: {:?}", w.graph.recorded());
        (changed, inserted, c.memo_runs)
    }

    /// Inserting or changing one row builds one row, in stream, cards and rows, and the memo work
    /// of the change is the same at n and 5n rows.
    #[test]
    fn one_row_changed_builds_one_row() {
        for arrange in ["stream", "cards", "rows"] {
            // past `WINDOW` the change must be near the top to be shown
            let (a, b) = (work(arrange, 20), work(arrange, 100));
            assert_eq!((a.0, a.1, b.0, b.1), (1, 1, 1, 1), "{arrange}");
            assert_eq!(a.2, b.2, "{arrange}: memo reruns of one change at 20 and 100 rows");
        }
    }

    /// What a list shows is a window, and a window named by its anchor key survives what happens
    /// around it: a row added above the anchor changes nothing below it, and the anchor is still
    /// the row it named.
    #[test]
    fn a_list_shows_its_window_and_keeps_its_anchor() {
        use osis_kit::view::paged::{LIST_WINDOW, ListWindow, WINDOW};
        let d = data();
        let tag = big(&d, 300);
        let w = WindowState::default();
        let spec = rows_spec(tag);
        let keys = |w: &WindowState| rows_keys(&d, w, &spec);
        let all = keys(&w);
        assert!(all.len() <= WINDOW, "a window: {}", all.len());
        let anchor = all[40].clone();
        w.graph.set_local_at(LIST_WINDOW, "c#items", ListWindow { anchor: Some(anchor.clone()), row: None, before: 2, after: 3, scope: String::new() });
        let seen = keys(&w);
        assert_eq!(seen, all[38..43].to_vec(), "two before the anchor, it and two after");
        // a row sorted above the window: the window and its anchor do not move
        let above = d.create_note().unwrap();
        name(&d, above, "a first");
        d.add_tag(above, tag).unwrap();
        d.db.settle();
        assert_eq!(keys(&w), seen);
        // a row sorted in just before the anchor: the rows from the anchor on stay as they were
        let near = d.create_note().unwrap();
        name(&d, near, "note 0039 x");
        d.add_tag(near, tag).unwrap();
        d.db.settle();
        let after = keys(&w);
        assert_eq!(after.iter().position(|k| *k == anchor), Some(2), "{after:?}");
        assert_eq!(after[2..], seen[2..]);
    }

    fn rows_keys(d: &osis_kit::store::Data, w: &WindowState, spec: &ViewSpec) -> Vec<String> {
        use osis_kit::view::Block;
        let cx = Cx::new(d, w, false);
        let s = osis_kit::views::render(&cx, "c", spec).unwrap();
        s.blocks.iter().find_map(|b| if let Block::List(l) = b { Some(l.rows().iter().map(|r| r.key.clone()).collect()) } else { None }).unwrap()
    }

    fn big(d: &osis_kit::store::Data, n: usize) -> osis::Tid {
        let tag = create(d, "tag").unwrap();
        let g = d.home().unwrap();
        let mut x = d.db.write();
        for i in 0..n {
            let t = x.create(g, None).unwrap();
            x.at(t, NAME).set(&format!("note {i:04}")).unwrap();
            x.hold(g, t).unwrap();
            x.hold(tag, t).unwrap();
        }
        x.commit().unwrap();
        tag
    }

    fn rows_spec(tag: osis::Tid) -> ViewSpec {
        let mut spec = ViewSpec::new("collection", tag);
        spec.config = Config::default().with("arrange", "rows").with("no_chooser", "true");
        spec
    }

    /// The row a window was anchored on leaves the list: the place holds, at its neighbour.
    #[test]
    fn a_list_keeps_its_place_when_its_top_row_goes() {
        use osis_kit::view::paged::{LIST_WINDOW, ListWindow};
        let d = data();
        let tag = big(&d, 100);
        let w = WindowState::default();
        let spec = rows_spec(tag);
        let all = rows_keys(&d, &w, &spec);
        let k = all[40].clone();
        w.graph.set_local_at(LIST_WINDOW, "c#items", ListWindow { anchor: Some(k.clone()), row: Some(40), before: 2, after: 3, scope: String::new() });
        assert_eq!(rows_keys(&d, &w, &spec), all[38..43].to_vec());
        d.delete(k.parse().unwrap()).unwrap();
        d.db.settle();
        assert_eq!(rows_keys(&d, &w, &spec), [&all[38..40], &all[41..44]].concat(), "the neighbour took its place");
    }

    /// A jump to a row names no key: the window is around that row.
    #[test]
    fn a_list_jumps_to_a_row() {
        use osis_kit::view::paged::{LIST_WINDOW, ListWindow};
        let d = data();
        let tag = big(&d, 100);
        let w = WindowState::default();
        let spec = rows_spec(tag);
        let all = rows_keys(&d, &w, &spec);
        w.graph.set_local_at(LIST_WINDOW, "c#items", ListWindow { anchor: None, row: Some(40), before: 1, after: 2, scope: String::new() });
        assert_eq!(rows_keys(&d, &w, &spec), all[39..42].to_vec());
    }

    /// A window chosen for another scope (a search's query) does not apply: a new list starts over.
    #[test]
    fn a_new_query_starts_at_the_top() {
        use osis_kit::view::paged::{LIST_WINDOW, ListWindow};
        use osis_kit::view::{Block, QUERY};
        let d = data();
        big(&d, 100);
        let w = WindowState::default();
        let results = |w: &WindowState| {
            let cx = Cx::new(&d, w, false);
            let s = osis_kit::views::render(&cx, "r", &ViewSpec::new("results", d.home().unwrap())).unwrap();
            s.blocks.iter().find_map(|b| if let Block::List(l) = b { Some(l.rows().iter().map(|r| r.key.clone()).collect::<Vec<_>>()) } else { None }).unwrap()
        };
        w.set_local(QUERY, "note".to_string());
        let note = results(&w);
        w.graph.set_local_at(LIST_WINDOW, "r#results", ListWindow { anchor: Some(note[40].clone()), row: Some(40), before: 2, after: 3, scope: "note".into() });
        assert_eq!(results(&w), note[38..43].to_vec());
        // the same key is in both, and a stale window must not hold
        w.set_local(QUERY, "note 00".to_string());
        assert_eq!(results(&w)[0], "label Things");
    }
}
