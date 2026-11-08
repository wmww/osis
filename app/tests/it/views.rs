//! What a user can observe, read as the opener's tree (toolkit-free).
use osis::core::{BODY, NAME, TAG, Tag};
use osis::{DynamicAspectKey, Member, Role, Tid, Value};
use osis_app::store::data as make;
use osis_kit::facets::create;
use osis_kit::schema::{Arrange, COLLECTION, Collection, CollectionOrder, CollectionSource, ElementSpec};
use osis_kit::store::Data;
use osis_kit::view::search::search;
use osis_kit::view::{Block, Config, Cx, Placed, ViewSpec, WindowState};
use osis_kit::views::{Node, expand, page};
use std::collections::BTreeMap;

fn data() -> Data {
    let d = make(osis::internals::create(osis::internals::Opening::memory()).unwrap());
    d.main_group().unwrap();
    d
}

fn open(d: &Data, t: Tid) -> Node {
    let w = WindowState::default();
    page(&Cx::new(d, &w, false), t).unwrap()
}

fn tabs(n: &Node) -> Vec<String> {
    n.out.blocks.iter().find_map(|b| if let Block::Tabs(t) = b { Some(t.iter().map(|x| x.label.clone()).collect()) } else { None }).unwrap_or_default()
}

fn content(n: &Node) -> &Node {
    n.children.iter().find(|c| !matches!(c.spec.view_type.as_str(), "bar" | "chrome")).unwrap()
}

/// A thing with event, contact and body aspects: each fitting view is a tab, the default the best
/// fit, and a choice persists.
#[test]
fn several_views_fit_with_tabs_and_a_kept_choice() {
    let d = data();
    let t = create(&d, "event").unwrap();
    let mut w = d.db.write();
    w.at(t, BODY).set(&"text".to_string()).unwrap();
    w.at(t, NAME).set(&"Mixed".to_string()).unwrap();
    w.at(t, osis_app::contact::NICKNAME).set(&"mix".to_string()).unwrap();
    w.commit().unwrap();
    let n = open(&d, t);
    assert_eq!(tabs(&n), ["Event", "Person", "Note"].map(String::from).to_vec());
    assert_eq!(content(&n).spec.view_type, "event", "accounts for the most");
    d.set_viewed_as(t, "person").unwrap();
    let n = open(&d, t);
    assert_eq!(content(&n).spec.view_type, "person");
    assert!(content(&n).out.blocks.iter().any(|b| matches!(b, Block::Form { .. })), "a person's form");
    d.set_viewed_as(t, "note").unwrap();
    assert!(content(&open(&d, t)).out.blocks.iter().any(|b| matches!(b, Block::Editor { ak, .. } if ak == "body.0")));
}

#[test]
fn a_stale_viewed_as_falls_back() {
    let d = data();
    let t = d.create_note().unwrap();
    d.set_viewed_as(t, "event").unwrap();
    assert_eq!(content(&open(&d, t)).spec.view_type, "note");
    assert!(tabs(&open(&d, t)).is_empty());
}

/// A chat appears as any thing does: found, favorited, tagged, in a tag's cards with its name.
#[test]
fn a_chat_is_an_ordinary_thing() {
    let d = data();
    let c = osis_chat::create(&d.db, &osis_chat::Options { name: "channel".into(), ..Default::default() }).unwrap();
    assert!(d.things().unwrap().contains(&c));
    let w = WindowState::default();
    let found = search(&Cx::new(&d, &w, false), "chann").unwrap();
    assert_eq!(found.named, vec![c]);
    d.toggle_favorite(c).unwrap();
    assert!(d.is_favorite(c).unwrap());
    let tag = create(&d, "tag").unwrap();
    d.add_tag(c, tag).unwrap();
    let n = open(&d, tag);
    let cards: Vec<_> = n.blocks().into_iter().filter_map(|b| if let Block::Entries(Placed::Cards(r)) = b { Some(r.entries.clone()) } else { None }).flatten().collect();
    assert_eq!(cards.iter().map(|e| e.title.as_str()).collect::<Vec<_>>(), ["channel"]);
    let n = open(&d, c);
    assert_eq!(content(&n).spec.view_type, "stream");
    assert!(n.blocks().iter().any(|b| matches!(b, Block::Entries(Placed::Stream(_)))));
}

/// A chat given a body offers both stream and note; the default stays the stream.
#[test]
fn a_chat_with_a_body_offers_note_too() {
    let d = data();
    let c = osis_chat::create(&d.db, &osis_chat::Options::default()).unwrap();
    let mut w = d.db.write();
    w.at(c, BODY).set(&"about this".to_string()).unwrap();
    w.commit().unwrap();
    let n = open(&d, c);
    assert_eq!(tabs(&n), ["Stream", "Note"].map(String::from).to_vec());
    assert_eq!(content(&n).spec.view_type, "stream");
    d.set_viewed_as(c, "note").unwrap();
    assert!(content(&open(&d, c)).out.blocks.iter().any(|b| matches!(b, Block::Editor { ak, .. } if ak == "body.0")));
}

/// A group holding a chat and a note: in stream both contribute, merged by time; cards, one each.
#[test]
fn arrangements_expand_or_show_one_each() {
    let d = data();
    let c = osis_chat::create(&d.db, &osis_chat::Options::default()).unwrap();
    osis_chat::post(&d.db, c, "hi").unwrap();
    let note = d.create_note().unwrap();
    let tag = create(&d, "tag").unwrap();
    d.add_tag(c, tag).unwrap();
    d.add_tag(note, tag).unwrap();
    let cards = |n: &Node| n.blocks().into_iter().find_map(|b| if let Block::Entries(Placed::Cards(r)) = b { Some(r.entries.len()) } else { None });
    assert_eq!(cards(&open(&d, tag)), Some(2));
    d.set_arranged(tag, &Arrange::Stream).unwrap();
    let n = open(&d, tag);
    let v = n.blocks().into_iter().find_map(|b| if let Block::Entries(Placed::Stream(v)) = b { Some(v.clone()) } else { None }).unwrap();
    assert_eq!(v.len(), 2);
    assert!(v.windows(2).all(|w| w[0].time <= w[1].time), "by time");
    assert_eq!(v.iter().filter(|e| e.thing == c).count(), 1);
    assert_eq!(v.iter().filter(|e| e.thing == note).count(), 1);
}

/// A thing with only an unknown aspect opens raw with no tabs and shows it; a view holding it is fine.
#[test]
fn an_unknown_thing_opens_raw() {
    let d = data();
    let g = d.main_group().unwrap();
    let mut w = d.db.write();
    let t = w.create().unwrap();
    w.group(g).add(Member::Item(t)).unwrap();
    w.at(t, DynamicAspectKey::untyped(osis::Ak::new("mystery:thing.0").unwrap())).set(&Value::Int(3)).unwrap();
    w.commit().unwrap();
    let n = open(&d, t);
    assert!(tabs(&n).is_empty());
    assert_eq!(content(&n).spec.view_type, "raw");
    let rows = content(&n).out.blocks.iter().find_map(|b| if let Block::Form { rows, .. } = b { Some(rows.clone()) } else { None }).unwrap();
    assert!(rows.iter().any(|r| r.label == "mystery:thing.0"), "{rows:?}");
    let recent = d.collections().unwrap().into_iter().find(|(c, _)| matches!(c.order, CollectionOrder::Changed)).unwrap().1;
    open(&d, recent);
}

/// A cycle of tags terminates; a thing under two tags appears under both.
#[test]
fn outline_cuts_cycles_and_repeats_shared_things() {
    let d = data();
    let top = create(&d, "tag").unwrap();
    let (a, b) = (create(&d, "tag").unwrap(), create(&d, "tag").unwrap());
    let set = |t, n: &str| {
        let mut w = d.db.write();
        w.at(t, NAME).set(&n.to_string()).unwrap();
        w.commit().unwrap();
    };
    set(a, "A");
    set(b, "B");
    let n = d.create_note().unwrap();
    set(n, "shared");
    d.add_tag(a, top).unwrap();
    d.add_tag(b, top).unwrap();
    d.add_tag(n, a).unwrap();
    d.add_tag(n, b).unwrap();
    d.add_tag(a, b).unwrap();
    d.add_tag(b, a).unwrap();
    d.set_arranged(top, &Arrange::Outline).unwrap();
    let node = open(&d, top);
    let runs = node.blocks().into_iter().find_map(|x| if let Block::Entries(Placed::Outline(r)) = x { Some(r.clone()) } else { None }).unwrap();
    for name in ["In A", "In B"] {
        let run = runs.iter().find(|r| r.parent.as_deref() == Some(name)).unwrap_or_else(|| panic!("{runs:?}"));
        assert!(run.entries.iter().any(|e| e.thing == n), "{name}: {run:?}");
    }
}

/// Raw is available for every thing and lists every aspect.
#[test]
fn raw_shows_every_aspect() {
    let d = data();
    let t = create(&d, "event").unwrap();
    let w = WindowState::default();
    let cx = Cx::new(&d, &w, false);
    let n = expand(&cx, "x", &ViewSpec::new("raw", t)).unwrap();
    let rows = n.out.blocks.iter().find_map(|b| if let Block::Form { rows, .. } = b { Some(rows.clone()) } else { None }).unwrap();
    assert!(rows.iter().any(|r| r.label == "event:start.0"));
}

/// A collection whose element spec names note (compact): note views with no tabs or chrome, though
/// the same thing, opened, is an event.
#[test]
fn an_element_spec_embeds_a_view() {
    let d = data();
    let e = create(&d, "event").unwrap();
    let g = d.main_group().unwrap();
    let mut wr = d.db.write();
    let holder = wr.create().unwrap();
    wr.group(g).add(Member::Item(holder)).unwrap();
    wr.at(holder, TAG).set(&Tag { color: None }).unwrap();
    wr.at(holder, COLLECTION)
        .set(&Collection { source: CollectionSource::Members, having: Default::default(), order: CollectionOrder::Own, arrange: Arrange::Cards, element: Some(ElementSpec { view_type: "note".into(), config: BTreeMap::from([("compact".to_string(), "true".to_string())]) }) })
        .unwrap();
    wr.group(holder).add(Member::Item(e)).unwrap();
    wr.commit().unwrap();
    let n = open(&d, holder);
    let col = content(&n);
    assert!(col.blocks().iter().any(|b| matches!(b, Block::Entries(Placed::Views { .. }))));
    let el = col.children.iter().find(|c| c.spec.view_type == "note").unwrap();
    assert_eq!(el.spec.config, Config::default().with("compact", "true"));
    assert!(el.out.blocks.iter().all(|b| !matches!(b, Block::Tabs(_) | Block::Bar { .. })));
    assert!(el.walk().iter().all(|x| x.spec.view_type != "chrome"));
    assert_eq!(content(&open(&d, e)).spec.view_type, "event");
}

/// `arranged.0` works on a thing the account cannot write.
#[test]
fn arrangement_on_what_i_cannot_write() {
    use osis::internals::Internals as _;
    let (a, b) = (osis::internals::create(osis::internals::Opening::memory()).unwrap(), osis::internals::create(osis::internals::Opening::memory()).unwrap());
    let (a, b) = (make(a), make(b));
    let deliver = |from: &Data, to: &Data| {
        let pks = from.db.engine(|e| e.commit_ids().iter().filter_map(|id| e.package(id).unwrap()).collect::<Vec<_>>());
        for pk in pks {
            let _ = to.db.engine(|e| e.ingest(&pk.bytes, pk.blobs.clone()));
        }
    };
    deliver(&a, &b);
    deliver(&b, &a);
    let t = create(&a, "tag").unwrap();
    a.db.grant(t, b.db.me(), Role::Read, osis::GrantOpts::default()).unwrap();
    deliver(&a, &b);
    deliver(&b, &a);
    b.main_group().unwrap();
    b.set_arranged(t, &Arrange::Rows).unwrap();
    assert_eq!(b.arranged(t).unwrap(), Some(Arrange::Rows));
}

/// What a window keeps comes back with the store: the open thing, a week, a draft.
#[test]
fn window_state_survives_reopening() {
    use osis::Store;
    let mem = osis::MemStore::new();
    let opening = || osis::internals::Opening::at(Store::Memory(mem.clone()));
    let d = make(osis::internals::create(opening()).unwrap());
    d.main_group().unwrap();
    let t = d.create_note().unwrap();
    let w = WindowState::default();
    let cx = Cx::new(&d, &w, false);
    cx.set_state(osis_kit::schema::WEEK, "cal", &2).unwrap();
    cx.set_state(osis_app::schema::DRAFT, "n#text", &"half".to_string()).unwrap();
    let win = d.window().unwrap();
    drop(cx);
    drop(d);
    let d = make(osis::internals::open(opening()).unwrap());
    assert_eq!(d.opened().unwrap(), Some(t));
    assert_eq!(d.window().unwrap(), win);
    let cx = Cx::new(&d, &w, false);
    assert_eq!(cx.state(osis_kit::schema::WEEK, "cal").unwrap(), Some(2));
    assert_eq!(cx.state(osis_app::schema::DRAFT, "n#text").unwrap().as_deref(), Some("half"));
}

/// Node state keys on the path: two nodes showing one thing have separate state.
#[test]
fn two_nodes_keep_separate_state() {
    use osis_kit::schema::WEEK;
    let d = data();
    let w = WindowState::default();
    let cx = Cx::new(&d, &w, false);
    cx.set_state(WEEK, "page:x/content", &1).unwrap();
    cx.set_state(WEEK, "rail/element:x", &5).unwrap();
    assert_eq!(cx.state(WEEK, "page:x/content").unwrap(), Some(1));
    assert_eq!(cx.state(WEEK, "rail/element:x").unwrap(), Some(5));
}

/// Only the log facet names osis_chat; only its files name a facet's aspect keys.
#[test]
fn chat_stays_in_its_facet() {
    fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        for e in std::fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() { walk(&p, out) } else { out.push(p) }
        }
    }
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    walk(&root.join("src"), &mut files);
    walk(&root.join("../libs/kit/src"), &mut files);
    for f in files {
        let text = std::fs::read_to_string(&f).unwrap();
        let path = f.to_string_lossy();
        if text.contains("osis_chat") {
            assert!(path.ends_with("facets/log.rs"), "{path} names osis_chat");
        }
        if ["/view/", "/views/", "/facets/", "/render/", "store.rs"].iter().any(|d| path.contains("libs/kit") && path.contains(d)) {
            for key in ["event:", "contact:", "chat:", "osis_app:", "event::", "contact::"] {
                assert!(!text.contains(key), "kit's {path} names {key}");
            }
        }
    }
}
