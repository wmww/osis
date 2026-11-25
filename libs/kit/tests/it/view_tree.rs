//! The view tree with kit alone: a small app's home, no app facets.
use osis::core::NAME;
use osis::{Osis, Result, Tid};
use osis_kit::facets::create;
use osis_kit::store::{Account, Data, Registry, start_setting};
use osis_kit::view::{Block, Cx, WindowState};
use osis_kit::views::page;
use std::sync::{Arc, Mutex};

/// One home, made on first use.
#[derive(Default)]
pub(crate) struct Small(Mutex<Option<Tid>>);

impl Account for Small {
    fn homes(&self, _: &osis::ReadOnly) -> Result<Vec<Tid>> {
        Ok(self.0.lock().unwrap().iter().copied().collect())
    }
    fn home(&self, db: &Osis) -> Result<Tid> {
        let mut g = self.0.lock().unwrap();
        if let Some(t) = *g {
            return Ok(t);
        }
        let mut w = db.write();
        let root = db.node();
        let t = w.create(root, None)?;
        // its strongs are what undoing a delete writes back
        start_setting(&mut w, t)?;
        w.hold(root, t)?;
        w.commit()?;
        *g = Some(t);
        Ok(t)
    }
}

pub(crate) fn data() -> Data {
    let d = Data::new(osis::internals::create(osis::internals::Opening::memory()).unwrap(), Arc::new(Small::default()), Registry::kit());
    d.home().unwrap();
    d
}

/// Names `t` `n`, in a commit of its own.
pub(crate) fn name(d: &Data, t: Tid, n: &str) {
    let mut w = d.db.write();
    w.at(t, NAME).set(&n.to_string()).unwrap();
    w.commit().unwrap();
}

/// A new note named `n`.
pub(crate) fn note(d: &Data, n: &str) -> Tid {
    let t = d.create_note().unwrap();
    name(d, t, n);
    t
}

fn view_type(d: &Data, t: Tid) -> String {
    let w = WindowState::default();
    let n = page(&Cx::new(d, &w, false), t).unwrap();
    n.children.iter().find(|c| !matches!(c.spec.view_type.as_str(), "bar" | "chrome")).unwrap().spec.view_type.clone()
}

/// With kit alone a note opens as a note and an unknown thing as raw.
#[test]
fn kit_alone_opens_things() {
    let d = data();
    let t = d.create_note().unwrap();
    assert_eq!(view_type(&d, t), "note");
    let g = d.home().unwrap();
    let mut w = d.db.write();
    let u = w.create(g, None).unwrap();
    w.hold(g, u).unwrap();
    w.at(u, osis::DynamicAspectKey::untyped(osis::Ak::new("x:y.0").unwrap())).set(&osis::Value::Int(1)).unwrap();
    w.commit().unwrap();
    assert_eq!(view_type(&d, u), "raw");
}

/// The opener's chrome is a node of its own, separate from the content.
#[test]
fn chrome_is_not_content() {
    let d = data();
    let t = create(&d, "tag").unwrap();
    name(&d, t, "T");
    let wn = WindowState::default();
    let n = page(&Cx::new(&d, &wn, false), t).unwrap();
    assert!(n.children.iter().any(|c| c.spec.view_type == "chrome"));
    let content = n.children.iter().find(|c| c.spec.view_type == "collection").unwrap();
    assert!(content.out.blocks.iter().all(|b| !matches!(b, Block::Bar { .. } | Block::Tabs(_))));
}

/// Undo works on a thing kit created: an edit keeps what it replaces (`start_setting`). A delete
/// releases the thing: it has no undo.
#[test]
fn undo_works_on_a_kit_created_thing() {
    let d = data();
    let t = note(&d, "one");
    name(&d, t, "two");
    assert!(d.undo(t).unwrap());
    assert_eq!(d.name(t).unwrap(), "one");
    d.delete(t).unwrap();
    assert!(!d.things().unwrap().contains(&t));
}

/// A thing made here from an offer is to have its title typed in: the field to type in next
/// names that, and the thing's page has the field.
#[test]
fn a_new_things_title_is_the_field_to_type_in() {
    use osis_kit::facets::name::TITLE;
    use osis_kit::view::{Act, Action, Input, TYPE_IN, UseOffer};
    let d = data();
    let w = WindowState::default();
    UseOffer("note", None).run(&Act::new(&d, &w), &Input::Press).unwrap();
    let t = d.opened().unwrap().unwrap();
    assert_eq!(w.graph.peek(TYPE_IN), Some((t, TITLE)));
    let n = page(&Cx::new(&d, &w, false), t).unwrap();
    assert!(n.blocks().iter().any(|b| matches!(b, Block::Editor { thing, ak, .. } if *thing == t && ak == TITLE)));
}
