//! The view tree with kit alone: a small app's account group, no app facets.
use osis::core::NAME;
use osis::{Member, Osis, Result, Tid};
use osis_kit::facets::create;
use osis_kit::store::{Account, Data, Registry, keep_a_day};
use osis_kit::view::{Block, Cx, WindowState};
use osis_kit::views::page;
use std::sync::{Arc, Mutex};

/// One group, made on first use.
#[derive(Default)]
struct Small(Mutex<Option<Tid>>);

impl Account for Small {
    fn groups(&self, _: &osis::ReadOnly) -> Result<Vec<Tid>> {
        Ok(self.0.lock().unwrap().iter().copied().collect())
    }
    fn main_group(&self, db: &Osis) -> Result<Tid> {
        let mut g = self.0.lock().unwrap();
        if let Some(t) = *g {
            return Ok(t);
        }
        let mut w = db.write();
        let t = w.create()?;
        // its memberships are what undoing a delete writes back
        keep_a_day(&mut w, t)?;
        w.group(db.home()).add(Member::Item(t))?;
        w.group(db.home()).add(Member::Subgroup(t))?;
        w.commit()?;
        *g = Some(t);
        Ok(t)
    }
}

pub(crate) fn data() -> Data {
    let d = Data::new(osis::internals::create(osis::internals::Opening::memory()).unwrap(), Arc::new(Small::default()), Registry::kit());
    d.main_group().unwrap();
    d
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
    let g = d.main_group().unwrap();
    let mut w = d.db.write();
    let u = w.create().unwrap();
    w.group(g).add(Member::Item(u)).unwrap();
    w.at(u, osis::DynamicAspectKey::untyped(osis::Ak::new("x:y.0").unwrap())).set(&osis::Value::Int(1)).unwrap();
    w.commit().unwrap();
    assert_eq!(view_type(&d, u), "raw");
}

/// The opener's chrome is a node of its own, separate from the content.
#[test]
fn chrome_is_not_content() {
    let d = data();
    let t = create(&d, "tag").unwrap();
    let mut w = d.db.write();
    w.at(t, NAME).set(&"T".to_string()).unwrap();
    w.commit().unwrap();
    let wn = WindowState::default();
    let n = page(&Cx::new(&d, &wn, false), t).unwrap();
    assert!(n.children.iter().any(|c| c.spec.view_type == "chrome"));
    let content = n.children.iter().find(|c| c.spec.view_type == "collection").unwrap();
    assert!(content.out.blocks.iter().all(|b| !matches!(b, Block::Bar { .. } | Block::Tabs(_))));
}

/// Undo works on a thing kit created: an edit, and a delete, which brings the thing back into its
/// group (both keep what they replace: `keep_a_day`).
#[test]
fn undo_works_on_a_kit_created_thing() {
    let d = data();
    let t = d.create_note().unwrap();
    let mut w = d.db.write();
    w.at(t, NAME).set(&"one".to_string()).unwrap();
    w.commit().unwrap();
    let mut w = d.db.write();
    w.at(t, NAME).set(&"two".to_string()).unwrap();
    w.commit().unwrap();
    assert!(d.undo(t).unwrap());
    assert_eq!(d.name(t).unwrap(), "one");
    d.delete(t).unwrap();
    assert!(!d.things().unwrap().contains(&t));
    assert!(d.undo(t).unwrap());
    assert!(d.things().unwrap().contains(&t), "back in its group");
    assert_eq!(d.name(t).unwrap(), "one");
}
