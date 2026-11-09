//! The app's account: its group among home's subgroups (marked `osis_app:app.0`), the first-use
//! seeds, and the registry of what the app adds to kit.

use crate::facets;
use crate::schema::{APP, COLOR};
use osis::core::NAME;
use osis::{Member, Osis, Result, Tid};
use osis_kit::schema::{Arrange, COLLECTION, Collection, CollectionOrder as Order, CollectionSource as Source, FAVORITES};
use osis_kit::store::{Account, Data, Registry};
use osis_kit::view::Db;
use std::sync::Arc;

/// Finds or makes the app's group.
pub struct AppAccount;

/// The collections every account group offers: config, name, colour.
fn seeds() -> Vec<(Collection, &'static str, &'static str)> {
    let v = |source, having: &[&str], order, arrange| Collection { source, having: having.iter().map(|s| s.to_string()).collect(), order, arrange, element: None };
    vec![
        (v(Source::Everything, &["event:start.0"], Order::Time, Arrange::Days), "Calendar", "#f97316"),
        (v(Source::Everything, &["contact:"], Order::Name, Arrange::Cards), "People", "#06b6d4"),
        (v(Source::Everything, &["tag.0"], Order::Name, Arrange::Outline), "Tags", "#8b5cf6"),
        (v(Source::Everything, &[], Order::Changed, Arrange::Rows), "Recent", "#64748b"),
    ]
}

impl Account for AppAccount {
    /// The groups marked as the app's among home's subgroups, smallest tid first.
    /// Works around issues/app-group-helper.md (as does merging favorites, collections, look).
    fn groups(&self, db: &Db) -> Result<Vec<Tid>> {
        let home = db.me();
        let mut out = Vec::new();
        for m in db.members(home)? {
            if let Member::Subgroup(t) = m
                && t != home
                && db.at(t, APP).get()? == Some(true)
            {
                out.push(t);
            }
        }
        Ok(out)
    }

    fn main_group(&self, db: &Osis) -> Result<Tid> {
        if let Some(g) = self.groups(&Db::new(db.clone()))?.first() {
            return Ok(*g);
        }
        let mut w = db.write();
        // an item of home (its own aspects sync) and a subgroup (its items sync: a group's
        // members are its items and its subgroups' members, not its items' items)
        let g = w.create()?;
        w.at(g, APP).set(&true)?;
        w.at(g, COLLECTION).set(&Collection { source: Source::Favorites, having: Default::default(), order: Order::Own, arrange: Arrange::Cards, element: None })?;
        w.group(db.me()).add(Member::Item(g))?;
        w.group(db.me()).add(Member::Subgroup(g))?;
        let mut favs = Vec::new();
        for (v, name, color) in seeds() {
            let t = w.create()?;
            w.at(t, COLLECTION).set(&v)?;
            w.at(t, NAME).set(&name.to_string())?;
            w.at(t, COLOR).set(&color.to_string())?;
            w.group(g).add(Member::Item(t))?;
            favs.push(t);
        }
        w.at(g, FAVORITES).set(&favs)?;
        w.commit()?;
        Ok(g)
    }
}

/// Kit's registry with the app's facets and view types.
pub fn registry() -> Registry {
    Registry::kit()
        .with_facet_before("body", &facets::event_time::FACET)
        .with_facet_before("body", &facets::event_place::FACET)
        .with_facet_before("body", &facets::contact::FACET)
        .with_facet_before("body", &facets::log::FACET)
        .with_facet_before("body", &facets::color::FACET)
        .with_view_before("note", &crate::views::stream::VIEW)
        .with_view_before("note", &crate::views::event::VIEW)
        .with_view_before("note", &crate::views::person::VIEW)
}

/// The app's `Data` over `db`.
pub fn data(db: Osis) -> Data {
    let d = Data::new(db, Arc::new(AppAccount), registry());
    for s in [&crate::schema::SCHEMA, &crate::event::SCHEMA, &crate::contact::SCHEMA] {
        // a store error here shows again at the first write
        if let Err(e) = d.db.register_schema(s.file(), s.source()) {
            eprintln!("osis-app: schema: {e}");
        }
    }
    d
}

/// Whether demo data was added to this account's group.
pub fn has_demo(d: &Data) -> Result<bool> {
    for g in d.groups()? {
        if d.db.at(g, crate::schema::DEMO).get()? == Some(true) {
            return Ok(true);
        }
    }
    Ok(false)
}
