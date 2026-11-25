//! The app's account: the seeds its home starts with, and the registry of what the app adds to
//! kit.

use crate::facets;
use crate::schema::COLOR;
use osis::core::NAME;
use osis::{Result, Role, Weak};
use osis_kit::schema::{Arrange, COLLECTION, Collection, CollectionOrder as Order, CollectionSource as Source, FAVORITES};
use osis_kit::store::{Data, Registry, start_setting};

/// The collections every home offers: config, name, colour.
fn seeds() -> Vec<(Collection, &'static str, &'static str)> {
    let v = |source, having: &[&str], order, arrange| Collection { source, having: having.iter().map(|s| s.to_string()).collect(), order, arrange, element: None };
    vec![
        (v(Source::Everything, &["event:start.0"], Order::Time, Arrange::Days), "Calendar", "#f97316"),
        (v(Source::Everything, &["contact:"], Order::Name, Arrange::Cards), "People", "#06b6d4"),
        (v(Source::Everything, &["tag.0"], Order::Name, Arrange::Outline), "Tags", "#8b5cf6"),
        (v(Source::Everything, &[], Order::Changed, Arrange::Rows), "Recent", "#64748b"),
    ]
}

/// Seeds home (the account) where it is here and has no collection yet: its collection of the
/// favorites, the seeded views among them and, by an admin node, the setting kit's things start
/// with. A node paired a moment ago holds none of the account yet and seeds nothing: the
/// account's seeds reach it.
fn seed(d: &Data) -> Result<()> {
    let g = d.home()?;
    if osis_account::Realm::at(g).profile(&d.db)?.is_none() || d.db.at(g, COLLECTION).get()?.is_some() {
        return Ok(());
    }
    let mut w = d.db.write();
    if d.db.role_on(g)? == Some(Role::Admin) {
        start_setting(&mut w, g)?;
    }
    w.at(g, COLLECTION).set(&Collection { source: Source::Favorites, having: Default::default(), order: Order::Own, arrange: Arrange::Cards, element: None })?;
    let mut favs = Vec::new();
    for (v, name, color) in seeds() {
        let t = w.create(g, None)?;
        start_setting(&mut w, t)?;
        w.at(t, COLLECTION).set(&v)?;
        w.at(t, NAME).set(&name.to_string())?;
        w.at(t, COLOR).set(&color.to_string())?;
        w.hold(g, t)?;
        favs.push(Weak(t));
    }
    // an edit, not a set: a favorite another node adds meanwhile stays
    w.at(g, FAVORITES).edit(&Vec::new(), &favs)?;
    w.commit()?;
    Ok(())
}

/// Kit's registry with the app's facets and view types.
pub fn registry() -> Registry {
    Registry::kit()
        .with_facet_before("body", &facets::event_time::FACET)
        .with_facet_before("body", &facets::event_place::FACET)
        .with_facet_before("body", &facets::contact::FACET)
        .with_facet_before("body", &facets::log::FACET)
        .with_facet_before("body", &facets::color::FACET)
        .with_view_before("note", &crate::views::STREAM)
        .with_view_before("note", &crate::views::EVENT)
        .with_view_before("note", &crate::views::PERSON)
}

/// The app's `Data` over `db`, a node acting for an account, its home seeded.
pub fn data(db: osis::Osis) -> Result<Data> {
    let d = Data::new(db, registry());
    for s in [&crate::schema::SCHEMA, &crate::event::SCHEMA, &crate::contact::SCHEMA] {
        // a store error here shows again at the first write
        if let Err(e) = d.db.register_schema(s.file(), s.source()) {
            eprintln!("osis-app: schema: {e}");
        }
    }
    seed(&d)?;
    Ok(d)
}
