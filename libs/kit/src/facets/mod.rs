//! The registry of facets (notes/app.md Facet): the only list of them.

pub mod about;
pub mod add;
pub mod body;
pub mod fields;
pub mod look;
pub mod members;
pub mod name;
pub mod places;

use crate::store::Data;
use crate::view::{Cx, Facet, Offer, WindowState};
use osis::{Result, Tid};

/// Kit's facets of core aspects, in the order they contribute to a summary (an app inserts its
/// own among them).
pub fn kit() -> [&'static dyn Facet; 8] {
    [&name::FACET, &members::FACET, &body::FACET, &look::FACET, &places::FACET, &about::FACET, &fields::FACET, &add::FACET]
}

/// The offer with this id: facets offer the same set for new things and additions.
pub fn offer(cx: &Cx<'_>, id: &str) -> Result<Option<Offer>> {
    for f in cx.data.registry.facets.iter() {
        if let Some(o) = f.offers(cx, None)?.into_iter().find(|o| o.id == id) {
            return Ok(Some(o));
        }
    }
    Ok(None)
}

/// A new thing through the offer `id`, opened on this node.
pub fn create(d: &Data, id: &str) -> Result<Tid> {
    let w = WindowState::default();
    let cx = Cx::new(d, &w, false);
    let o = offer(&cx, id)?.ok_or_else(|| osis::Error::Invalid(format!("no offer {id}")))?;
    d.create_with(o.set)
}
