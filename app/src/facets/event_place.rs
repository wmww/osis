//! `event:location.0`: where a thing happens.

use crate::event::LOCATION;
use osis_kit::view::{Block, Cx, Facet, Icon, Offer, Section, Summary, TextRole};
use osis::{Result, Tid};

pub struct PlaceFacet;
pub static FACET: PlaceFacet = PlaceFacet;

fn start(_: &osis_kit::store::Data, w: &mut osis::Write<'_>, t: Tid, _g: Tid) -> Result<()> {
    w.at(t, LOCATION).set(&String::new())
}

impl Facet for PlaceFacet {
    fn id(&self) -> &'static str {
        "event-place"
    }
    fn claims(&self, ak: &str) -> bool {
        ak == "event:location.0"
    }
    fn summarize(&self, cx: &Cx<'_>, t: Tid, s: &mut Summary) -> Result<()> {
        if s.sub.is_empty() {
            s.sub = cx.data.db.at(t, LOCATION).get()?.unwrap_or_default();
        }
        Ok(())
    }
    fn show(&self, _cx: &Cx<'_>, t: Tid) -> Result<Section> {
        Ok(Section::of(vec![Block::Editor { thing: t, ak: "event:location.0".into(), key: None, placeholder: "Where".into(), role: TextRole::Muted, multiline: false, lead: None }]))
    }
    fn search(&self, cx: &Cx<'_>, t: Tid) -> Result<Vec<String>> {
        Ok(cx.data.db.at(t, LOCATION).get()?.into_iter().collect())
    }
    fn offers(&self, cx: &Cx<'_>, t: Option<Tid>) -> Result<Vec<Offer>> {
        Ok(match t {
            Some(t) if !cx.has(t, "event:location.0")? => vec![Offer { id: "place", label: "Place", icon: Icon::Event, set: start }],
            _ => Vec::new(),
        })
    }
}
