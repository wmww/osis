//! `osis_app:color.0`: a thing's colour when nothing better gives it one.

use crate::schema::COLOR;
use osis::{Result, Tid};
use osis_kit::view::{Cx, Facet, Section, Summary};

pub struct ColorFacet;
pub static FACET: ColorFacet = ColorFacet;

impl Facet for ColorFacet {
    fn id(&self) -> &'static str {
        "color"
    }
    fn claims(&self, ak: &str) -> bool {
        ak == "osis_app:color.0"
    }
    fn universal(&self) -> bool {
        true
    }
    fn summarize(&self, cx: &Cx<'_>, t: Tid, s: &mut Summary) -> Result<()> {
        if s.color.is_none() {
            s.color = cx.data.db.at(t, COLOR).get()?;
        }
        Ok(())
    }
    fn show(&self, _: &Cx<'_>, _: Tid) -> Result<Section> {
        Ok(Section::default())
    }
}
