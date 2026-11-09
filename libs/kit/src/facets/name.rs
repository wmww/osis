//! `name.0`: a thing's title.

use crate::store::Reader;
use crate::view::{Block, Cx, Facet, Icon, Mark, Offer, Section, Summary, TextRole};
use osis::core::NAME;
use osis::{Result, Tid};

pub struct NameFacet;
pub static FACET: NameFacet = NameFacet;

/// Gives `t` a name of its own.
fn start(_: &crate::store::Data, w: &mut osis::Write<'_>, t: Tid, _g: Tid) -> Result<()> {
    w.at(t, NAME).set(&String::new())
}

impl Facet for NameFacet {
    fn id(&self) -> &'static str {
        "name"
    }
    fn claims(&self, ak: &str) -> bool {
        ak == "name.0"
    }
    fn universal(&self) -> bool {
        true
    }
    fn summarize(&self, cx: &Reader, t: Tid, s: &mut Summary) -> Result<()> {
        s.name = cx.name(t)?;
        Ok(())
    }
    fn show(&self, cx: &Cx, t: Tid) -> Result<Section> {
        let s = cx.summary(t)?;
        let cfg = cx.config();
        if cfg.get("title") == Some("none") {
            return Ok(Section::default());
        }
        if cfg.flag("compact") || cfg.flag("read_only") {
            return Ok(Section::of(vec![Block::Label(s.name)]));
        }
        if !cx.has(t, "name.0")? {
            return Ok(Section::of(vec![Block::Heading(s.name)]));
        }
        let lead = match s.mark {
            Mark::Initials(_) => Some((s.mark, s.color)),
            Mark::Icon(_) => None,
        };
        Ok(Section::of(vec![Block::Editor { thing: t, ak: "name.0".into(), key: None, placeholder: "Untitled".into(), role: TextRole::Title, multiline: false, lead }]))
    }
    fn offers(&self, cx: &Reader, t: Option<Tid>) -> Result<Vec<Offer>> {
        let Some(t) = t else { return Ok(Vec::new()) };
        if cx.has(t, "name.0")? {
            return Ok(Vec::new());
        }
        Ok(vec![Offer { id: "name", label: "Name", icon: Icon::Note, set: start }])
    }
}
