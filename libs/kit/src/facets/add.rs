//! "Add" on every designed view: the same offers that made it (notes/app.md Create).

use crate::store::Reader;
use crate::view::{Block, Chip, Cx, Do, Facet, Icon, Section, Toggle};
use crate::schema::ADDING;
use osis::{Result, Tid};

pub struct AddFacet;
pub static FACET: AddFacet = AddFacet;

impl Facet for AddFacet {
    fn id(&self) -> &'static str {
        "add"
    }
    fn claims(&self, _: &str) -> bool {
        false
    }
    fn applies(&self, _: &Reader, _: Tid) -> Result<bool> {
        Ok(true)
    }
    fn universal(&self) -> bool {
        true
    }
    fn show(&self, cx: &Cx, t: Tid) -> Result<Section> {
        let open = cx.flag(ADDING, &cx.path())?;
        let mut blocks = vec![Block::Chips(vec![Chip::action(Icon::Plus, if open { "Done" } else { "Add" }, Do::new(Toggle(ADDING, cx.path())))])];
        if open {
            blocks.push(Block::Chips(cx.offer_chips(Some(t))?));
        }
        Ok(Section::of(blocks))
    }
}
