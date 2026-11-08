//! "Add" on every designed view: the same offers that made it (notes/app.md Create).

use crate::view::{Action, Block, Chip, Cx, Do, Facet, Icon, Input, Section};
use crate::schema::ADDING;
use osis::{Result, Tid};

pub struct AddFacet;
pub static FACET: AddFacet = AddFacet;

#[derive(Clone, Debug, PartialEq)]
struct Toggle(String);
impl Action for Toggle {
    fn run(&self, cx: &Cx<'_>, _: &Input) -> Result<()> {
        if cx.state(ADDING, &self.0)?.unwrap_or(false) {
            cx.clear_state(ADDING, &self.0)
        } else {
            cx.set_state(ADDING, &self.0, &true)
        }
    }
}

impl Facet for AddFacet {
    fn id(&self) -> &'static str {
        "add"
    }
    fn claims(&self, _: &str) -> bool {
        false
    }
    fn applies(&self, cx: &Cx<'_>, t: Tid) -> Result<bool> {
        Ok(!cx.data.is_app(t)?)
    }
    fn universal(&self) -> bool {
        true
    }
    fn show(&self, cx: &Cx<'_>, t: Tid) -> Result<Section> {
        let open = cx.state(ADDING, &cx.path())?.unwrap_or(false);
        let mut blocks = vec![Block::Chips(vec![Chip::action(Icon::Plus, if open { "Done" } else { "Add" }, Do::new(Toggle(cx.path())))])];
        if open {
            blocks.push(Block::Chips(cx.offer_chips(Some(t))?));
        }
        Ok(Section::of(blocks))
    }
}
