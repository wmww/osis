//! Which tags a thing is in. Tagging places and nests only, and shares nothing (notes/tags.md).

use crate::view::{Act, Action, Block, Chip, ChipMark, Cx, Do, Facet, Icon, Input, Section, Toggle};
use crate::schema::PICKING;
use osis::{Result, Tid};

pub struct PlacesFacet;
pub static FACET: PlacesFacet = PlacesFacet;

#[derive(Clone, Debug, PartialEq)]
struct AddTag(Tid, Tid);
impl Action for AddTag {
    fn run(&self, act: &Act, _: &Input) -> Result<()> {
        act.add_tag(self.0, self.1)
    }
}

#[derive(Clone, Debug, PartialEq)]
struct RemoveTag(Tid, Tid);
impl Action for RemoveTag {
    fn run(&self, act: &Act, _: &Input) -> Result<()> {
        act.remove_tag(self.0, self.1)
    }
}

impl Facet for PlacesFacet {
    fn id(&self) -> &'static str {
        "places"
    }
    fn show(&self, cx: &Cx, t: Tid) -> Result<Section> {
        let open = cx.flag(PICKING, &cx.path())?;
        let tags = cx.tags_of(t)?;
        let tag_chip = |tag: Tid, press: Do, remove: Option<Do>| -> Result<Chip> { Ok(Chip { label: cx.name(tag)?, color: cx.own_color(tag)?, mark: ChipMark::Dot, flat: false, press: Some(press), remove }) };
        let mut chips = Vec::new();
        for tag in &tags {
            chips.push(tag_chip(*tag, Do::new(crate::view::Open(Some(*tag))), Some(Do::new(RemoveTag(t, *tag))))?);
        }
        chips.push(Chip::action(Icon::Plus, if open { "Done" } else { "Tag" }, Do::new(Toggle(PICKING, cx.path()))));
        let mut blocks = vec![Block::Chips(chips)];
        if open {
            let others: Vec<Tid> = cx.all_tags()?.into_iter().filter(|tag| !tags.contains(tag) && *tag != t).collect();
            blocks.push(Block::Label("Add a tag".into()));
            if others.is_empty() {
                blocks.push(Block::Line("No other tags yet.".into()));
            }
            let mut pick = Vec::new();
            for tag in others {
                pick.push(tag_chip(tag, Do::new(AddTag(t, tag)), None)?);
            }
            blocks.push(Block::Chips(pick));
        }
        Ok(Section::of(blocks))
    }
}
