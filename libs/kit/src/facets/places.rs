//! Which tags a thing is in. Tagging places and nests only, and shares nothing (notes/tags.md).

use crate::store::Reader;
use crate::view::{Act, Action, Block, Chip, ChipMark, Cx, Do, Facet, Icon, Input, Section};
use crate::schema::PICKING;
use osis::{Result, Tid};

pub struct PlacesFacet;
pub static FACET: PlacesFacet = PlacesFacet;

#[derive(Clone, Debug, PartialEq)]
struct TogglePicker(String);
impl Action for TogglePicker {
    fn run(&self, act: &Act, _: &Input) -> Result<()> {
        if act.state(PICKING, &self.0)?.unwrap_or(false) {
            act.clear_state(PICKING, &self.0)
        } else {
            act.set_state(PICKING, &self.0, &true)
        }
    }
}

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
        let d = cx;
        let open = cx.state(PICKING, &cx.path())?.unwrap_or(false);
        let tags = d.tags_of(t)?;
        let tag_chip = |g: Tid, press: Do, remove: Option<Do>| -> Result<Chip> { Ok(Chip { label: d.name(g)?, color: d.own_color(g)?, mark: ChipMark::Dot, flat: false, press: Some(press), remove }) };
        let mut chips = Vec::new();
        for g in &tags {
            chips.push(tag_chip(*g, Do::new(crate::view::Open(Some(*g))), Some(Do::new(RemoveTag(t, *g))))?);
        }
        chips.push(Chip::action(Icon::Plus, if open { "Done" } else { "Tag" }, Do::new(TogglePicker(cx.path()))));
        let mut blocks = vec![Block::Chips(chips)];
        if open {
            let others: Vec<Tid> = d.all_tags()?.into_iter().filter(|g| !tags.contains(g) && *g != t).collect();
            blocks.push(Block::Label("Add a tag".into()));
            if others.is_empty() {
                blocks.push(Block::Line("No other tags yet.".into()));
            }
            let mut pick = Vec::new();
            for g in others {
                pick.push(tag_chip(g, Do::new(AddTag(t, g)), None)?);
            }
            blocks.push(Block::Chips(pick));
        }
        Ok(Section::of(blocks))
    }
}
