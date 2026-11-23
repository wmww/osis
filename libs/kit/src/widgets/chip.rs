//! A chip: a small pill with a colour dot or an icon and a label (a tag on a thing, an action
//! like "+ Tag" or "Undo"). It is a card in its own colour (else the screen's) and leans with
//! the theme's slant like other cards; a flat chip has no fill until hovered. A removable chip
//! has a × at its end. Emits `ChipPress::Open` for a click on the chip, `Remove` on the ×.

use crate::view::ChipMark;
use crate::text;
use super::{brighten, clickable, clicked, fill_card, key_press, lean, pressed, primary, repaint_on};
use crate::theme::{Card, Look, fade};
use masonry::accesskit::{Node, Role};
use masonry::core::{AccessCtx, AccessEvent, BoxConstraints, BrushIndex, ChildrenIds, EventCtx, LayoutCtx, PaintCtx, PointerEvent, PropertiesMut, PropertiesRef, RegisterCtx, TextEvent, Update, UpdateCtx, Widget};
use masonry::kurbo::{Affine, Circle, Line, Point, RoundedRect, Size, Stroke};
use masonry::parley::Layout;
use masonry::peniko::{Color, Fill};
use masonry::vello::Scene;
use std::sync::Arc;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChipPress {
    Open,
    Remove,
}

pub struct Chip {
    label: String,
    tint: Option<Color>,
    mark: ChipMark,
    removable: bool,
    /// A plain action: no fill until hovered.
    flat: bool,
    look: Arc<Look>,
    text: Option<Layout<BrushIndex>>,
    /// Where the pointer went down: on the × or not.
    down_on_x: bool,
}

const H: f64 = 28.0;
const X_W: f64 = 22.0;

impl Chip {
    pub fn new(label: &str, tint: Option<Color>, mark: ChipMark, look: Arc<Look>) -> Chip {
        Chip { label: label.into(), tint, mark, removable: false, flat: false, look, text: None, down_on_x: false }
    }

    pub fn removable(mut self, on: bool) -> Self {
        self.removable = on;
        self
    }

    pub fn flat(mut self, on: bool) -> Self {
        self.flat = on;
        self
    }

    /// Where the label starts, past the mark.
    const LEAD: f64 = 28.0;
}

impl Widget for Chip {
    type Action = ChipPress;

    fn on_pointer_event(&mut self, ctx: &mut EventCtx<'_>, _props: &mut PropertiesMut<'_>, event: &PointerEvent) {
        if let PointerEvent::Down(e) = event
            && primary(e)
        {
            self.down_on_x = self.removable && ctx.local_position(e.state.position).x > ctx.size().width - X_W - 4.0;
        }
        if pressed(ctx, event) {
            ctx.submit_action::<ChipPress>(if self.down_on_x { ChipPress::Remove } else { ChipPress::Open });
        }
    }

    fn on_text_event(&mut self, ctx: &mut EventCtx<'_>, _props: &mut PropertiesMut<'_>, event: &TextEvent) {
        use masonry::core::keyboard::{Key, NamedKey};
        if key_press(event) {
            ctx.submit_action::<ChipPress>(ChipPress::Open);
        } else if let TextEvent::Keyboard(k) = event
            && k.state.is_up()
            && matches!(k.key, Key::Named(NamedKey::Delete | NamedKey::Backspace))
            && self.removable
        {
            ctx.submit_action::<ChipPress>(ChipPress::Remove);
        }
    }

    fn on_access_event(&mut self, ctx: &mut EventCtx<'_>, _props: &mut PropertiesMut<'_>, event: &AccessEvent) {
        if clicked(event) {
            ctx.submit_action::<ChipPress>(ChipPress::Open);
        }
    }

    fn update(&mut self, ctx: &mut UpdateCtx<'_>, _props: &mut PropertiesMut<'_>, event: &Update) {
        repaint_on(ctx, event);
    }

    fn register_children(&mut self, _ctx: &mut RegisterCtx<'_>) {}

    fn layout(&mut self, ctx: &mut LayoutCtx<'_>, _props: &mut PropertiesMut<'_>, bc: &BoxConstraints) -> Size {
        let look = self.look.clone();
        let (fcx, lcx) = ctx.text_contexts();
        let l = text::layout(fcx, lcx, &look, &self.label, look.text_px(13.0), look.text_weight(), None);
        let w = Self::LEAD + f64::from(l.width()) + if self.removable { X_W } else { 12.0 };
        self.text = Some(l);
        bc.constrain(Size::new(w, H))
    }

    fn paint(&mut self, ctx: &mut PaintCtx<'_>, _props: &PropertiesRef<'_>, scene: &mut Scene) {
        let look = &*self.look;
        let size = ctx.size();
        let tint = self.tint.unwrap_or(look.main);
        let skew = lean(look.shear(), size);
        let rect = RoundedRect::from_rect(size.to_rect(), (look.radius() * 100.0).min(size.height / 2.0));
        let hovered = ctx.is_hovered();
        let card = look.card(Some(tint));
        let (fg, muted) = if self.flat { (look.fg, look.muted) } else { (card.fg, card.muted) };
        if self.flat {
            if hovered {
                scene.fill(Fill::NonZero, skew, fade(look.fg, 0.07), None, &rect);
            }
        } else {
            let c = if hovered { Card { top: brighten(card.top), bottom: brighten(card.bottom), ..card } } else { card };
            fill_card(scene, look, rect, &c, skew);
        }
        if ctx.is_focus_target() {
            scene.stroke(&Stroke::new(1.5), skew, look.main, None, &rect);
        }
        let mid = size.height / 2.0;
        match self.mark {
            ChipMark::Dot => scene.fill(Fill::NonZero, Affine::IDENTITY, tint, None, &Circle::new((15.0, mid), 4.0)),
            ChipMark::Icon(i) => i.paint(scene, (8.0, mid - 7.0), 14.0, if self.flat { muted } else { fg }, false),
        }
        if let Some(l) = &self.text {
            let c = if self.flat { muted } else { fg };
            text::draw(scene, l, Point::new(Self::LEAD, mid - f64::from(l.height()) / 2.0), c);
        }
        if self.removable {
            let cx = size.width - X_W / 2.0 - 3.0;
            let c = fade(fg, if hovered { 0.8 } else { 0.45 });
            let st = Stroke::new(1.5);
            scene.stroke(&st, Affine::IDENTITY, c, None, &Line::new((cx - 3.5, mid - 3.5), (cx + 3.5, mid + 3.5)));
            scene.stroke(&st, Affine::IDENTITY, c, None, &Line::new((cx + 3.5, mid - 3.5), (cx - 3.5, mid + 3.5)));
        }
    }

    fn accessibility_role(&self) -> Role {
        Role::Button
    }

    fn accessibility(&mut self, _ctx: &mut AccessCtx<'_>, _props: &PropertiesRef<'_>, node: &mut Node) {
        clickable(node, &self.label);
    }

    fn children_ids(&self) -> ChildrenIds {
        ChildrenIds::new()
    }

    fn accepts_focus(&self) -> bool {
        true
    }
}
