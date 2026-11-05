//! A chip: a small pill with a colour dot or an icon and a label (a tag on a thing, an action
//! like "+ Tag" or "Undo"). It leans with the theme's slant like other cards. A removable chip
//! has a × at its end. Emits `ChipPress::Open` for a click on the chip, `Remove` on the ×.

use crate::icons::Icon;
use crate::text;
use crate::theme::{Look, fade, mix, neutral};
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

/// What a chip shows before its label.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ChipMark {
    /// A dot in the chip's colour (a tag).
    Dot,
    Icon(Icon),
    None,
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

    fn lead(&self) -> f64 {
        match self.mark {
            ChipMark::None => 11.0,
            _ => 28.0,
        }
    }
}

impl Widget for Chip {
    type Action = ChipPress;

    fn on_pointer_event(&mut self, ctx: &mut EventCtx<'_>, _props: &mut PropertiesMut<'_>, event: &PointerEvent) {
        match event {
            PointerEvent::Down(e) => {
                let x = ctx.local_position(e.state.position).x;
                self.down_on_x = self.removable && x > ctx.size().width - X_W - 4.0;
                ctx.capture_pointer();
                ctx.request_paint_only();
            }
            PointerEvent::Up(..) => {
                if ctx.is_active() && ctx.is_hovered() {
                    ctx.submit_action::<ChipPress>(if self.down_on_x { ChipPress::Remove } else { ChipPress::Open });
                }
                ctx.request_paint_only();
            }
            _ => {}
        }
    }

    fn on_text_event(&mut self, ctx: &mut EventCtx<'_>, _props: &mut PropertiesMut<'_>, event: &TextEvent) {
        use masonry::core::keyboard::{Key, NamedKey};
        if let TextEvent::Keyboard(k) = event
            && k.state.is_up()
        {
            match &k.key {
                Key::Named(NamedKey::Enter) => ctx.submit_action::<ChipPress>(ChipPress::Open),
                Key::Character(c) if c == " " => ctx.submit_action::<ChipPress>(ChipPress::Open),
                Key::Named(NamedKey::Delete | NamedKey::Backspace) if self.removable => ctx.submit_action::<ChipPress>(ChipPress::Remove),
                _ => {}
            }
        }
    }

    fn on_access_event(&mut self, ctx: &mut EventCtx<'_>, _props: &mut PropertiesMut<'_>, event: &AccessEvent) {
        if event.action == masonry::accesskit::Action::Click {
            ctx.submit_action::<ChipPress>(ChipPress::Open);
        }
    }

    fn update(&mut self, ctx: &mut UpdateCtx<'_>, _props: &mut PropertiesMut<'_>, event: &Update) {
        if matches!(event, Update::HoveredChanged(_) | Update::ActiveChanged(_) | Update::FocusChanged(_)) {
            ctx.request_paint_only();
        }
    }

    fn register_children(&mut self, _ctx: &mut RegisterCtx<'_>) {}

    fn layout(&mut self, ctx: &mut LayoutCtx<'_>, _props: &mut PropertiesMut<'_>, bc: &BoxConstraints) -> Size {
        let look = self.look.clone();
        let (fcx, lcx) = ctx.text_contexts();
        let l = text::layout(fcx, lcx, &look, &self.label, 13.0, 500.0, None);
        let w = self.lead() + f64::from(l.width()) + if self.removable { X_W } else { 12.0 };
        self.text = Some(l);
        bc.constrain(Size::new(w, H))
    }

    fn paint(&mut self, ctx: &mut PaintCtx<'_>, _props: &PropertiesRef<'_>, scene: &mut Scene) {
        let look = &*self.look;
        let size = ctx.size();
        let tint = self.tint.unwrap_or_else(neutral);
        let k = look.theme.slant.to_radians().tan();
        let skew = Affine::translate((size.height * 0.5 * k, 0.0)) * Affine::skew(-k, 0.0);
        let rect = RoundedRect::from_rect(size.to_rect(), (look.theme.radius * 100.0).min(size.height / 2.0));
        let hovered = ctx.is_hovered();
        let fill = if self.flat {
            if hovered { Some(fade(look.fg, 0.07)) } else { None }
        } else {
            let base = look.card(None);
            Some(mix(base, tint, if hovered { 0.32 } else { 0.22 }))
        };
        if let Some(f) = fill {
            scene.fill(Fill::NonZero, skew, f, None, &rect);
        }
        if ctx.is_focus_target() {
            scene.stroke(&Stroke::new(1.5), skew, look.accent, None, &rect);
        }
        let mid = size.height / 2.0;
        match self.mark {
            ChipMark::Dot => scene.fill(Fill::NonZero, Affine::IDENTITY, tint, None, &Circle::new((15.0, mid), 4.0)),
            ChipMark::Icon(i) => i.paint(scene, (8.0, mid - 7.0), 14.0, if self.flat { look.muted } else { look.fg }, false),
            ChipMark::None => {}
        }
        if let Some(l) = &self.text {
            let c = if self.flat { look.muted } else { look.fg };
            text::draw(scene, l, Point::new(self.lead(), mid - f64::from(l.height()) / 2.0), c);
        }
        if self.removable {
            let cx = size.width - X_W / 2.0 - 3.0;
            let c = fade(look.fg, if hovered { 0.8 } else { 0.45 });
            let st = Stroke::new(1.5);
            scene.stroke(&st, Affine::IDENTITY, c, None, &Line::new((cx - 3.5, mid - 3.5), (cx + 3.5, mid + 3.5)));
            scene.stroke(&st, Affine::IDENTITY, c, None, &Line::new((cx + 3.5, mid - 3.5), (cx - 3.5, mid + 3.5)));
        }
    }

    fn accessibility_role(&self) -> Role {
        Role::Button
    }

    fn accessibility(&mut self, _ctx: &mut AccessCtx<'_>, _props: &PropertiesRef<'_>, node: &mut Node) {
        node.set_label(self.label.clone());
        node.add_action(masonry::accesskit::Action::Click);
    }

    fn children_ids(&self) -> ChildrenIds {
        ChildrenIds::new()
    }

    fn accepts_focus(&self) -> bool {
        true
    }
}
