//! A panel: one child on the theme's panel surface (fill at panel opacity, outline and shadow
//! fading with it), or an inset (a faint fill, no outline) or a field (opaque-ish surface with
//! the outline).

use super::shadow;
use crate::theme::{Look, fade, mix};
use masonry::accesskit::{Node, Role};
use masonry::core::{AccessCtx, BoxConstraints, ChildrenIds, LayoutCtx, NewWidget, PaintCtx, PropertiesMut, PropertiesRef, RegisterCtx, Widget, WidgetMut, WidgetPod};
use masonry::kurbo::{Affine, Insets, Point, RoundedRect, Size, Stroke};
use masonry::vello::Scene;
use std::sync::Arc;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PanelKind {
    Panel,
    Inset,
    Field,
}

pub struct Panel {
    child: WidgetPod<dyn Widget>,
    look: Arc<Look>,
    kind: PanelKind,
    /// Padding before spacing, (vertical, horizontal) px.
    pad: (f64, f64),
    /// Fill the offered width.
    fill_width: bool,
    fill_height: bool,
}

impl Panel {
    pub fn new(child: NewWidget<impl Widget + ?Sized>, look: Arc<Look>, kind: PanelKind, pad: (f64, f64)) -> Panel {
        Panel { child: child.erased().to_pod(), look, kind, pad, fill_width: true, fill_height: false }
    }

    pub fn fill_height(mut self, on: bool) -> Self {
        self.fill_height = on;
        self
    }

    pub fn fill_width(mut self, on: bool) -> Self {
        self.fill_width = on;
        self
    }

    pub fn child_mut<'t>(this: &'t mut WidgetMut<'_, Self>) -> WidgetMut<'t, dyn Widget> {
        this.ctx.get_mut(&mut this.widget.child)
    }

    fn radius(&self) -> f64 {
        let r = self.look.theme.radius;
        match self.kind {
            PanelKind::Panel => r * 1.35,
            PanelKind::Inset | PanelKind::Field => r * 0.8,
        }
    }
}

impl Widget for Panel {
    type Action = masonry::core::NoAction;

    fn register_children(&mut self, ctx: &mut RegisterCtx<'_>) {
        ctx.register_child(&mut self.child);
    }

    fn layout(&mut self, ctx: &mut LayoutCtx<'_>, _props: &mut PropertiesMut<'_>, bc: &BoxConstraints) -> Size {
        let (v, h) = (self.look.sp(self.pad.0), self.look.sp(self.pad.1));
        let cbc = bc.shrink((2.0 * h, 2.0 * v)).loosen();
        let mut cbc = cbc;
        if self.fill_width && bc.is_width_bounded() {
            cbc = BoxConstraints::new(Size::new(cbc.max().width, cbc.min().height), cbc.max());
        }
        if self.fill_height && bc.is_height_bounded() {
            cbc = BoxConstraints::new(Size::new(cbc.min().width, cbc.max().height), cbc.max());
        }
        let cs = ctx.run_layout(&mut self.child, &cbc);
        ctx.place_child(&mut self.child, Point::new(h, v));
        let size = bc.constrain(Size::new(cs.width + 2.0 * h, cs.height + 2.0 * v));
        let (dx, dy) = self.look.shadow_offset(1.5);
        let b = self.look.theme.shadow_blur * 2.5;
        ctx.set_paint_insets(Insets::new((b - dx).max(0.0), (b - dy).max(0.0), (b + dx).max(0.0), (b + dy).max(0.0)));
        size
    }

    fn paint(&mut self, ctx: &mut PaintCtx<'_>, _props: &PropertiesRef<'_>, scene: &mut Scene) {
        let look = &*self.look;
        let rect = RoundedRect::from_rect(ctx.size().to_rect(), self.radius());
        let op = look.theme.panel_opacity;
        match self.kind {
            PanelKind::Panel => {
                if op > 0.0 {
                    let mut l = look.clone();
                    l.shadow = fade(l.shadow, op);
                    shadow(scene, &l, rect, 1.5, Affine::IDENTITY);
                    scene.fill(masonry::peniko::Fill::NonZero, Affine::IDENTITY, look.panel, None, &rect);
                    // gloss on a panel: only a faint lit top edge
                    if look.theme.gloss > 0.0 {
                        let r = rect.rect();
                        let g = masonry::peniko::Gradient::new_linear((r.x0, r.y0), (r.x0, r.y0 + 24.0))
                            .with_stops([(0.0, fade(masonry::peniko::Color::WHITE, look.theme.gloss * 0.18)), (1.0, fade(masonry::peniko::Color::WHITE, 0.0))]);
                        scene.fill(masonry::peniko::Fill::NonZero, Affine::IDENTITY, &g, None, &rect);
                    }
                    if look.theme.outline > 0.0 {
                        let ow = look.theme.outline;
                        scene.stroke(&Stroke::new(ow), Affine::IDENTITY, fade(look.outline, op), None, &rect.rect().inset(-ow / 2.0).to_rounded_rect(self.radius()));
                    }
                }
            }
            PanelKind::Inset => {
                scene.fill(masonry::peniko::Fill::NonZero, Affine::IDENTITY, fade(look.fg, 0.04), None, &rect);
            }
            PanelKind::Field => {
                let bg = fade(mix(look.surface, look.main, 0.03), 0.62 + op * 0.38);
                scene.fill(masonry::peniko::Fill::NonZero, Affine::IDENTITY, bg, None, &rect);
                if look.theme.outline > 0.0 {
                    let ow = look.theme.outline;
                    scene.stroke(&Stroke::new(ow), Affine::IDENTITY, look.outline, None, &rect.rect().inset(-ow / 2.0).to_rounded_rect(self.radius()));
                }
            }
        }
    }

    fn accessibility_role(&self) -> Role {
        Role::GenericContainer
    }

    fn accessibility(&mut self, _ctx: &mut AccessCtx<'_>, _props: &PropertiesRef<'_>, _node: &mut Node) {}

    fn children_ids(&self) -> ChildrenIds {
        ChildrenIds::from_slice(&[self.child.id()])
    }
}
