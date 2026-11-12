//! A panel: one child on the theme's panel colour (flat; its alpha is panel opacity, which the
//! outline and shadow follow), or an inset (a faint fill, no outline), or a field (the panel
//! colour at least 62% opaque, with the outline and the tile shadow, leaning with the slant).

use super::{lean, shadow};
use crate::theme::{Look, fade};
use masonry::accesskit::{Node, Role};
use masonry::core::{AccessCtx, BoxConstraints, ChildrenIds, LayoutCtx, NewWidget, PaintCtx, PropertiesMut, PropertiesRef, RegisterCtx, Update, UpdateCtx, Widget, WidgetMut, WidgetPod};
use masonry::kurbo::{Affine, Insets, Point, RoundedRect, Size, Stroke};
use masonry::vello::Scene;
use std::sync::Arc;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PanelKind {
    Panel,
    Inset,
    Field,
    /// A raised inset in the accent (today in a calendar).
    Highlight,
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
    /// Emit `Blur` when the keyboard focus leaves the child (a form field saving its text).
    report_blur: bool,
}

/// The keyboard focus left a panel's child (`Panel::report_blur`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Blur;

impl Panel {
    pub fn new(child: NewWidget<impl Widget + ?Sized>, look: Arc<Look>, kind: PanelKind, pad: (f64, f64)) -> Panel {
        Panel { child: child.erased().to_pod(), look, kind, pad, fill_width: true, fill_height: false, report_blur: false }
    }

    pub fn fill_height(mut self, on: bool) -> Self {
        self.fill_height = on;
        self
    }

    pub fn report_blur(mut self, on: bool) -> Self {
        self.report_blur = on;
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
        let r = self.look.radius();
        match self.kind {
            PanelKind::Panel => r * 1.35,
            PanelKind::Inset | PanelKind::Field | PanelKind::Highlight => r * 0.8,
        }
    }
}

impl Widget for Panel {
    type Action = Blur;

    fn update(&mut self, ctx: &mut UpdateCtx<'_>, _props: &mut PropertiesMut<'_>, event: &Update) {
        if self.report_blur && matches!(event, Update::ChildFocusChanged(false)) {
            ctx.submit_action::<Blur>(Blur);
        }
    }

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
        let b = self.look.shadow_blur(2.5);
        ctx.set_paint_insets(Insets::new((b - dx).max(0.0), (b - dy).max(0.0), (b + dx).max(0.0), (b + dy).max(0.0)));
        size
    }

    fn paint(&mut self, ctx: &mut PaintCtx<'_>, _props: &PropertiesRef<'_>, scene: &mut Scene) {
        use masonry::peniko::{Color, Fill, Gradient};
        let look = &*self.look;
        let size = ctx.size();
        let rect = RoundedRect::from_rect(size.to_rect(), self.radius());
        let ow = look.outline_width();
        let outline = |scene: &mut Scene, xf: Affine, c: Color| {
            if ow > 0.0 {
                scene.stroke(&Stroke::new(ow), xf, c, None, &rect.rect().inset(-ow / 2.0).to_rounded_rect(self.radius()));
            }
        };
        let id = Affine::IDENTITY;
        match self.kind {
            PanelKind::Panel => {
                let op = look.panel_opacity();
                if op > 0.0 {
                    shadow(scene, look, rect, (1.5, 2.5), fade(look.shadow, op), id);
                    scene.fill(Fill::NonZero, id, look.panel, None, &rect);
                    // a blurring panel has a faint lit top edge
                    let lit = (look.theme.panel_blur * 0.04).clamp(0.0, 1.0);
                    if lit > 0.0 {
                        let hi = fade(Color::WHITE, if look.dark { 0.14 } else { 0.75 } * lit * op);
                        let r = rect.rect();
                        let g = Gradient::new_linear((r.x0, r.y0), (r.x0, r.y0 + 2.0)).with_stops([(0.0, hi), (1.0, fade(hi, 0.0))]);
                        scene.fill(Fill::NonZero, id, &g, None, &rect);
                    }
                    outline(scene, id, fade(look.outline, op));
                }
            }
            PanelKind::Inset => {
                scene.fill(Fill::NonZero, id, fade(look.fg, 0.04), None, &rect);
            }
            PanelKind::Highlight => {
                scene.fill(Fill::NonZero, id, fade(look.fg, 0.04), None, &rect);
                let w = 2.0;
                scene.stroke(&Stroke::new(w), id, look.main, None, &rect.rect().inset(-w / 2.0).to_rounded_rect((self.radius() - w / 2.0).max(0.0)));
            }
            PanelKind::Field => {
                let xf = lean(look.shear(), size);
                shadow(scene, look, rect, (1.0, 1.0), look.shadow, xf);
                scene.fill(Fill::NonZero, xf, look.field(), None, &rect);
                outline(scene, xf, look.outline);
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
