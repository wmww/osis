//! A heading mark in the main colour (notes/theming.md `mark`): a slash leaning with the slant
//! or a dot before a heading, or a small dot after the brand. Sized from the heading's font size.

use super::lean;
use crate::theme::Look;
use masonry::accesskit::{Node, Role};
use masonry::core::{AccessCtx, BoxConstraints, ChildrenIds, LayoutCtx, PaintCtx, PropertiesMut, PropertiesRef, RegisterCtx, Widget};
use masonry::kurbo::{Affine, Circle, Rect, Size};
use masonry::peniko::{Color, Fill};
use masonry::vello::Scene;

enum Kind {
    Slash,
    Dot,
    After,
}

pub struct Mark {
    kind: Kind,
    color: Color,
    shear: f64,
    /// The heading's font size, px.
    em: f64,
    sp: f64,
}

impl Mark {
    /// Before a heading of font size `em`: a dot, else a slash.
    pub fn new(look: &Look, dot: bool, em: f64) -> Mark {
        Mark { kind: if dot { Kind::Dot } else { Kind::Slash }, color: look.main, shear: look.shear(), em, sp: look.sp(1.0) }
    }

    /// The dot after the brand.
    pub fn after(look: &Look, em: f64) -> Mark {
        Mark { kind: Kind::After, color: look.main, shear: 0.0, em, sp: 1.0 }
    }

    /// (mark width, gap after it, height).
    fn dims(&self) -> (f64, f64, f64) {
        let em = self.em;
        match self.kind {
            Kind::Slash => ((em * 0.2).max(4.0), em * 0.5 * self.sp, em * 0.85),
            Kind::Dot => (em * 0.5, em * 0.6 * self.sp, em * 0.5),
            Kind::After => (em * 0.3, em * 0.08, em * 0.3),
        }
    }
}

impl Widget for Mark {
    type Action = masonry::core::NoAction;

    fn register_children(&mut self, _ctx: &mut RegisterCtx<'_>) {}

    fn layout(&mut self, _ctx: &mut LayoutCtx<'_>, _props: &mut PropertiesMut<'_>, bc: &BoxConstraints) -> Size {
        let (w, gap, h) = self.dims();
        // the dot after the brand sits on the baseline: room below it for the descent
        let below = if matches!(self.kind, Kind::After) { self.em * 0.28 } else { 0.0 };
        bc.constrain(Size::new(w + gap, h + below))
    }

    fn paint(&mut self, _ctx: &mut PaintCtx<'_>, _props: &PropertiesRef<'_>, scene: &mut Scene) {
        let (w, gap, h) = self.dims();
        match self.kind {
            Kind::Slash => {
                let r = Rect::new(0.0, 0.0, w, h);
                scene.fill(Fill::NonZero, lean(self.shear, r.size()), self.color, None, &r);
            }
            Kind::Dot => scene.fill(Fill::NonZero, Affine::IDENTITY, self.color, None, &Circle::new((w / 2.0, h / 2.0), w / 2.0)),
            Kind::After => scene.fill(Fill::NonZero, Affine::IDENTITY, self.color, None, &Circle::new((gap + w / 2.0, h / 2.0), w / 2.0)),
        }
    }

    fn accessibility_role(&self) -> Role {
        Role::GenericContainer
    }

    fn accessibility(&mut self, _ctx: &mut AccessCtx<'_>, _props: &PropertiesRef<'_>, _node: &mut Node) {}

    fn children_ids(&self) -> ChildrenIds {
        ChildrenIds::new()
    }
}
