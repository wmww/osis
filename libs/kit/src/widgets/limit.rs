//! Centres one child horizontally at no more than `max` width (a readable column on a wide window).

use masonry::accesskit::{Node, Role};
use masonry::core::{AccessCtx, BoxConstraints, ChildrenIds, LayoutCtx, NewWidget, PaintCtx, PropertiesMut, PropertiesRef, RegisterCtx, Widget, WidgetPod};
use masonry::kurbo::{Point, Size};
use masonry::vello::Scene;

pub struct Limit {
    child: WidgetPod<dyn Widget>,
    max: f64,
}

impl Limit {
    pub fn new(child: NewWidget<impl Widget + ?Sized>, max: f64) -> Limit {
        Limit { child: child.erased().to_pod(), max }
    }
}

impl Widget for Limit {
    type Action = masonry::core::NoAction;

    fn register_children(&mut self, ctx: &mut RegisterCtx<'_>) {
        ctx.register_child(&mut self.child);
    }

    fn layout(&mut self, ctx: &mut LayoutCtx<'_>, _props: &mut PropertiesMut<'_>, bc: &BoxConstraints) -> Size {
        let avail = if bc.is_width_bounded() { bc.max().width } else { self.max };
        let w = avail.min(self.max);
        let cbc = BoxConstraints::new(Size::new(w, bc.min().height), Size::new(w, bc.max().height));
        let s = ctx.run_layout(&mut self.child, &cbc);
        ctx.place_child(&mut self.child, Point::new(((avail - w) / 2.0).max(0.0), 0.0));
        bc.constrain(Size::new(avail, s.height))
    }

    fn paint(&mut self, _ctx: &mut PaintCtx<'_>, _props: &PropertiesRef<'_>, _scene: &mut Scene) {}

    fn accessibility_role(&self) -> Role {
        Role::GenericContainer
    }

    fn accessibility(&mut self, _ctx: &mut AccessCtx<'_>, _props: &PropertiesRef<'_>, _node: &mut Node) {}

    fn children_ids(&self) -> ChildrenIds {
        ChildrenIds::from_slice(&[self.child.id()])
    }
}

/// The shortest a page with a list in it is laid out (Minor: a window shorter than this scrolls the
/// whole page, so what sits around the list stays reachable and the list keeps some room; 0 gives
/// a short window's list no height, infinity scrolls every page).
const MIN_PAGE: f64 = 520.0;

/// Fills the height it is given, but never less than `MIN_PAGE`: its child's flexible parts get
/// what that leaves, and a shorter parent scrolls it.
pub struct MinHeight {
    child: WidgetPod<dyn Widget>,
}

impl MinHeight {
    pub fn new(child: NewWidget<dyn Widget>) -> MinHeight {
        MinHeight { child: child.to_pod() }
    }
}

impl Widget for MinHeight {
    type Action = masonry::core::NoAction;

    fn register_children(&mut self, ctx: &mut RegisterCtx<'_>) {
        ctx.register_child(&mut self.child);
    }

    fn layout(&mut self, ctx: &mut LayoutCtx<'_>, _props: &mut PropertiesMut<'_>, bc: &BoxConstraints) -> Size {
        let h = if bc.is_height_bounded() { bc.max().height.max(MIN_PAGE) } else { MIN_PAGE };
        let s = ctx.run_layout(&mut self.child, &BoxConstraints::tight(Size::new(bc.max().width, h)));
        ctx.place_child(&mut self.child, Point::ZERO);
        Size::new(bc.max().width, s.height)
    }

    fn paint(&mut self, _ctx: &mut PaintCtx<'_>, _props: &PropertiesRef<'_>, _scene: &mut Scene) {}

    fn accessibility_role(&self) -> Role {
        Role::GenericContainer
    }

    fn accessibility(&mut self, _ctx: &mut AccessCtx<'_>, _props: &PropertiesRef<'_>, _node: &mut Node) {}

    fn children_ids(&self) -> ChildrenIds {
        ChildrenIds::from_slice(&[self.child.id()])
    }
}
