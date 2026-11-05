//! A grid of tiles: as many equal columns as fit at `min` width each, rows as tall as their
//! tallest tile. A reorderable grid lets the pointer drag a tile to another place: past a few
//! pixels of movement a drop mark shows where it would go, and the drop emits `Reorder` (the
//! app decides; the grid does not move anything itself). The last `fixed` children (a "new"
//! tile) neither move nor take a drop after them.

use crate::theme::Look;
use masonry::accesskit::{Node, Role};
use masonry::core::{AccessCtx, BoxConstraints, ChildrenIds, EventCtx, LayoutCtx, NewWidget, PaintCtx, PointerEvent, PropertiesMut, PropertiesRef, RegisterCtx, Widget, WidgetMut, WidgetPod};
use masonry::kurbo::{Affine, Rect};
use masonry::peniko::Fill;
use masonry::kurbo::{Point, Size};
use masonry::vello::Scene;
use std::sync::Arc;

pub struct TileGrid {
    children: Vec<WidgetPod<dyn Widget>>,
    look: Arc<Look>,
    /// Least column width, px.
    min: f64,
    /// Most columns (0: no limit).
    max_cols: usize,
    /// Space between tiles before spacing, px.
    gap: f64,
    /// Children at the end that do not take part in reordering; `None`: not reorderable.
    fixed: Option<usize>,
    /// Each child's rect, from the last layout.
    rects: Vec<Rect>,
    /// A press on a child: (its index, where it started); dragging once it moved past the slop.
    press: Option<(usize, Point)>,
    /// The drop index while dragging.
    drop: Option<usize>,
}

/// A tile was dragged from index `from` to index `to` (in the order without it moved).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reorder {
    pub from: usize,
    pub to: usize,
}

/// How far (logical px) a press moves before it is a drag: below, a tremble stays a click.
const SLOP: f64 = 6.0;

impl TileGrid {
    pub fn new(look: Arc<Look>, min: f64) -> TileGrid {
        TileGrid { children: Vec::new(), look, min, max_cols: 0, gap: 12.0, fixed: None, rects: Vec::new(), press: None, drop: None }
    }

    /// At most `n` columns (a list: 1).
    pub fn max_cols(mut self, n: usize) -> Self {
        self.max_cols = n;
        self
    }

    /// Children can be dragged into another order; the last `fixed` ones stay.
    pub fn reorderable(mut self, fixed: usize) -> Self {
        self.fixed = Some(fixed);
        self
    }

    fn movable(&self) -> usize {
        self.children.len().saturating_sub(self.fixed.unwrap_or(0))
    }

    /// The drop index for a pointer at `p`: before the first movable child whose centre is
    /// after `p` in reading order.
    fn drop_at(&self, p: Point) -> usize {
        let n = self.movable();
        self.rects.iter().take(n).position(|r| p.y < r.y0 || (p.y < r.y1 && p.x < r.center().x)).unwrap_or(n)
    }

    pub fn gap(mut self, px: f64) -> Self {
        self.gap = px;
        self
    }

    pub fn with_child(mut self, child: NewWidget<impl Widget + ?Sized>) -> Self {
        self.children.push(child.erased().to_pod());
        self
    }

    pub fn len(&self) -> usize {
        self.children.len()
    }

    pub fn is_empty(&self) -> bool {
        self.children.is_empty()
    }

    pub fn add_child(this: &mut WidgetMut<'_, Self>, child: NewWidget<impl Widget + ?Sized>) {
        this.widget.children.push(child.erased().to_pod());
        this.ctx.children_changed();
        this.ctx.request_layout();
    }

    pub fn clear(this: &mut WidgetMut<'_, Self>) {
        for c in std::mem::take(&mut this.widget.children) {
            this.ctx.remove_child(c);
        }
        this.ctx.request_layout();
    }
}

impl Widget for TileGrid {
    type Action = Reorder;

    fn on_pointer_event(&mut self, ctx: &mut EventCtx<'_>, _props: &mut PropertiesMut<'_>, event: &PointerEvent) {
        if self.fixed.is_none() {
            return;
        }
        match event {
            PointerEvent::Down(e) => {
                let p = ctx.local_position(e.state.position);
                let n = self.movable();
                self.press = self.rects.iter().take(n).position(|r| r.contains(p)).map(|i| (i, p));
                self.drop = None;
            }
            PointerEvent::Move(e) => {
                let Some((_, start)) = self.press else { return };
                let p = ctx.local_position(e.current.position);
                if self.drop.is_some() || (p - start).hypot() > SLOP {
                    let d = Some(self.drop_at(p));
                    if d != self.drop {
                        self.drop = d;
                        ctx.request_paint_only();
                    }
                }
            }
            PointerEvent::Up(..) => {
                if let (Some((from, _)), Some(d)) = (self.press, self.drop) {
                    // the index in the order without the dragged tile
                    let to = if d > from { d - 1 } else { d };
                    if to != from {
                        ctx.submit_action::<Reorder>(Reorder { from, to });
                    }
                    ctx.request_paint_only();
                }
                self.press = None;
                self.drop = None;
            }
            PointerEvent::Cancel(..) => {
                self.press = None;
                if self.drop.take().is_some() {
                    ctx.request_paint_only();
                }
            }
            _ => {}
        }
    }

    fn register_children(&mut self, ctx: &mut RegisterCtx<'_>) {
        for c in &mut self.children {
            ctx.register_child(c);
        }
    }

    fn layout(&mut self, ctx: &mut LayoutCtx<'_>, _props: &mut PropertiesMut<'_>, bc: &BoxConstraints) -> Size {
        let gap = self.look.sp(self.gap);
        let width = if bc.is_width_bounded() { bc.max().width } else { self.min * 3.0 + gap * 2.0 };
        let mut cols = (((width + gap) / (self.min + gap)).floor() as usize).max(1);
        if self.max_cols > 0 {
            cols = cols.min(self.max_cols);
        }
        let cw = ((width - gap * (cols as f64 - 1.0)) / cols as f64).max(0.0);
        let mut y = 0.0;
        self.rects.clear();
        for row in self.children.chunks_mut(cols) {
            let mut h: f64 = 0.0;
            for c in row.iter_mut() {
                let s = ctx.run_layout(c, &BoxConstraints::new(Size::new(cw, 0.0), Size::new(cw, f64::INFINITY)));
                h = h.max(s.height);
            }
            // a second pass makes the row's tiles equally tall
            for (i, c) in row.iter_mut().enumerate() {
                ctx.run_layout(c, &BoxConstraints::tight(Size::new(cw, h)));
                let at = Point::new(i as f64 * (cw + gap), y);
                ctx.place_child(c, at);
                self.rects.push(Rect::from_origin_size(at, (cw, h)));
            }
            y += h + gap;
        }
        let height = if self.children.is_empty() { 0.0 } else { y - gap };
        bc.constrain(Size::new(width, height))
    }

    fn paint(&mut self, _ctx: &mut PaintCtx<'_>, _props: &PropertiesRef<'_>, scene: &mut Scene) {
        // the drop mark: a bar at the leading edge of the slot (the trailing edge of the last)
        let Some(d) = self.drop else { return };
        let (x, r) = match (self.rects.get(d), d.checked_sub(1).and_then(|i| self.rects.get(i))) {
            (Some(r), _) if d < self.movable() => (r.x0 - self.look.sp(self.gap) / 2.0, *r),
            (_, Some(r)) => (r.x1 + self.look.sp(self.gap) / 2.0, *r),
            _ => return,
        };
        let horizontal = r.width() > r.height() * 3.0 && self.max_cols == 1;
        let bar = if horizontal {
            let y = if d < self.movable() { r.y0 - self.look.sp(self.gap) / 2.0 } else { r.y1 + self.look.sp(self.gap) / 2.0 };
            Rect::new(r.x0, y - 1.5, r.x1, y + 1.5)
        } else {
            Rect::new(x - 1.5, r.y0, x + 1.5, r.y1)
        };
        scene.fill(Fill::NonZero, Affine::IDENTITY, self.look.accent, None, &bar.to_rounded_rect(1.5));
    }

    fn accessibility_role(&self) -> Role {
        Role::List
    }

    fn accessibility(&mut self, _ctx: &mut AccessCtx<'_>, _props: &PropertiesRef<'_>, _node: &mut Node) {}

    fn children_ids(&self) -> ChildrenIds {
        self.children.iter().map(|c| c.id()).collect()
    }
}
