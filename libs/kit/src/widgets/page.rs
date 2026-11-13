//! A page's one vertical scroller. A page lays out at the height it is given and one scroll
//! reaches all of it; two scrollers are never nested on one axis. Its parts, in order: a head
//! (`head`: a thing's bar), its content, a foot (`foot`: a composer).
//!
//! - Without a list, the content gets the page's height when it fits in it (what fills takes
//!   what is left), else its own height, and scrolls. Nothing is squeezed below its own height.
//! - With a list (`Link`), the page is that list: what is above it on the page and what is below
//!   are the list's leading and trailing rows, and the list holds the page's one scroll position
//!   (`VirtualList`). The list's widget is laid out at the page's height (or its rows', when
//!   shorter) and the page only moves the content by what the list says.
//! - The head and foot are pinned (stay put) while the page keeps at least as much height as they
//!   take; on a shorter page they are its first and last parts and scroll with it.
//!
//! So at any height every part is reachable, nothing scrolls when everything fits, and exactly
//! one bar shows: the list's, else the page's. A page inside another page is plain content of it.

use super::vlist::{GUTTER, MIN_THUMB, VirtualList, paint_thumb};
use crate::theme::Look;
use masonry::accesskit::{Action, Node, Role};
use masonry::core::{AccessCtx, AccessEvent, AllowRawMut, BoxConstraints, ChildrenIds, EventCtx, LayoutCtx, NewWidget, PaintCtx, PointerEvent, PointerScrollEvent, PropertiesMut, PropertiesRef, RegisterCtx, ScrollDelta, Update, UpdateCtx, Widget, WidgetId, WidgetPod};
use masonry::kurbo::{Point, Size};
use masonry::vello::Scene;
use std::cell::RefCell;
use std::sync::{Arc, Mutex, MutexGuard};

/// What a page and its list tell each other.
#[derive(Default)]
pub(crate) struct Link {
    /// The page is measuring its content: the first list laid out holds the page.
    pub measuring: bool,
    /// The list holding the page, its rows' height at the page's width when measured, and
    /// whether those are all its rows.
    pub list: Option<WidgetId>,
    pub rows: f64,
    pub whole: bool,
    /// For the list's layout: the height of what is above it and below it on the page, and the
    /// page's viewport height.
    pub a: f64,
    pub b: f64,
    pub v: f64,
    pub vh: f64,
    /// From the list's layout: how far the page is moved, its rows' height (its height is `vh`),
    /// the list's one position and its range.
    pub s: f64,
    pub r: f64,
    pub t: f64,
    pub t_min: f64,
    pub t_max: f64,
    /// The list moved by input since the page's last layout.
    pub moved: bool,
}

pub(crate) type LinkRef = Arc<Mutex<Link>>;

pub(crate) fn lock(l: &LinkRef) -> MutexGuard<'_, Link> {
    l.lock().unwrap_or_else(|e| e.into_inner())
}

thread_local! {
    /// The page whose content is being laid out (layout is depth-first on one thread).
    static PAGE: RefCell<Option<LinkRef>> = const { RefCell::new(None) };
}

/// The page around a widget being laid out.
pub(crate) fn current() -> Option<LinkRef> {
    PAGE.with(|p| p.borrow().clone())
}

/// What a scroll step means in logical px.
pub(crate) fn wheel(delta: &ScrollDelta, scale: f64) -> f64 {
    match delta {
        ScrollDelta::PixelDelta(p) => -p.to_logical::<f64>(scale).y,
        ScrollDelta::LineDelta(_, y) => f64::from(-*y) * super::vlist::LINE,
        _ => 0.0,
    }
}

/// The part of `v` a target `y0..y1` (viewport coordinates) must move by to show, its top when it
/// is taller than the viewport.
pub(crate) fn into_view(y0: f64, y1: f64, v: f64) -> f64 {
    if y0 < 0.0 {
        y0
    } else if y1 > v {
        (y1 - v).min(y0)
    } else {
        0.0
    }
}

/// The content's viewport: clips it and moves it by the page's scroll.
struct View {
    child: WidgetPod<dyn Widget>,
    link: LinkRef,
    /// Set by the page before each layout: what the content is laid out at, where its top is
    /// (the head's height when that scrolls), and the page's own scroll (no list).
    bc: BoxConstraints,
    top: f64,
    s: f64,
    /// Plain content of an outer page: the outer page is the one its lists hold.
    plain: bool,
    /// From the last layout: the content's height.
    height: f64,
}

impl AllowRawMut for View {}

impl Widget for View {
    type Action = masonry::core::NoAction;

    fn register_children(&mut self, ctx: &mut RegisterCtx<'_>) {
        ctx.register_child(&mut self.child);
    }

    fn update(&mut self, _ctx: &mut UpdateCtx<'_>, _props: &mut PropertiesMut<'_>, _event: &Update) {}

    fn layout(&mut self, ctx: &mut LayoutCtx<'_>, _props: &mut PropertiesMut<'_>, bc: &BoxConstraints) -> Size {
        if self.plain {
            self.height = ctx.run_layout(&mut self.child, &self.bc).height;
            ctx.place_child(&mut self.child, Point::ZERO);
            ctx.clear_clip_path();
            return bc.max();
        }
        let outer = PAGE.with(|p| p.replace(Some(self.link.clone())));
        self.height = ctx.run_layout(&mut self.child, &self.bc).height;
        PAGE.with(|p| p.replace(outer));
        let l = lock(&self.link);
        let s = if l.list.is_some() && !l.measuring { l.s } else { self.s };
        drop(l);
        ctx.place_child(&mut self.child, Point::new(0.0, self.top - s));
        let size = bc.max();
        // clipped above and below while something scrolls; never at the sides (a panel's shadow)
        if s > 0.5 || self.top + self.height > size.height + 0.5 {
            ctx.set_clip_path(masonry::kurbo::Rect::new(-size.width, 0.0, 2.0 * size.width, size.height));
        } else {
            ctx.clear_clip_path();
        }
        size
    }

    fn paint(&mut self, _ctx: &mut PaintCtx<'_>, _props: &PropertiesRef<'_>, _scene: &mut Scene) {}

    fn accessibility_role(&self) -> Role {
        Role::GenericContainer
    }

    fn accessibility(&mut self, _ctx: &mut AccessCtx<'_>, _props: &PropertiesRef<'_>, node: &mut Node) {
        node.set_clips_children();
    }

    fn children_ids(&self) -> ChildrenIds {
        ChildrenIds::from_slice(&[self.child.id()])
    }
}

pub struct Page {
    view: WidgetPod<View>,
    head: Option<WidgetPod<dyn Widget>>,
    foot: Option<WidgetPod<dyn Widget>>,
    look: Arc<Look>,
    link: LinkRef,
    /// Space between the head, the content and the foot.
    gap: f64,
    /// Inside another page (or under no height), so plain content.
    plain: bool,
    /// The page's own scroll (no list), its range, and the viewport's top and height.
    s: f64,
    range: f64,
    view_y: f64,
    v: f64,
    /// The head and foot are pinned.
    pinned: bool,
    /// What the last measure was taken under: constraints, viewport, scrolled head and foot.
    measured: Option<(BoxConstraints, f64, f64, f64)>,
    content_bc: BoxConstraints,
    /// The page draws its own bar (nothing else shows one).
    own_bar: bool,
    /// Holding the thumb, this far below its top.
    grab: Option<f64>,
    /// The page moved by input since its last layout.
    moved: bool,
}

impl Page {
    pub fn new(child: NewWidget<impl Widget + ?Sized>, look: Arc<Look>) -> Page {
        let link = LinkRef::default();
        let view = View { child: child.erased().to_pod(), link: link.clone(), bc: BoxConstraints::UNBOUNDED, top: 0.0, s: 0.0, plain: false, height: 0.0 };
        Page { view: NewWidget::new(view).to_pod(), head: None, foot: None, look, link, gap: 0.0, plain: false, s: 0.0, range: 0.0, view_y: 0.0, v: 0.0, pinned: true, measured: None, content_bc: BoxConstraints::UNBOUNDED, own_bar: false, grab: None, moved: false }
    }

    /// What goes above the content (pinned while it fits), `gap` from it.
    pub fn with_head(mut self, head: NewWidget<impl Widget + ?Sized>, gap: f64) -> Self {
        self.head = Some(head.erased().to_pod());
        self.gap = gap;
        self
    }

    /// What goes below the content (pinned while it fits), `gap` from it.
    pub fn with_foot(mut self, foot: NewWidget<impl Widget + ?Sized>, gap: f64) -> Self {
        self.foot = Some(foot.erased().to_pod());
        self.gap = gap;
        self
    }

    /// The thumb's height and top, when the page draws its bar.
    fn thumb(&self) -> Option<(f64, f64)> {
        if !self.own_bar {
            return None;
        }
        let total = self.v + self.range;
        let h = (self.v * self.v / total).clamp(MIN_THUMB.min(self.v), self.v);
        Some((h, self.view_y + self.s / self.range.max(1.0) * (self.v - h)))
    }

    /// Moves the page by `d`, through its list when it has one. `false`: nothing moved.
    fn scroll(&mut self, ctx: &mut EventCtx<'_>, d: f64) -> bool {
        let mut l = lock(&self.link);
        if let Some(id) = l.list {
            let to = (l.t + d).clamp(l.t_min, l.t_max.max(l.t_min));
            if (to - l.t).abs() < 0.01 {
                return false;
            }
            l.t = to;
            drop(l);
            ctx.mutate_widget_later(id, move |mut w| {
                if let Some(mut list) = w.try_downcast::<VirtualList>() {
                    VirtualList::scroll_by(&mut list, d);
                }
            });
            return true;
        }
        drop(l);
        let to = (self.s + d).clamp(0.0, self.range);
        if (to - self.s).abs() < 0.01 {
            return false;
        }
        self.s = to;
        self.moved = true;
        ctx.request_layout();
        true
    }

    /// The head's and foot's heights, with the gap each keeps from the content.
    fn ends(&mut self, ctx: &mut LayoutCtx<'_>, w: f64) -> (f64, f64) {
        let natural = BoxConstraints::new(Size::new(w, 0.0), Size::new(w, f64::INFINITY));
        let gap = self.gap;
        let mut h = |p: &mut Option<WidgetPod<dyn Widget>>| p.as_mut().map_or(0.0, |p| ctx.run_layout(p, &natural).height + gap);
        (h(&mut self.head), h(&mut self.foot))
    }

    /// Sets what the view lays its content out at and where, and lays it out at `v`.
    fn run_view(&mut self, ctx: &mut LayoutCtx<'_>, w: f64, v: f64, bc: BoxConstraints, top: f64, s: f64) -> f64 {
        // the list lays out again in each pass (measuring, then for the page), whatever it is given
        if let Some(id) = lock(&self.link).list {
            ctx.request_layout_of(id);
        }
        let (view, mut raw) = ctx.get_raw_mut(&mut self.view);
        (view.bc, view.top, view.s, view.plain) = (bc, top, s, self.plain);
        raw.request_layout();
        drop(raw);
        ctx.run_layout(&mut self.view, &BoxConstraints::tight(Size::new(w, v)));
        ctx.get_raw(&mut self.view).0.height
    }
}

impl Widget for Page {
    type Action = masonry::core::NoAction;

    fn on_pointer_event(&mut self, ctx: &mut EventCtx<'_>, _props: &mut PropertiesMut<'_>, event: &PointerEvent) {
        if self.plain {
            return;
        }
        match event {
            PointerEvent::Scroll(PointerScrollEvent { delta, .. }) => {
                if self.scroll(ctx, wheel(delta, ctx.get_scale_factor())) {
                    ctx.set_handled();
                }
            }
            PointerEvent::Down(e) => {
                let p = ctx.local_position(e.state.position);
                let Some((h, y)) = self.thumb().filter(|_| p.x >= ctx.size().width - GUTTER) else { return };
                ctx.capture_pointer();
                let on = p.y >= y && p.y < y + h;
                let grab = if on { p.y - y } else { h / 2.0 };
                self.grab = Some(grab);
                if !on {
                    let to = (p.y - self.view_y - grab) / (self.v - h).max(1.0) * self.range;
                    self.s = to.clamp(0.0, self.range);
                    self.moved = true;
                    ctx.request_layout();
                }
                ctx.set_handled();
            }
            PointerEvent::Move(e) if self.grab.is_some() => {
                let (h, _) = self.thumb().unwrap_or((0.0, 0.0));
                let y = ctx.local_position(e.current.position).y - self.view_y - self.grab.unwrap_or(0.0);
                self.s = (y / (self.v - h).max(1.0) * self.range).clamp(0.0, self.range);
                self.moved = true;
                ctx.request_layout();
            }
            PointerEvent::Up(..) | PointerEvent::Cancel(..) if self.grab.is_some() => {
                self.grab = None;
                ctx.request_paint_only();
            }
            _ => {}
        }
    }

    fn on_access_event(&mut self, ctx: &mut EventCtx<'_>, _props: &mut PropertiesMut<'_>, event: &AccessEvent) {
        let d = match event.action {
            Action::ScrollUp => -self.v * 0.9,
            Action::ScrollDown => self.v * 0.9,
            _ => return,
        };
        if !self.plain && self.scroll(ctx, d) {
            ctx.set_handled();
        }
    }

    fn update(&mut self, ctx: &mut UpdateCtx<'_>, _props: &mut PropertiesMut<'_>, event: &Update) {
        // bring an area (the page's coordinates) into view; the pinned head and foot always show
        let Update::RequestPanToChild(r) = event else { return };
        let in_head = self.head.is_some() && r.y1 <= self.view_y + 0.5;
        let in_foot = self.foot.is_some() && r.y0 >= self.view_y + self.v - 0.5;
        if self.plain || (self.pinned && (in_head || in_foot)) {
            return;
        }
        let l = lock(&self.link);
        if let Some(id) = l.list {
            // where the area is in the one position's terms: what is above the list is where it
            // is, the list's rows are moved inside it by `t - s`, what is below follows all rows
            let virt = |y: f64| {
                let y = y - self.view_y + l.s;
                if y < l.a {
                    y
                } else if y < l.a + l.vh {
                    y + (l.t - l.s)
                } else {
                    y + (l.r - l.vh)
                }
            };
            let d = into_view(virt(r.y0) - l.t, virt(r.y1) - l.t, self.v);
            drop(l);
            if d == 0.0 {
                return;
            }
            ctx.mutate_widget_later(id, move |mut w| {
                if let Some(mut list) = w.try_downcast::<VirtualList>() {
                    VirtualList::bring_by(&mut list, d);
                }
            });
            return;
        }
        drop(l);
        let d = into_view(r.y0 - self.view_y, r.y1 - self.view_y, self.v);
        let to = (self.s + d).clamp(0.0, self.range);
        if to != self.s {
            self.s = to;
            self.moved = true;
            ctx.request_layout();
        }
    }

    fn register_children(&mut self, ctx: &mut RegisterCtx<'_>) {
        ctx.register_child(&mut self.view);
        if let Some(h) = &mut self.head {
            ctx.register_child(h);
        }
        if let Some(f) = &mut self.foot {
            ctx.register_child(f);
        }
    }

    fn layout(&mut self, ctx: &mut LayoutCtx<'_>, _props: &mut PropertiesMut<'_>, bc: &BoxConstraints) -> Size {
        let w = bc.max().width;
        self.plain = current().is_some() || !bc.is_height_bounded();
        if self.plain {
            // a column at its own height
            self.own_bar = false;
            lock(&self.link).list = None;
            let (hh, hf) = self.ends(ctx, w);
            // the content under what the page is given, less the head and foot
            let less = |h: f64| (h - hh - hf).max(0.0);
            let inner = BoxConstraints::new(Size::new(w, less(bc.min().height)), Size::new(w, less(bc.max().height)));
            let c = self.run_view(ctx, w, 0.0, inner, 0.0, 0.0);
            ctx.run_layout(&mut self.view, &BoxConstraints::tight(Size::new(w, c)));
            if let Some(h) = &mut self.head {
                ctx.place_child(h, Point::ZERO);
            }
            ctx.place_child(&mut self.view, Point::new(0.0, hh));
            if let Some(f) = &mut self.foot {
                ctx.place_child(f, Point::new(0.0, hh + c + self.gap));
            }
            return bc.constrain(Size::new(w, hh + c + hf));
        }
        // where the focused field's caret was as last laid out, in the viewport then
        let was = ctx.focused_area().is_some_and(|r| r.y0 >= self.view_y - 0.5 && r.y1 <= self.view_y + self.v + 0.5);
        let total = bc.max().height;
        let (hh, hf) = self.ends(ctx, w);
        // pinned while the page keeps at least as much as they take
        self.pinned = total - hh - hf >= hh + hf;
        let (v, eh, ef) = if self.pinned { (total - hh - hf, 0.0, 0.0) } else { (total, hh, hf) };
        let natural = BoxConstraints::new(Size::new(w, 0.0), Size::new(w, f64::INFINITY));
        let key = (*bc, v, eh, ef);
        if ctx.child_needs_layout(&self.view) || self.measured != Some(key) {
            {
                // the list keeps the page while it is on it (a list laid out from its cache does
                // not report again); a list that left gives way to the next laid out
                let gone = lock(&self.link).list.filter(|id| ctx.descendant_origin(*id).is_none()).is_some();
                let mut l = lock(&self.link);
                if gone {
                    (l.list, l.rows, l.whole) = (None, 0.0, true);
                }
                l.measuring = true;
            }
            let n = self.run_view(ctx, w, v, natural, eh, 0.0);
            let mut l = lock(&self.link);
            l.measuring = false;
            let fit = |c: f64| BoxConstraints::tight(Size::new(w, c.max(0.0)));
            self.content_bc = match l.list {
                None if eh + n + ef <= v => fit(v - eh - ef),
                None => natural,
                Some(id) => {
                    // the list's top below the view's (the scrolled head included), and what is
                    // around it
                    let a = match (ctx.descendant_origin(id), ctx.descendant_origin(self.view.id())) {
                        (Some(a), Some(r)) => a.y - r.y,
                        _ => eh,
                    };
                    let around = n - l.rows;
                    // the list's own height: what the rest leaves when everything fits, else the
                    // page's (or its rows', when they fit a page whole); the content stays at its
                    // own height around it, so nothing else lays out again as the list moves
                    let vh = if l.whole && eh + n + ef <= v {
                        v - eh - ef - around
                    } else if l.whole {
                        l.rows.min(v)
                    } else {
                        v
                    };
                    (l.a, l.b, l.v, l.vh) = (a, eh + around + ef - a, v, vh);
                    natural
                }
            };
            self.measured = Some(key);
        }
        self.v = v;
        self.view_y = if self.pinned { hh } else { 0.0 };
        // the content's height under its constraints is known before it is laid out again
        let has_list = lock(&self.link).list.is_some();
        if !has_list {
            let c = if self.content_bc.is_height_bounded() { self.content_bc.max().height } else { ctx.get_raw(&mut self.view).0.height };
            self.range = (eh + c + ef - v).max(0.0);
            self.s = self.s.clamp(0.0, self.range);
        }
        let c = self.run_view(ctx, w, v, self.content_bc, eh, self.s);
        if has_list {
            self.range = (eh + c + ef - v).max(0.0);
        }
        let s = if has_list { lock(&self.link).s } else { self.s };
        self.own_bar = !has_list && self.range > 0.5;
        if let Some(h) = &mut self.head {
            ctx.place_child(h, Point::new(0.0, if self.pinned { 0.0 } else { -s }));
        }
        ctx.place_child(&mut self.view, Point::new(0.0, self.view_y));
        if let Some(f) = &mut self.foot {
            let y = if self.pinned { total - hf + self.gap } else { eh + c + self.gap - s };
            ctx.place_child(f, Point::new(0.0, y));
        }
        // the focused field's caret stays in view when what moved it was not a scroll (the space
        // shrank under it, its text grew); a scroll may take it out of view
        let shows = ctx.focused_area().is_some_and(|r| r.y0 >= self.view_y - 0.5 && r.y1 <= self.view_y + v + 0.5);
        let moved = std::mem::take(&mut self.moved) | std::mem::take(&mut lock(&self.link).moved);
        if was && !shows && !moved {
            ctx.request_scroll_to_focused();
        }
        // a head or foot that scrolls is clipped to the page (never at the sides: shadows)
        if !self.pinned && (self.head.is_some() || self.foot.is_some()) && self.range > 0.5 {
            ctx.set_clip_path(masonry::kurbo::Rect::new(-w, 0.0, 2.0 * w, total));
        } else {
            ctx.clear_clip_path();
        }
        Size::new(w, total)
    }

    fn paint(&mut self, _ctx: &mut PaintCtx<'_>, _props: &PropertiesRef<'_>, _scene: &mut Scene) {}

    fn post_paint(&mut self, ctx: &mut PaintCtx<'_>, _props: &PropertiesRef<'_>, scene: &mut Scene) {
        if let Some((h, y)) = self.thumb() {
            paint_thumb(scene, &self.look, ctx.size().width - GUTTER, y, h, self.grab.is_some());
        }
    }

    fn accessibility_role(&self) -> Role {
        Role::GenericContainer
    }

    fn accessibility(&mut self, _ctx: &mut AccessCtx<'_>, _props: &PropertiesRef<'_>, node: &mut Node) {
        if !self.plain {
            node.set_clips_children();
            // scrollable exactly when it shows its bar
            if self.own_bar {
                node.add_action(Action::ScrollUp);
                node.add_action(Action::ScrollDown);
            }
        }
    }

    fn children_ids(&self) -> ChildrenIds {
        // the head and foot over the view (which spans the page when they scroll with it)
        let mut ids = ChildrenIds::new();
        ids.push(self.view.id());
        if let Some(h) = &self.head {
            ids.push(h.id());
        }
        if let Some(f) = &self.foot {
            ids.push(f.id());
        }
        ids
    }
}

