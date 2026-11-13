//! A page's one vertical scrollable. A page lays out at the height it is given; what it holds
//! scrolls as one, never as two scrollables nested on one axis:
//! - with no list, the content scrolls when taller than the page;
//! - with a list (the first `VirtualList` laid out in it, `Link`), what is around the list keeps
//!   its own height and the list gets the rest; when that does not show everything, the list is
//!   as tall as the whole page and one scroll runs through all of it: what is above the list goes
//!   first, then the list's rows, then what is below it. A list that fits a page's height whole
//!   is laid out whole and the page alone scrolls.
//!
//! So at any height every part of the page is reachable by the one scroll, and nothing scrolls
//! when everything fits. One bar shows: the list's when its rows scroll, else the page's. A page
//! inside another page is plain content of the outer one.

use super::vlist::{GUTTER, MIN_THUMB, paint_thumb};
use crate::theme::Look;
use masonry::accesskit::{Action, Node, Role};
use masonry::core::{AccessCtx, AccessEvent, BoxConstraints, ChildrenIds, EventCtx, LayoutCtx, NewWidget, PaintCtx, PointerEvent, PointerScrollEvent, PropertiesMut, PropertiesRef, RegisterCtx, ScrollDelta, Update, UpdateCtx, Widget, WidgetId, WidgetPod};
use masonry::kurbo::{Point, Size};
use masonry::vello::Scene;
use std::cell::RefCell;
use std::sync::{Arc, Mutex, MutexGuard};

/// What a page and the list it holds tell each other.
#[derive(Default)]
pub(crate) struct Link {
    /// The page is measuring what is around the list: the list reports its rows and the height
    /// it is given.
    pub measuring: bool,
    pub given: f64,
    /// The list holding the page (the first laid out in it).
    pub list: Option<WidgetId>,
    /// The height of the list's rows at the page's width, when all of them are loaded.
    pub content: Option<f64>,
    /// The list is at the top, at the end of its rows (all of them, not only those loaded).
    pub at_top: bool,
    pub at_end: bool,
    /// The list follows its end.
    pub stuck: bool,
    /// The list shows its own bar.
    pub bar: bool,
    /// The page's viewport: its top in window coordinates, its height.
    pub page_y: f64,
    pub view: f64,
    /// How far the page is scrolled.
    pub s: f64,
    /// The list's top in the page's content, from the last paint.
    pub a: Option<f64>,
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

pub struct Page {
    child: WidgetPod<dyn Widget>,
    look: Arc<Look>,
    link: LinkRef,
    /// Inside another page (or under no height), so plain content.
    plain: bool,
    s: f64,
    range: f64,
    view: f64,
    /// The constraints last given, and what the content was laid out at under them.
    given: Option<BoxConstraints>,
    content_bc: BoxConstraints,
    /// The page draws its own bar (nothing else shows one).
    own_bar: bool,
    /// Holding the thumb, this far below its top.
    grab: Option<f64>,
    /// The list followed its end at the last layout.
    stuck: bool,
}

impl Page {
    pub fn new(child: NewWidget<impl Widget + ?Sized>, look: Arc<Look>) -> Page {
        Page { child: child.erased().to_pod(), look, link: LinkRef::default(), plain: false, s: 0.0, range: 0.0, view: 0.0, given: None, content_bc: BoxConstraints::UNBOUNDED, own_bar: false, grab: None, stuck: false }
    }

    /// The thumb's height and top, when the page draws its bar.
    fn thumb(&self) -> Option<(f64, f64)> {
        if !self.own_bar {
            return None;
        }
        let total = self.view + self.range;
        let h = (self.view * self.view / total).clamp(MIN_THUMB.min(self.view), self.view);
        Some((h, self.s / self.range.max(1.0) * (self.view - h)))
    }

    /// Moves the page by `d`, stopping where the list fills it unless the list is at its edge.
    /// `false`: nothing moved.
    fn scroll(&mut self, d: f64) -> bool {
        let mut to = self.s + d;
        {
            let l = lock(&self.link);
            if let (Some(_), Some(a)) = (l.list, l.a) {
                if d > 0.0 && !l.at_end && self.s < a - 0.5 {
                    to = to.min(a);
                } else if d < 0.0 && !l.at_top && self.s > a + 0.5 {
                    to = to.max(a);
                }
            }
        }
        let to = to.clamp(0.0, self.range);
        if (to - self.s).abs() < 0.01 {
            return false;
        }
        self.s = to;
        true
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
                if self.scroll(wheel(delta, ctx.get_scale_factor())) {
                    ctx.request_layout();
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
                    let to = (p.y - grab) / (self.view - h).max(1.0) * self.range;
                    self.s = to.clamp(0.0, self.range);
                    ctx.request_layout();
                }
                ctx.set_handled();
            }
            PointerEvent::Move(e) if self.grab.is_some() => {
                let (h, _) = self.thumb().unwrap_or((0.0, 0.0));
                let y = ctx.local_position(e.current.position).y - self.grab.unwrap_or(0.0);
                self.s = (y / (self.view - h).max(1.0) * self.range).clamp(0.0, self.range);
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
            Action::ScrollUp => -self.view * 0.9,
            Action::ScrollDown => self.view * 0.9,
            _ => return,
        };
        if !self.plain && self.scroll(d) {
            ctx.request_layout();
            ctx.set_handled();
        }
    }

    fn update(&mut self, ctx: &mut UpdateCtx<'_>, _props: &mut PropertiesMut<'_>, event: &Update) {
        // as Portal: bring a focused widget's area (content coordinates) into view
        if let Update::RequestPanToChild(r) = event
            && !self.plain
        {
            let to = if r.y0 < self.s { r.y0 } else if r.y1 > self.s + self.view { r.y1 - self.view } else { self.s };
            let to = to.clamp(0.0, self.range);
            if to != self.s {
                self.s = to;
                ctx.request_layout();
            }
        }
    }

    fn register_children(&mut self, ctx: &mut RegisterCtx<'_>) {
        ctx.register_child(&mut self.child);
    }

    fn layout(&mut self, ctx: &mut LayoutCtx<'_>, _props: &mut PropertiesMut<'_>, bc: &BoxConstraints) -> Size {
        self.plain = current().is_some() || !bc.is_height_bounded();
        if self.plain {
            self.own_bar = false;
            let s = ctx.run_layout(&mut self.child, bc);
            ctx.place_child(&mut self.child, Point::ZERO);
            return bc.constrain(s);
        }
        let (w, v) = (bc.max().width, bc.max().height);
        let outer = PAGE.with(|p| p.replace(Some(self.link.clone())));
        if ctx.child_needs_layout(&self.child) || self.given != Some(*bc) {
            // what is around the list: the page's height less what the list is given, laid out
            // taller until the list is given some (the rare page where it does not fit at all)
            let mut h = v;
            let around = loop {
                {
                    let mut l = lock(&self.link);
                    (l.measuring, l.list, l.content, l.given) = (true, None, None, 0.0);
                }
                ctx.run_layout(&mut self.child, &BoxConstraints::new(Size::new(w, 0.0), Size::new(w, h)));
                let l = lock(&self.link);
                if l.list.is_none() || l.given > 0.0 {
                    break h - l.given;
                }
                h = (h * 2.0).max(1.0);
            };
            let mut l = lock(&self.link);
            l.measuring = false;
            let tight = |h: f64| BoxConstraints::tight(Size::new(w, h));
            self.content_bc = match (l.list, l.content) {
                // as Portal: content taller than the page overflows its constraints
                (None, _) => tight(v),
                (Some(_), Some(c)) if around + c <= v => tight(v),
                // the list fits a page whole: laid out whole, the page scrolls alone
                (Some(_), Some(c)) if c <= v => tight(around + c),
                (Some(_), _) => tight(v + around),
            };
            self.given = Some(*bc);
        }
        let size = ctx.run_layout(&mut self.child, &self.content_bc);
        PAGE.with(|p| p.replace(outer));
        let at_end = self.s >= self.range - 0.5;
        self.view = v;
        self.range = (size.height - v).max(0.0);
        let mut l = lock(&self.link);
        // a list following its end shows the page's end, and keeps it while the page is there
        let stuck = l.list.is_some() && l.stuck;
        if stuck && (!self.stuck || at_end) {
            self.s = self.range;
        }
        self.stuck = stuck;
        self.s = self.s.clamp(0.0, self.range);
        (l.s, l.view) = (self.s, v);
        self.own_bar = self.range > 0.0 && !(l.list.is_some() && l.bar);
        drop(l);
        ctx.place_child(&mut self.child, Point::new(0.0, -self.s));
        ctx.set_clip_path(Size::new(w, v).to_rect());
        Size::new(w, v)
    }

    fn paint(&mut self, ctx: &mut PaintCtx<'_>, _props: &PropertiesRef<'_>, scene: &mut Scene) {
        if self.plain {
            return;
        }
        lock(&self.link).page_y = ctx.window_origin().y;
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
        ChildrenIds::from_slice(&[self.child.id()])
    }
}
