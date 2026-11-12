//! The desktop shell: masonry_winit with one window.

use super::Waker;
use crate::render::Ui;
use masonry::app::RenderRoot;
use masonry::core::{ErasedAction, NewWidget, Widget, WidgetId};
use masonry::dpi::LogicalSize;
use masonry_winit::app::{AppDriver, DriverCtx, EventLoop, EventLoopProxy, MasonryState, MasonryUserEvent, NewWindow, WindowId};
use masonry_winit::winit::dpi::PhysicalSize;
use masonry_winit::winit::error::EventLoopError;
use masonry_winit::winit::window::{Theme, Window};

/// The action the desktop waker delivers through the event loop.
#[derive(Debug)]
struct Wakeup;

/// An event loop with one window to come.
pub struct App {
    event_loop: EventLoop,
    window: WindowId,
    wake_id: WidgetId,
}

impl App {
    pub fn new() -> Result<App, EventLoopError> {
        Ok(App { event_loop: EventLoop::with_user_event().build()?, window: WindowId::next(), wake_id: WidgetId::next() })
    }

    /// A waker for osis's `Dispatcher::Pump` and the UI's own posts.
    pub fn waker(&self) -> Waker {
        let (proxy, window, widget): (EventLoopProxy, _, _) = (self.event_loop.create_proxy(), self.window, self.wake_id);
        // fails only once the loop has exited
        Waker::new(move || drop(proxy.send_event(MasonryUserEvent::Action(window, Box::new(Wakeup), widget))))
    }

    /// Opens the window with `root` and runs `ui` until it closes.
    pub fn run(self, title: &str, size: (f64, f64), root: NewWidget<dyn Widget>, ui: Ui) -> Result<(), EventLoopError> {
        let attrs = Window::default_attributes().with_title(title).with_resizable(true).with_inner_size(LogicalSize::new(size.0, size.1));
        let w = NewWindow::new_with_id(self.window, attrs, root).with_base_color(ui.base_color());
        masonry_winit::app::run_with(self.event_loop, vec![w], Desktop { ui, window: self.window }, masonry::theme::default_property_set())
    }
}

/// `Ui` as masonry_winit's driver.
struct Desktop {
    ui: Ui,
    window: WindowId,
}

impl Desktop {
    /// Runs `f` on the window's root with its scale and the system's dark mode, then keeps the
    /// window's clear colour the look's.
    fn with(&mut self, w: &mut masonry_winit::app::Window, f: impl FnOnce(&mut Ui, &mut RenderRoot, f64, bool)) {
        let (scale, dark) = (w.handle().scale_factor(), w.handle().theme() == Some(Theme::Dark));
        f(&mut self.ui, w.render_root(), scale, dark);
        *w.base_color() = self.ui.base_color();
    }
}

impl AppDriver for Desktop {
    /// The window exists now; wakes before it were dropped by masonry_winit, so `start` runs
    /// what is due.
    fn on_start(&mut self, state: &mut MasonryState<'_>) {
        let w = state.window(self.window);
        self.with(w, |ui, root, scale, dark| ui.start(root, scale, dark));
    }

    fn on_resized(&mut self, _w: WindowId, ctx: &mut DriverCtx<'_, '_>, _size: PhysicalSize<u32>) {
        self.with(ctx.window(self.window), |ui, root, scale, _| ui.resized(root, scale));
    }

    fn on_theme_changed(&mut self, _w: WindowId, ctx: &mut DriverCtx<'_, '_>, theme: Theme) {
        self.with(ctx.window(self.window), |ui, root, _, _| ui.theme_changed(root, theme == Theme::Dark));
    }

    fn on_action(&mut self, _w: WindowId, ctx: &mut DriverCtx<'_, '_>, id: WidgetId, action: ErasedAction) {
        let w = ctx.window(self.window);
        if action.is::<Wakeup>() {
            self.with(w, |ui, root, _, _| ui.wake(root));
        } else {
            self.with(w, |ui, root, _, _| ui.action(root, id, action));
        }
    }
}
