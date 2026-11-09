//! Windowing over masonry_winit: the event loop, a `Waker` that wakes it from any thread, and
//! running one window.

use masonry::peniko::Color;
use masonry::core::{NewWidget, Widget, WidgetId};
use masonry::dpi::LogicalSize;
use masonry_winit::app::{AppDriver, EventLoop, EventLoopProxy, MasonryUserEvent, NewWindow, WindowId};
use masonry_winit::winit::error::EventLoopError;
use masonry_winit::winit::window::Window;

/// The action a `Waker` delivers to `AppDriver::on_action`: run what is due on the UI thread.
#[derive(Debug)]
pub struct Wakeup;

/// Wakes the event loop by sending a `Wakeup` action for the window.
#[derive(Clone)]
pub struct Waker {
    proxy: EventLoopProxy,
    window: WindowId,
    widget: WidgetId,
}

impl Waker {
    /// Wakes the loop, from any thread.
    pub fn wake(&self) {
        // fails only once the loop has exited
        let _ = self.proxy.send_event(MasonryUserEvent::Action(self.window, Box::new(Wakeup), self.widget));
    }
}

/// An event loop with one window to come.
pub struct App {
    event_loop: EventLoop,
    window: WindowId,
    wake_id: WidgetId,
}

impl App {
    pub fn new() -> Result<App, EventLoopError> {
        Ok(App::with_event_loop(EventLoop::with_user_event().build()?))
    }

    /// Over a loop built elsewhere (Android builds it with its `AndroidApp`).
    pub fn with_event_loop(event_loop: EventLoop) -> App {
        App { event_loop, window: WindowId::next(), wake_id: WidgetId::next() }
    }

    /// The window's id, for `DriverCtx::render_root`.
    pub fn window(&self) -> WindowId {
        self.window
    }

    /// A waker for osis's `Dispatcher::Pump` and the UI's own posts.
    pub fn waker(&self) -> Waker {
        Waker { proxy: self.event_loop.create_proxy(), window: self.window, widget: self.wake_id }
    }

    /// Opens the window with `root` and runs until it closes.
    pub fn run(self, title: &str, size: (f64, f64), root: NewWidget<dyn Widget>, driver: impl AppDriver + 'static, base: Color) -> Result<(), EventLoopError> {
        let attrs = Window::default_attributes().with_title(title).with_resizable(true).with_inner_size(LogicalSize::new(size.0, size.1));
        let w = NewWindow::new_with_id(self.window, attrs, root).with_base_color(base);
        masonry_winit::app::run_with(self.event_loop, vec![w], driver, masonry::theme::default_property_set())
    }
}
