//! osis-kit patch: the platform accessibility adapter, `accesskit_winit`'s with the
//! `accessibility` feature (off by default: the Linux adapter alone pulls zbus and ~55 crates).
//! Off, a no-op adapter of the same shape: no screen reader sees the app, and nothing sends an
//! `AccessKit` user event.

#[cfg(feature = "accessibility")]
pub use accesskit_winit::{Adapter, Event, WindowEvent};

#[cfg(not(feature = "accessibility"))]
pub use self::null::{Adapter, Event, WindowEvent};

#[cfg(not(feature = "accessibility"))]
#[allow(missing_docs, reason = "stand-ins for accesskit_winit's types")]
mod null {
    use masonry_core::accesskit::{ActionRequest, TreeUpdate};
    use winit::event::WindowEvent as WinitWindowEvent;
    use winit::event_loop::{ActiveEventLoop, EventLoopProxy};
    use winit::window::{Window, WindowId};

    pub struct Adapter;

    impl Adapter {
        pub fn with_event_loop_proxy<T: From<Event> + Send + 'static>(
            _event_loop: &ActiveEventLoop,
            _window: &Window,
            _proxy: EventLoopProxy<T>,
        ) -> Self {
            Self
        }

        pub fn process_event(&mut self, _window: &Window, _event: &WinitWindowEvent) {}

        pub fn update_if_active(&mut self, _updater: impl FnOnce() -> TreeUpdate) {}
    }

    #[derive(Debug)]
    #[allow(dead_code, reason = "never built: no adapter sends events")]
    pub struct Event {
        pub window_id: WindowId,
        pub window_event: WindowEvent,
    }

    #[derive(Debug)]
    #[allow(dead_code, reason = "never built: no adapter sends events")]
    pub enum WindowEvent {
        InitialTreeRequested,
        ActionRequested(ActionRequest),
        AccessibilityDeactivated,
    }
}
